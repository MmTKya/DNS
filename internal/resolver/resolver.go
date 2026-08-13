// Package resolver is the AegisDNS datapath: the part of the process that
// answers DNS queries.
//
// It is deliberately stateless with respect to the control plane.  Everything
// it needs arrives as an immutable *config.Config snapshot, and reconfiguring
// it means building a new proxy from a new snapshot rather than mutating a
// live one.  That separation is what makes hot reload, cluster replication and
// atomic updates tractable later; the well-documented pain in comparable
// products comes from letting the UI, the config file and the datapath share
// mutable state.
//
// Phase 0 forwards plain UDP and TCP to upstreams with a cache in front.
// Encrypted transports, serve-stale and per-client policy land in phase 1, and
// filtering attaches through the Hook defined below.
package resolver

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/MmTKya/DNS/internal/config"
)

// Resolve forwards a query upstream and fills in dctx.Res.
type Resolve func(ctx context.Context, dctx *proxy.DNSContext) error

// Hook wraps the resolution of every query.  It is the single extension point
// through which the rest of the product attaches: the filter engine, the query
// log, per-client policy and, later, the threat-intel enrichment queue.
//
// A hook that decides the query itself sets dctx.Res and returns without
// calling resolve; the proxy then writes that response and never contacts an
// upstream.  Otherwise it calls resolve and may inspect the outcome, which is
// what lets the query log record the response code, the upstream used and the
// time taken.  Hooks run on the hot path and must not block.
type Hook func(ctx context.Context, dctx *proxy.DNSContext, resolve Resolve) error

// Resolver owns the running DNS proxy.
type Resolver struct {
	logger *slog.Logger

	// mu guards proxy and cfg across Start, Reload and Shutdown.  Queries do
	// not take it: they run inside the proxy that Start handed off.
	mu    sync.Mutex
	proxy *proxy.Proxy
	cfg   *config.Config

	// hook is read on every query, so it is guarded separately and kept
	// cheap.  RWMutex over atomic.Pointer keeps the nil case readable.
	// rescue is read on every query for the same reason, so it lives under
	// the same lock rather than under mu, which queries must never take.
	hookMu sync.RWMutex
	hook   Hook
	rescue *rescuer

	// onRescue is handed to each rescuer built by a reload, so a counter
	// survives reconfiguration rather than resetting whenever a resolver is
	// changed — which is exactly when someone is watching it.
	onRescue func()
}

// New creates a resolver from cfg.  It does not bind any sockets; call Start.
func New(cfg *config.Config, logger *slog.Logger) *Resolver {
	if logger == nil {
		logger = slog.Default()
	}

	return &Resolver{
		cfg:    cfg,
		logger: logger.With("component", "resolver"),
	}
}

// SetHook installs the query hook, replacing any previous one.  Passing nil
// removes it.
// OnRescue registers a callback for lookups that only succeeded because a
// second resolver was asked.  Set before Start.
//
// Handed to every rescuer a reload builds, so the count survives someone
// changing their resolvers — which is exactly when it is being watched.
func (r *Resolver) OnRescue(fn func()) {
	r.hookMu.Lock()
	defer r.hookMu.Unlock()

	r.onRescue = fn
	if r.rescue != nil {
		r.rescue.onRescue = fn
	}
}

func (r *Resolver) SetHook(h Hook) {
	r.hookMu.Lock()
	defer r.hookMu.Unlock()

	r.hook = h
}

// Start binds the configured listeners and begins serving.
func (r *Resolver) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.proxy != nil {
		return fmt.Errorf("resolver is already running")
	}

	p, err := r.build(r.cfg)
	if err != nil {
		return err
	}

	if err = p.Start(ctx); err != nil {
		return fmt.Errorf("starting dns listeners: %w", err)
	}

	r.proxy = p
	r.logger.InfoContext(ctx, "dns datapath started",
		"listen", r.cfg.DNS.Listen,
		"upstreams", len(r.cfg.DNS.Upstreams),
		"upstream_mode", r.cfg.DNS.UpstreamMode,
		"cache", r.cfg.DNS.CacheEnabled,
	)

	return nil
}

// Reload swaps the datapath over to cfg.
//
// The new proxy cannot be started before the old one stops, because both want
// the same sockets.  There is therefore a brief window with no listener; if
// the new configuration fails to bind, Reload restores the previous one and
// returns the original error, so a bad edit degrades to "unchanged" instead of
// "no DNS at all".
func (r *Resolver) Reload(ctx context.Context, cfg *config.Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	next, err := r.build(cfg)
	if err != nil {
		return err
	}

	if r.proxy != nil {
		if err = r.proxy.Shutdown(ctx); err != nil {
			r.logger.WarnContext(ctx, "shutting down previous datapath", "err", err)
		}
		r.proxy = nil
	}

	if err = next.Start(ctx); err != nil {
		startErr := fmt.Errorf("starting dns listeners with new config: %w", err)

		restored, buildErr := r.build(r.cfg)
		if buildErr != nil {
			return fmt.Errorf("%w (previous config could not be rebuilt: %w)", startErr, buildErr)
		}
		if restoreErr := restored.Start(ctx); restoreErr != nil {
			return fmt.Errorf("%w (previous config could not be restarted: %w)", startErr, restoreErr)
		}

		r.proxy = restored
		r.logger.ErrorContext(ctx, "reload failed, previous configuration restored", "err", err)

		return startErr
	}

	r.proxy = next
	r.cfg = cfg
	r.logger.InfoContext(ctx, "dns datapath reloaded", "listen", cfg.DNS.Listen)

	return nil
}

// Shutdown stops serving.  It is safe to call on a resolver that never started.
func (r *Resolver) Shutdown(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.proxy == nil {
		return nil
	}

	err := r.proxy.Shutdown(ctx)
	r.proxy = nil

	if err != nil {
		return fmt.Errorf("shutting down dns datapath: %w", err)
	}

	return nil
}

// Running reports whether the datapath is currently serving.
func (r *Resolver) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.proxy != nil
}

// Addrs returns the addresses actually bound, which differ from the configured
// ones when a port of 0 was requested.  It returns nil when not running.
func (r *Resolver) Addrs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.proxy == nil {
		return nil
	}

	var addrs []string
	for _, proto := range []proxy.Proto{proxy.ProtoUDP, proxy.ProtoTCP} {
		for _, a := range r.proxy.Addrs(proto) {
			addrs = append(addrs, fmt.Sprintf("%s/%s", a.String(), proto))
		}
	}

	return addrs
}

// build turns a config snapshot into a configured, not yet started, proxy.
func (r *Resolver) build(cfg *config.Config) (*proxy.Proxy, error) {
	udpAddrs, err := cfg.UDPAddrs()
	if err != nil {
		return nil, err
	}

	tcpAddrs, err := cfg.TCPAddrs()
	if err != nil {
		return nil, err
	}

	opts := &upstream.Options{
		Logger:  r.logger.With("subsystem", "upstream"),
		Timeout: cfg.DNS.UpstreamTimeout.Duration(),
	}

	// Encrypted upstreams are given by hostname, and resolving that hostname
	// needs DNS that does not depend on this resolver.  Bootstrap resolvers
	// are plain IPs for exactly that reason (config.Validate enforces it).
	if len(cfg.DNS.Bootstrap) > 0 {
		boot, bootErr := bootstrapResolver(cfg.DNS.Bootstrap, opts)
		if bootErr != nil {
			return nil, bootErr
		}
		opts.Bootstrap = boot
	}

	upstreams, err := proxy.ParseUpstreamsConfig(cfg.DNS.Upstreams, opts)
	if err != nil {
		return nil, fmt.Errorf("parsing upstreams: %w", err)
	}

	proxyCfg := &proxy.Config{
		Logger:         r.logger.With("subsystem", "proxy"),
		UDPListenAddr:  udpAddrs,
		TCPListenAddr:  tcpAddrs,
		UpstreamConfig: upstreams,
		UpstreamMode:   upstreamMode(cfg.DNS.UpstreamMode),
		CacheEnabled:   cfg.DNS.CacheEnabled,
		CacheSizeBytes: cfg.DNS.CacheSizeBytes,
		CacheMinTTL:    cfg.DNS.CacheMinTTL,
		CacheMaxTTL:    cfg.DNS.CacheMaxTTL,
		RefuseAny:      cfg.DNS.RefuseAny,
		DNSSECEnabled:  cfg.DNS.DNSSEC,
		RequestHandler: &hookHandler{resolver: r},
	}

	// Serving stale answers while a refresh runs behind them (RFC 8767) is the
	// difference between "the internet is down" and "one page loaded a second
	// late" when an upstream flickers.
	if cfg.DNS.CacheEnabled && cfg.DNS.ServeStale {
		proxyCfg.CacheOptimistic = true
		proxyCfg.CacheOptimisticMaxAge = cfg.DNS.ServeStaleMaxAge.Duration()
	}

	// Built with the same options as the upstreams, so an encrypted rescue
	// resolver bootstraps the same way.
	rescue := newRescuer(cfg, opts, r.logger)
	rescue.onRescue = r.onRescue
	r.hookMu.Lock()
	old := r.rescue
	r.rescue = rescue
	r.hookMu.Unlock()
	if old != nil {
		old.close()
	}

	if len(cfg.DNS.Fallbacks) > 0 {
		// Fallbacks are parsed with the same options but kept in their own
		// pool, so they are only consulted once the normal upstreams have all
		// failed rather than being load-balanced into ordinary traffic.
		fallbacks, fbErr := proxy.ParseUpstreamsConfig(cfg.DNS.Fallbacks, opts)
		if fbErr != nil {
			return nil, fmt.Errorf("parsing fallbacks: %w", fbErr)
		}
		proxyCfg.Fallbacks = fallbacks
	}

	if err = configureTLS(proxyCfg, cfg); err != nil {
		return nil, err
	}

	p, err := proxy.New(proxyCfg)
	if err != nil {
		return nil, fmt.Errorf("creating dns proxy: %w", err)
	}

	return p, nil
}

// configureTLS sets up the encrypted listeners.
//
// These are what let a phone on mobile data reach its own filtered resolver
// over DoH without a VPN, and what lets LAN clients encrypt queries to the
// node.  Without a certificate they stay off; config validation has already
// rejected a listener configured without one.
func configureTLS(proxyCfg *proxy.Config, cfg *config.Config) error {
	tlsCfg := cfg.DNS.TLS
	if !tlsCfg.Enabled() {
		return nil
	}

	cert, err := tls.LoadX509KeyPair(tlsCfg.CertFile, tlsCfg.KeyFile)
	if err != nil {
		return fmt.Errorf("loading tls certificate: %w", err)
	}

	proxyCfg.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if proxyCfg.TLSListenAddr, err = tcpAddrs(tlsCfg.TLSListen); err != nil {
		return fmt.Errorf("dns.tls.tls_listen: %w", err)
	}

	httpsAddrs, err := addrPorts(tlsCfg.HTTPSListen)
	if err != nil {
		return fmt.Errorf("dns.tls.https_listen: %w", err)
	}
	if len(httpsAddrs) > 0 {
		proxyCfg.HTTPConfig = &proxy.HTTPConfig{
			ListenAddresses: httpsAddrs,
			// The second route carries a client id in the path, which is how a
			// roaming device identifies itself to per-client policy: one DoH
			// URL per device, no LAN address to key on.
			Routes: []string{"/dns-query", "/dns-query/{clientid}"},
		}
	}

	if proxyCfg.QUICListenAddr, err = udpAddrs(tlsCfg.QUICListen); err != nil {
		return fmt.Errorf("dns.tls.quic_listen: %w", err)
	}

	return nil
}

func tcpAddrs(addrs []string) (out []*net.TCPAddr, err error) {
	for _, a := range addrs {
		addr, resolveErr := net.ResolveTCPAddr("tcp", a)
		if resolveErr != nil {
			return nil, fmt.Errorf("resolving %q: %w", a, resolveErr)
		}
		out = append(out, addr)
	}

	return out, nil
}

// addrPorts parses listener addresses that must be literal IPs, which is what
// the DoH server wants.
func addrPorts(addrs []string) (out []netip.AddrPort, err error) {
	for _, a := range addrs {
		addr, parseErr := netip.ParseAddrPort(a)
		if parseErr != nil {
			return nil, fmt.Errorf("parsing %q as ip:port: %w", a, parseErr)
		}
		out = append(out, addr)
	}

	return out, nil
}

func udpAddrs(addrs []string) (out []*net.UDPAddr, err error) {
	for _, a := range addrs {
		addr, resolveErr := net.ResolveUDPAddr("udp", a)
		if resolveErr != nil {
			return nil, fmt.Errorf("resolving %q: %w", a, resolveErr)
		}
		out = append(out, addr)
	}

	return out, nil
}

// bootstrapResolver builds the resolver used to look up upstream hostnames.
// Several addresses are queried in parallel so one dead bootstrap does not add
// its timeout to every cold start.
func bootstrapResolver(addrs []string, opts *upstream.Options) (upstream.Resolver, error) {
	// The bootstrap resolvers themselves must not need a bootstrap.
	bootOpts := opts.Clone()
	bootOpts.Bootstrap = nil

	parallel := make(upstream.ParallelResolver, 0, len(addrs))
	for _, addr := range addrs {
		ur, err := upstream.NewUpstreamResolver(addr, bootOpts)
		if err != nil {
			return nil, fmt.Errorf("creating bootstrap resolver %q: %w", addr, err)
		}
		parallel = append(parallel, upstream.NewCachingResolver(ur))
	}

	return parallel, nil
}

func upstreamMode(mode string) proxy.UpstreamMode {
	switch mode {
	case config.UpstreamModeParallel:
		return proxy.UpstreamModeParallel
	case config.UpstreamModeFastestAddr:
		return proxy.UpstreamModeFastestAddr
	default:
		return proxy.UpstreamModeLoadBalance
	}
}

// hookHandler is the dnsproxy request handler.  It gives the hook a chance to
// answer or annotate the query, then falls through to normal resolution.
type hookHandler struct {
	resolver *Resolver
}

// ServeDNS implements proxy.Handler.
func (h *hookHandler) ServeDNS(ctx context.Context, p *proxy.Proxy, dctx *proxy.DNSContext) error {
	h.resolver.hookMu.RLock()
	hook := h.resolver.hook
	rescue := h.resolver.rescue
	h.resolver.hookMu.RUnlock()

	// Every path resolves through the rescuer, so a name that one resolver
	// cannot answer is retried whether or not filtering is switched on.
	resolve := p.Resolve
	if rescue != nil {
		resolve = func(ctx context.Context, dctx *proxy.DNSContext) error {
			return rescue.resolve(ctx, p, dctx)
		}
	}

	if hook == nil {
		return resolve(ctx, dctx)
	}

	return hook(ctx, dctx, resolve)
}

var _ proxy.Handler = (*hookHandler)(nil)
