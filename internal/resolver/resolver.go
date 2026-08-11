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
	"fmt"
	"log/slog"
	"sync"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/MmTKya/DNS/internal/config"
)

// Hook runs for every query before it is forwarded upstream.  It is the single
// extension point through which later phases attach: the filter engine, the
// query logger, per-client policy and the threat-intel enrichment queue all
// hang off this signature, so it is fixed now and must stay stable.
//
// A hook that fully answers a query sets dctx.Res and returns nil; the proxy
// then writes that response and never contacts an upstream.  Returning an
// error aborts the request.  Hooks run on the hot path and must not block.
type Hook func(ctx context.Context, dctx *proxy.DNSContext) error

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
	hookMu sync.RWMutex
	hook   Hook
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
		RefuseAny:      cfg.DNS.RefuseAny,
		RequestHandler: &hookHandler{resolver: r},
	}

	p, err := proxy.New(proxyCfg)
	if err != nil {
		return nil, fmt.Errorf("creating dns proxy: %w", err)
	}

	return p, nil
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
	h.resolver.hookMu.RUnlock()

	if hook != nil {
		if err := hook(ctx, dctx); err != nil {
			return err
		}

		// The hook answered the query itself, so there is nothing to forward.
		if dctx.Res != nil {
			return nil
		}
	}

	return p.Resolve(ctx, dctx)
}

var _ proxy.Handler = (*hookHandler)(nil)
