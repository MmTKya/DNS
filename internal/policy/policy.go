// Package policy decides what happens to a query.
//
// It sits between the datapath and the rules: the resolver hands it every
// query, it consults the filter engine, and it either answers the query itself
// or lets resolution proceed and reports the outcome.  Keeping this out of
// internal/resolver is what allows the datapath to stay a thin wrapper around
// dnsproxy, and what will let per-client policy, threat intelligence and
// enforcement attach here rather than being threaded through the transport.
package policy

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/MmTKya/DNS/internal/config"
	"github.com/MmTKya/DNS/internal/filter"
	"github.com/MmTKya/DNS/internal/resolver"
	"github.com/miekg/dns"
)

// Verdicts describe what was done with a query.
const (
	VerdictAllowed   = "allowed"
	VerdictBlocked   = "blocked"
	VerdictRewritten = "rewritten"
	VerdictError     = "error"

	// VerdictPaused marks a query refused because its client is paused.  It is
	// distinct from a block so the panel can say why, and so "paused" can be
	// counted separately from filtering.
	VerdictPaused = "paused"
)

// Event is one handled query, handed to the observer.
type Event struct {
	Time time.Time

	// Client is the address the query came from.
	Client netip.Addr

	// ClientID identifies a device that named itself, through a DoH path or a
	// DoT server name.  It survives the device changing networks, which an
	// address does not.
	ClientID string

	// ClientName is the friendly name the operator gave the device, if any.
	ClientName string

	Host  string
	QType uint16
	Proto string

	Verdict string

	// RuleSource and MatchedDomain explain a block: which list, and which
	// rule inside it.
	RuleSource    string
	MatchedDomain string

	Rcode       int
	AnswerCount int
	Cached      bool
	Elapsed     time.Duration
	Upstream    string
	Error       string
}

// Observer receives every handled query.  Implementations must not block: they
// run on the hot path, so the query log buffers in memory and writes later.
type Observer interface {
	Observe(event Event)
}

// Client is what policy needs to know about the device asking.
type Client struct {
	Key              string
	Name             string
	FilteringEnabled bool
	Paused           bool
}

// ClientResolver maps a query's source to a client.  It is an interface here
// so that policy does not depend on how identity is stored, and so tests can
// supply a fixed answer.
type ClientResolver interface {
	Identify(addr netip.Addr, clientID string) Client
}

// ObserverFunc adapts a function to Observer.
type ObserverFunc func(event Event)

// Observe implements Observer.
func (f ObserverFunc) Observe(event Event) { f(event) }

// Engine applies filtering policy to queries.
type Engine struct {
	filter   *filter.Engine
	logger   *slog.Logger
	observer atomic.Pointer[Observer]
	clients  atomic.Pointer[ClientResolver]

	// settings is swapped wholesale on reload rather than mutated field by
	// field, so a query never sees a half-updated policy.
	settings atomic.Pointer[settings]
}

type settings struct {
	blockingIPv4 netip.Addr
	blockingIPv6 netip.Addr
	blockingMode string
	blockedTTL   uint32
	enabled      bool
}

// New creates a policy engine.
func New(filterEngine *filter.Engine, cfg *config.Config, logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.Default()
	}

	e := &Engine{
		filter: filterEngine,
		logger: logger.With("component", "policy"),
	}
	e.Configure(cfg)

	return e
}

// Configure applies a new configuration snapshot.
func (e *Engine) Configure(cfg *config.Config) {
	s := &settings{
		enabled:      cfg.Filtering.Enabled,
		blockingMode: cfg.Filtering.BlockingMode,
		blockedTTL:   cfg.Filtering.BlockedTTL,
	}

	if addr, err := netip.ParseAddr(cfg.Filtering.BlockingIPv4); err == nil {
		s.blockingIPv4 = addr
	}
	if addr, err := netip.ParseAddr(cfg.Filtering.BlockingIPv6); err == nil {
		s.blockingIPv6 = addr
	}

	e.settings.Store(s)
}

// SetObserver installs the sink for handled queries.
func (e *Engine) SetObserver(o Observer) {
	e.observer.Store(&o)
}

// SetClientResolver installs client identification.  Without one, every query
// is treated as coming from an unknown, filtered device.
func (e *Engine) SetClientResolver(c ClientResolver) {
	e.clients.Store(&c)
}

// Hook returns the resolver hook that applies this policy.
func (e *Engine) Hook() resolver.Hook {
	return e.handle
}

func (e *Engine) handle(ctx context.Context, dctx *proxy.DNSContext, resolve resolver.Resolve) error {
	start := time.Now()

	req := dctx.Req
	if req == nil || len(req.Question) == 0 {
		return resolve(ctx, dctx)
	}

	question := req.Question[0]
	host := strings.TrimSuffix(strings.ToLower(question.Name), ".")

	event := Event{
		Time:     start,
		Client:   dctx.Addr.Addr(),
		ClientID: clientID(dctx),
		Host:     host,
		QType:    question.Qtype,
		Proto:    string(dctx.Proto),
		Verdict:  VerdictAllowed,
	}

	s := e.settings.Load()

	client := Client{FilteringEnabled: true}
	if c := e.clients.Load(); c != nil {
		client = (*c).Identify(event.Client, event.ClientID)
	}
	event.ClientName = client.Name

	// A paused client is refused outright.  In DNS-only mode this is content
	// filtering and nothing more: the device keeps its network access, and a
	// hardcoded address or its own DoH walks around it.  The panel says so.
	if client.Paused {
		dctx.Res = e.negativeResponse(req, dns.RcodeRefused, s)
		event.Verdict = VerdictPaused
		event.Rcode = dctx.Res.Rcode
		event.Elapsed = time.Since(start)
		e.observe(event)

		return nil
	}

	if s.enabled && client.FilteringEnabled {
		res := e.filter.Match(host, question.Qtype, event.ClientID)
		if res.Matched {
			event.RuleSource = res.SourceID
			event.MatchedDomain = res.MatchedDomain

			switch res.Action {
			case filter.ActionBlock:
				dctx.Res = e.blockedResponse(req, s)
				event.Verdict = VerdictBlocked
				event.Rcode = dctx.Res.Rcode
				event.AnswerCount = len(dctx.Res.Answer)
				event.Elapsed = time.Since(start)
				e.observe(event)

				return nil

			case filter.ActionRewrite:
				if resp := e.rewrittenResponse(req, res, s); resp != nil {
					dctx.Res = resp
					event.Verdict = VerdictRewritten
					event.Rcode = resp.Rcode
					event.AnswerCount = len(resp.Answer)
					event.Elapsed = time.Since(start)
					e.observe(event)

					return nil
				}

			case filter.ActionAllow:
				// An explicit exception is worth recording, so the panel can
				// show that a name was reached because a rule allowed it.
			}
		}
	}

	err := resolve(ctx, dctx)

	// A resolver sees the whole CNAME chain; a browser extension does not.
	// Trackers exploit that by hiding behind a subdomain of the site you are
	// visiting that resolves, one CNAME later, to the tracker's own domain.
	// Checking the chain is a capability only something in this position has.
	if err == nil && s.enabled && client.FilteringEnabled {
		if hit, ok := e.uncloak(dctx, question.Qtype, event.ClientID); ok {
			dctx.Res = e.blockedResponse(req, s)
			event.Verdict = VerdictBlocked
			event.RuleSource = hit.SourceID
			event.MatchedDomain = hit.MatchedDomain
			event.Rcode = dctx.Res.Rcode
			event.AnswerCount = len(dctx.Res.Answer)
			event.Elapsed = time.Since(start)
			e.observe(event)

			return nil
		}
	}

	event.Elapsed = time.Since(start)
	if err != nil {
		event.Verdict = VerdictError
		event.Error = err.Error()
	}
	if dctx.Res != nil {
		event.Rcode = dctx.Res.Rcode
		event.AnswerCount = len(dctx.Res.Answer)
	}
	if dctx.Upstream != nil {
		event.Upstream = dctx.Upstream.Address()
	} else if err == nil {
		// dnsproxy leaves the upstream unset when it answered from cache.
		event.Cached = true
	}

	e.observe(event)

	return err
}

// maxCNAMEDepth bounds the chain walk.  A legitimate chain is two or three
// links; anything longer is a misconfiguration or a deliberate loop.
const maxCNAMEDepth = 8

// uncloak checks the CNAME targets in a response against the ruleset.
func (e *Engine) uncloak(dctx *proxy.DNSContext, qtype uint16, clientID string) (res filter.Result, blocked bool) {
	if dctx.Res == nil {
		return filter.Result{}, false
	}

	checked := 0
	for _, rr := range dctx.Res.Answer {
		cname, ok := rr.(*dns.CNAME)
		if !ok {
			continue
		}

		checked++
		if checked > maxCNAMEDepth {
			break
		}

		target := strings.TrimSuffix(strings.ToLower(cname.Target), ".")
		if target == "" {
			continue
		}

		hit := e.filter.Match(target, qtype, clientID)
		if hit.Matched && hit.Action == filter.ActionBlock {
			return hit, true
		}
		// An allow rule anywhere in the chain settles it: the operator has
		// said this path is fine.
		if hit.Matched && hit.Action == filter.ActionAllow {
			return filter.Result{}, false
		}
	}

	return filter.Result{}, false
}

func (e *Engine) observe(event Event) {
	if o := e.observer.Load(); o != nil {
		(*o).Observe(event)
	}
}

// clientID extracts a self-declared device identity.
//
// A roaming phone has a different address on every network, so an address is
// useless for per-device policy once the device leaves the LAN.  Both encrypted
// transports carry a stable identifier instead: DoH puts it in the URL path,
// DoT in the TLS server name.
func clientID(dctx *proxy.DNSContext) string {
	if r := dctx.HTTPRequest; r != nil {
		// "/dns-query/kids-tablet" -> "kids-tablet"
		if rest, found := strings.CutPrefix(r.URL.Path, "/dns-query/"); found {
			return sanitiseClientID(rest)
		}
	}

	return ""
}

// sanitiseClientID keeps an identifier that arrives from the network from
// carrying anything surprising into logs, rules or the panel.
func sanitiseClientID(id string) string {
	id = strings.Trim(id, "/")
	if len(id) > 63 {
		return ""
	}

	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_':
		default:
			return ""
		}
	}

	return id
}

// blockedResponse builds the answer for a blocked name.
//
// Every query type is handled, not just A and AAAA.  A filter that answers A
// and leaves HTTPS, SVCB or MX to the upstream leaks the very connection it
// was meant to stop, and inconsistent handling across types is a documented
// way to slip past protective DNS services.
func (e *Engine) blockedResponse(req *dns.Msg, s *settings) *dns.Msg {
	switch s.blockingMode {
	case config.BlockingModeNXDOMAIN:
		return e.negativeResponse(req, dns.RcodeNameError, s)

	case config.BlockingModeRefused:
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeRefused)

		return resp

	case config.BlockingModeCustomIP:
		return e.addressResponse(req, s.blockingIPv4, s.blockingIPv6, s)

	default:
		// null_ip: browsers fail fast on an unroutable address, which is why
		// it is the default.
		return e.addressResponse(req, netip.IPv4Unspecified(), netip.IPv6Unspecified(), s)
	}
}

func (e *Engine) rewrittenResponse(req *dns.Msg, res filter.Result, s *settings) *dns.Msg {
	if res.RewriteNXDOMAIN {
		return e.negativeResponse(req, dns.RcodeNameError, s)
	}

	var v4, v6 netip.Addr
	for _, addr := range res.RewriteIPs {
		if addr.Is4() && !v4.IsValid() {
			v4 = addr
		}
		if addr.Is6() && !addr.Is4In6() && !v6.IsValid() {
			v6 = addr
		}
	}

	if !v4.IsValid() && !v6.IsValid() {
		return nil
	}

	return e.addressResponse(req, v4, v6, s)
}

// addressResponse answers A and AAAA with the given addresses, and every other
// type with NODATA.
func (e *Engine) addressResponse(req *dns.Msg, v4, v6 netip.Addr, s *settings) *dns.Msg {
	question := req.Question[0]

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true

	hdr := dns.RR_Header{
		Name:   question.Name,
		Rrtype: question.Qtype,
		Class:  dns.ClassINET,
		Ttl:    s.blockedTTL,
	}

	switch question.Qtype {
	case dns.TypeA:
		if !v4.IsValid() {
			return e.negativeResponse(req, dns.RcodeSuccess, s)
		}
		resp.Answer = append(resp.Answer, &dns.A{Hdr: hdr, A: v4.AsSlice()})

	case dns.TypeAAAA:
		if !v6.IsValid() {
			return e.negativeResponse(req, dns.RcodeSuccess, s)
		}
		resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: hdr, AAAA: v6.AsSlice()})

	default:
		// NODATA: the name exists, but not with this type. This is the honest
		// answer for a blocked name and it caches correctly.
		return e.negativeResponse(req, dns.RcodeSuccess, s)
	}

	return resp
}

// negativeResponse builds an empty answer with an SOA in the authority
// section, which is what lets clients cache the negative result for the TTL
// rather than retrying every time.
func (e *Engine) negativeResponse(req *dns.Msg, rcode int, s *settings) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetRcode(req, rcode)
	resp.Authoritative = true

	zone := req.Question[0].Name
	if parent := parentZone(zone); parent != "" {
		zone = parent
	}

	resp.Ns = append(resp.Ns, &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    s.blockedTTL,
		},
		Ns:      "aegisdns.invalid.",
		Mbox:    "hostmaster.aegisdns.invalid.",
		Serial:  uint32(time.Now().Unix()),
		Refresh: 1800,
		Retry:   900,
		Expire:  604800,
		Minttl:  s.blockedTTL,
	})

	return resp
}

func parentZone(name string) string {
	_, rest, found := strings.Cut(name, ".")
	if !found || rest == "" || rest == "." {
		return name
	}

	return rest
}
