package resolver

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/MmTKya/DNS/internal/config"
	"github.com/miekg/dns"
)

// rescueTimeout bounds a second attempt.
//
// Short on purpose: this runs after a query has already failed, so the person
// waiting has been waiting a while. A rescue that takes as long again is worse
// than the failure it is fixing.
const rescueTimeout = 3 * time.Second

// rescuer re-asks a different resolver when the first one gives up.
//
// SERVFAIL is not "this name does not exist" — it is "I could not find out",
// and it is very often specific to one resolver: a broken chain to a country's
// nameservers, an aggressive filter, a bad cache entry. The household does not
// care whose fault it is; they see a page that will not load, with nothing
// anywhere saying why.
//
// Only SERVFAIL is retried. NXDOMAIN is a real answer, and asking a second
// resolver for one would slow down every typo, defeat negative caching, and —
// worse here — give a name a second chance to resolve after this node has
// already decided it should not.
type rescuer struct {
	logger    *slog.Logger
	upstreams []upstream.Upstream

	// rebind drops answers that point a public name inside this network.
	rebind        bool
	blockingAddrs []netip.Addr

	// onRescue counts lookups that only succeeded on the second resolver.
	// Nil when nothing is watching.
	onRescue func()
}

// newRescuer builds the rescue pool, skipping anything already in use.
//
// A resolver that just failed is not going to succeed on the retry, and
// including it would turn the rescue into a slower way to get the same answer.
func newRescuer(cfg *config.Config, opts *upstream.Options, logger *slog.Logger) *rescuer {
	inUse := make(map[string]bool, len(cfg.DNS.Upstreams))
	for _, address := range cfg.DNS.Upstreams {
		inUse[address] = true
	}

	r := &rescuer{
		logger: logger.With("component", "rescue"),
		rebind: cfg.DNS.RebindProtection,
	}

	// The node's own blocking answers are internal addresses on purpose, so
	// they are recognised rather than caught by the protection.
	for _, address := range []string{cfg.Filtering.BlockingIPv4, cfg.Filtering.BlockingIPv6} {
		if addr, err := netip.ParseAddr(address); err == nil {
			r.blockingAddrs = append(r.blockingAddrs, addr)
		}
	}

	for _, address := range rescueAddresses(cfg.DNS.Rescue) {
		if inUse[address] {
			continue
		}

		u, err := upstream.AddressToUpstream(address, opts)
		if err != nil {
			logger.Warn("skipping an unusable rescue resolver", "address", address, "err", err)

			continue
		}

		r.upstreams = append(r.upstreams, u)
	}

	return r
}

// resolve runs the proxy and, if the answer is a SERVFAIL, asks someone else.
func (r *rescuer) resolve(ctx context.Context, p *proxy.Proxy, dctx *proxy.DNSContext) error {
	err := p.Resolve(ctx, dctx)
	if err != nil || dctx.Res == nil {
		return err
	}

	if r.rebind {
		if hit, found := checkRebind(dctx.Res, r.blockingAddrs); found {
			// Warn, not debug: this is either an attack or a misconfiguration,
			// and both are things someone needs to know about rather than
			// discover as a site that mysteriously does not work.
			r.logger.WarnContext(ctx, "dropped an answer pointing into this network",
				"host", hit.Name, "address", hit.Address)

			refused := new(dns.Msg)
			refused.SetRcode(dctx.Req, dns.RcodeNameError)
			dctx.Res = refused

			return nil
		}
	}

	if dctx.Res.Rcode != dns.RcodeServerFailure {
		return nil
	}
	if len(r.upstreams) == 0 || dctx.Req == nil {
		return nil
	}

	rescued, from := r.retry(ctx, dctx.Req)
	if rescued == nil {
		return nil
	}

	// The reply is built against the original question, so the id and flags
	// match what the client sent rather than what the rescue resolver saw.
	rescued.SetRcode(dctx.Req, rescued.Rcode)
	dctx.Res = rescued

	if r.onRescue != nil {
		r.onRescue()
	}

	r.logger.DebugContext(ctx, "rescued a failed lookup",
		"host", dctx.Req.Question[0].Name, "via", from)

	return nil
}

// retry asks each rescue resolver in turn for the first usable answer.
func (r *rescuer) retry(ctx context.Context, req *dns.Msg) (res *dns.Msg, from string) {
	ctx, cancel := context.WithTimeout(ctx, rescueTimeout)
	defer cancel()

	for _, u := range r.upstreams {
		if ctx.Err() != nil {
			return nil, ""
		}

		// A copy, because the upstream sets its own id on the message it
		// sends and the original is still the client's.
		query := req.Copy()

		reply, err := u.Exchange(query)
		if err != nil || reply == nil {
			continue
		}

		// NXDOMAIN from the rescue resolver is accepted: it is a real answer,
		// and the point of asking was that the first resolver had none.
		if reply.Rcode == dns.RcodeServerFailure || reply.Rcode == dns.RcodeRefused {
			continue
		}

		return reply, u.Address()
	}

	return nil, ""
}

// close releases the rescue upstreams.
func (r *rescuer) close() {
	for _, u := range r.upstreams {
		_ = u.Close()
	}
}

// rescueAddresses returns the defaults, used when nothing is configured.
//
// Two operators rather than one, and neither of them the shipped primary: the
// whole value of a rescue is that it fails differently from the thing it is
// rescuing.
func rescueAddresses(configured []string) []string {
	if len(configured) > 0 {
		return slices.Clone(configured)
	}

	return []string{"1.1.1.1", "8.8.8.8"}
}
