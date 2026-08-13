package resolver

import (
	"context"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/MmTKya/DNS/internal/config"
	"github.com/miekg/dns"
)

// serveDNS starts a resolver that returns the given rcode, with an A record
// when the rcode is NOERROR.
func serveDNS(t *testing.T, rcode int) string {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}

	server := &dns.Server{PacketConn: conn}
	server.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetRcode(req, rcode)

		if rcode == dns.RcodeSuccess {
			reply.Answer = append(reply.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name: req.Question[0].Name, Rrtype: dns.TypeA,
					Class: dns.ClassINET, Ttl: 60,
				},
				A: net.IPv4(203, 0, 113, 7),
			})
		}

		_ = w.WriteMsg(reply)
	})

	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	return conn.LocalAddr().String()
}

func newTestRescuer(t *testing.T, rescueAddrs []string) *rescuer {
	t.Helper()

	cfg := &config.Config{}
	cfg.DNS.Rescue = rescueAddrs

	return newRescuer(cfg, &upstream.Options{}, slog.New(slog.DiscardHandler))
}

// The failure this exists for: one resolver cannot answer and the household
// sees a page that will not load. A second opinion turns it into an answer.
func TestRescueTurnsAServfailIntoAnAnswer(t *testing.T) {
	t.Parallel()

	good := serveDNS(t, dns.RcodeSuccess)
	r := newTestRescuer(t, []string{good})

	req := new(dns.Msg)
	req.SetQuestion("gib.gov.tr.", dns.TypeA)

	res, from := r.retry(context.Background(), req)
	if res == nil {
		t.Fatal("retry() returned nothing for a resolver that answers")
	}
	if res.Rcode != dns.RcodeSuccess || len(res.Answer) == 0 {
		t.Errorf("retry() = %s with %d answers, want NOERROR with an answer",
			dns.RcodeToString[res.Rcode], len(res.Answer))
	}
	if from == "" {
		t.Error("retry() did not say which resolver answered")
	}
}

// A rescue resolver that fails the same way must not be reported as a rescue.
func TestRescueSkipsResolversThatAlsoFail(t *testing.T) {
	t.Parallel()

	broken := serveDNS(t, dns.RcodeServerFailure)
	good := serveDNS(t, dns.RcodeSuccess)

	r := newTestRescuer(t, []string{broken, good})

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	res, from := r.retry(context.Background(), req)
	if res == nil || res.Rcode != dns.RcodeSuccess {
		t.Fatalf("retry() did not fall through to the working resolver: %v", res)
	}
	if from == broken {
		t.Error("retry() reported the broken resolver as the one that answered")
	}
}

// NXDOMAIN from a rescue resolver is a real answer and is taken as one: the
// first resolver had none, and "does not exist" is information.
func TestRescueAcceptsNXDOMAIN(t *testing.T) {
	t.Parallel()

	missing := serveDNS(t, dns.RcodeNameError)
	r := newTestRescuer(t, []string{missing})

	req := new(dns.Msg)
	req.SetQuestion("nothing.invalid.", dns.TypeA)

	res, _ := r.retry(context.Background(), req)
	if res == nil || res.Rcode != dns.RcodeNameError {
		t.Fatalf("retry() = %v, want NXDOMAIN to be accepted", res)
	}
}

// The rescue pool must not contain a resolver that is already answering
// queries: it just failed, and asking it again is a slower way to fail.
func TestRescueExcludesResolversAlreadyInUse(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{}
	cfg.DNS.Upstreams = []string{"1.1.1.1", "8.8.8.8"}
	cfg.DNS.Rescue = []string{"1.1.1.1", "9.9.9.9"}

	r := newRescuer(cfg, &upstream.Options{}, slog.New(slog.DiscardHandler))
	t.Cleanup(r.close)

	for _, u := range r.upstreams {
		if u.Address() == "1.1.1.1" {
			t.Error("a resolver already in use was kept in the rescue pool")
		}
	}
	if len(r.upstreams) == 0 {
		t.Error("the rescue pool is empty; 9.9.9.9 should have survived")
	}
}

// Without this the defaults would be empty and the whole mechanism would sit
// there doing nothing on the installs that need it most.
func TestRescueDefaultsAreUsedWhenNothingIsConfigured(t *testing.T) {
	t.Parallel()

	if got := rescueAddresses(nil); len(got) < 2 {
		t.Errorf("rescueAddresses(nil) = %v, want at least two resolvers", got)
	}

	configured := []string{"192.0.2.1"}
	if got := rescueAddresses(configured); len(got) != 1 || got[0] != "192.0.2.1" {
		t.Errorf("rescueAddresses(%v) = %v, want the configured list", configured, got)
	}
}

// A rescued name must be paid for once. The proxy's own cache never sees these
// answers — its lookup already returned SERVFAIL and the good answer is
// substituted afterwards — so without this every visit to the same name costs
// the second lookup again.
func TestRescuedAnswersAreCached(t *testing.T) {
	t.Parallel()

	var asked atomic.Int64
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}

	server := &dns.Server{PacketConn: conn}
	server.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		asked.Add(1)

		reply := new(dns.Msg)
		reply.SetReply(req)
		reply.Answer = append(reply.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name: req.Question[0].Name, Rrtype: dns.TypeA,
				Class: dns.ClassINET, Ttl: 300,
			},
			A: net.IPv4(203, 0, 113, 9),
		})
		_ = w.WriteMsg(reply)
	})
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	r := newTestRescuer(t, []string{conn.LocalAddr().String()})

	req := new(dns.Msg)
	req.SetQuestion("gib.gov.tr.", dns.TypeA)

	res, _ := r.retry(context.Background(), req)
	if res == nil {
		t.Fatal("the first rescue returned nothing")
	}
	r.store(req, res)

	if hit := r.fromCache(req); hit == nil {
		t.Fatal("the rescued answer was not cached")
	}
	if asked.Load() != 1 {
		t.Errorf("the resolver was asked %d times, want 1", asked.Load())
	}

	// A different record type is a different question and must not be served
	// the cached A record.
	other := new(dns.Msg)
	other.SetQuestion("gib.gov.tr.", dns.TypeAAAA)
	if hit := r.fromCache(other); hit != nil {
		t.Error("an AAAA question was answered from the cached A record")
	}
}

// An expired entry must not be served: the point of rescuing a name is that
// something upstream was broken, and it may since have been fixed.
func TestExpiredRescuesAreNotServed(t *testing.T) {
	t.Parallel()

	r := newTestRescuer(t, nil)

	req := new(dns.Msg)
	req.SetQuestion("stale.example.com.", dns.TypeA)

	res := new(dns.Msg)
	res.SetReply(req)
	res.Answer = append(res.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.IPv4(203, 0, 113, 9),
	})

	r.store(req, res)

	r.cacheMu.Lock()
	for key, entry := range r.cache {
		entry.expiresAt = time.Now().Add(-time.Second)
		r.cache[key] = entry
	}
	r.cacheMu.Unlock()

	if hit := r.fromCache(req); hit != nil {
		t.Error("an expired rescue was served")
	}
}
