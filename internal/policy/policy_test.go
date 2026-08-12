package policy_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/MmTKya/DNS/internal/config"
	"github.com/MmTKya/DNS/internal/filter"
	"github.com/MmTKya/DNS/internal/policy"
	"github.com/MmTKya/DNS/internal/resolver"
	"github.com/miekg/dns"
)

const upstreamAnswer = "192.0.2.99"

// recorder collects the events the policy engine emits.
type recorder struct {
	mu     sync.Mutex
	events []policy.Event
}

func (r *recorder) Observe(event policy.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, event)
}

func (r *recorder) last() (policy.Event, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.events) == 0 {
		return policy.Event{}, false
	}

	return r.events[len(r.events)-1], true
}

// newEngine builds a policy engine over the given rules.
func newEngine(t *testing.T, rules string, mutate func(*config.Config)) (*policy.Engine, *recorder) {
	t.Helper()

	builder := filter.NewBuilder()
	src := builder.AddSource("test-list", "Test list")
	if _, err := builder.AddReader(src, strings.NewReader(rules)); err != nil {
		t.Fatalf("compiling rules: %v", err)
	}

	engine := filter.NewEngine()
	engine.Replace(builder.Build())

	cfg := config.Default()
	if mutate != nil {
		mutate(cfg)
	}

	rec := &recorder{}
	pol := policy.New(engine, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	pol.SetObserver(rec)

	return pol, rec
}

// ask runs one query through the policy hook.  upstreamCalled reports whether
// the query would have been forwarded.
func ask(t *testing.T, pol *policy.Engine, name string, qtype uint16, decorate func(*proxy.DNSContext)) (resp *dns.Msg, upstreamCalled bool) {
	t.Helper()

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)

	dctx := &proxy.DNSContext{
		Req:   req,
		Proto: proxy.ProtoUDP,
		Addr:  netip.MustParseAddrPort("192.168.1.50:5000"),
	}
	if decorate != nil {
		decorate(dctx)
	}

	resolve := func(_ context.Context, d *proxy.DNSContext) error {
		upstreamCalled = true

		answer := new(dns.Msg)
		answer.SetReply(d.Req)
		if d.Req.Question[0].Qtype == dns.TypeA {
			rr, err := dns.NewRR(d.Req.Question[0].Name + " 300 IN A " + upstreamAnswer)
			if err != nil {
				return err
			}
			answer.Answer = append(answer.Answer, rr)
		}
		d.Res = answer

		return nil
	}

	if err := pol.Hook()(t.Context(), dctx, resolver.Resolve(resolve)); err != nil {
		t.Fatalf("hook: %v", err)
	}

	return dctx.Res, upstreamCalled
}

func TestBlockedNullIP(t *testing.T) {
	t.Parallel()

	pol, rec := newEngine(t, "||ads.example.com^\n", nil)

	resp, forwarded := ask(t, pol, "ads.example.com", dns.TypeA, nil)
	if forwarded {
		t.Error("a blocked query must never reach the upstream")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}
	if a := resp.Answer[0].(*dns.A); a.A.String() != "0.0.0.0" {
		t.Errorf("A = %s, want 0.0.0.0", a.A)
	}

	resp, _ = ask(t, pol, "ads.example.com", dns.TypeAAAA, nil)
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d AAAA answers, want 1", len(resp.Answer))
	}
	if aaaa := resp.Answer[0].(*dns.AAAA); aaaa.AAAA.String() != "::" {
		t.Errorf("AAAA = %s, want ::", aaaa.AAAA)
	}

	event, ok := rec.last()
	if !ok {
		t.Fatal("no event was recorded")
	}
	if event.Verdict != policy.VerdictBlocked {
		t.Errorf("verdict = %q, want %q", event.Verdict, policy.VerdictBlocked)
	}
	if event.RuleSource != "test-list" {
		t.Errorf("rule source = %q, want %q", event.RuleSource, "test-list")
	}
}

func TestBlockedNonAddressTypesGetNodata(t *testing.T) {
	t.Parallel()

	pol, _ := newEngine(t, "||ads.example.com^\n", nil)

	// Answering A while letting HTTPS or SVCB through to the upstream leaks
	// the very connection the block was meant to stop, and inconsistent
	// handling across types is a documented way past protective DNS.
	for _, qtype := range []uint16{dns.TypeHTTPS, dns.TypeSVCB, dns.TypeMX, dns.TypeTXT, dns.TypeCNAME} {
		resp, forwarded := ask(t, pol, "ads.example.com", qtype, nil)
		if forwarded {
			t.Errorf("%s: forwarded upstream despite the block", dns.TypeToString[qtype])
		}
		if resp.Rcode != dns.RcodeSuccess {
			t.Errorf("%s: rcode = %s, want NOERROR (NODATA)", dns.TypeToString[qtype], dns.RcodeToString[resp.Rcode])
		}
		if len(resp.Answer) != 0 {
			t.Errorf("%s: got %d answers, want 0", dns.TypeToString[qtype], len(resp.Answer))
		}
		// An SOA in the authority section is what lets the client cache the
		// negative answer instead of retrying every time.
		if len(resp.Ns) != 1 {
			t.Errorf("%s: got %d authority records, want an SOA", dns.TypeToString[qtype], len(resp.Ns))
		}
	}
}

func TestBlockingModes(t *testing.T) {
	t.Parallel()

	t.Run("nxdomain", func(t *testing.T) {
		t.Parallel()

		pol, _ := newEngine(t, "||ads.example.com^\n", func(c *config.Config) {
			c.Filtering.BlockingMode = config.BlockingModeNXDOMAIN
		})

		resp, _ := ask(t, pol, "ads.example.com", dns.TypeA, nil)
		if resp.Rcode != dns.RcodeNameError {
			t.Errorf("rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
		}
	})

	t.Run("refused", func(t *testing.T) {
		t.Parallel()

		pol, _ := newEngine(t, "||ads.example.com^\n", func(c *config.Config) {
			c.Filtering.BlockingMode = config.BlockingModeRefused
		})

		resp, _ := ask(t, pol, "ads.example.com", dns.TypeA, nil)
		if resp.Rcode != dns.RcodeRefused {
			t.Errorf("rcode = %s, want REFUSED", dns.RcodeToString[resp.Rcode])
		}
	})

	t.Run("custom ip", func(t *testing.T) {
		t.Parallel()

		pol, _ := newEngine(t, "||ads.example.com^\n", func(c *config.Config) {
			c.Filtering.BlockingMode = config.BlockingModeCustomIP
			c.Filtering.BlockingIPv4 = "192.168.1.2"
		})

		resp, _ := ask(t, pol, "ads.example.com", dns.TypeA, nil)
		if len(resp.Answer) != 1 {
			t.Fatalf("got %d answers, want 1", len(resp.Answer))
		}
		if a := resp.Answer[0].(*dns.A); a.A.String() != "192.168.1.2" {
			t.Errorf("A = %s, want 192.168.1.2", a.A)
		}

		// No IPv6 address was configured, so AAAA has to be NODATA rather than
		// an invented answer.
		resp, _ = ask(t, pol, "ads.example.com", dns.TypeAAAA, nil)
		if len(resp.Answer) != 0 {
			t.Errorf("got %d AAAA answers, want 0", len(resp.Answer))
		}
	})
}

func TestAllowedNameIsForwarded(t *testing.T) {
	t.Parallel()

	pol, rec := newEngine(t, "||example.com^\n@@||cdn.example.com^\n", nil)

	resp, forwarded := ask(t, pol, "cdn.example.com", dns.TypeA, nil)
	if !forwarded {
		t.Error("an allowed name must be resolved normally")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}

	event, _ := rec.last()
	if event.Verdict != policy.VerdictAllowed {
		t.Errorf("verdict = %q, want %q", event.Verdict, policy.VerdictAllowed)
	}
	// The panel should be able to say which rule let it through.
	if event.RuleSource == "" {
		t.Error("an explicit exception should still be attributed")
	}
}

func TestRewrite(t *testing.T) {
	t.Parallel()

	pol, rec := newEngine(t, "||nas.home.lan^$dnsrewrite=192.168.1.10\n", nil)

	resp, forwarded := ask(t, pol, "nas.home.lan", dns.TypeA, nil)
	if forwarded {
		t.Error("a rewritten name must not be forwarded")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}
	if a := resp.Answer[0].(*dns.A); a.A.String() != "192.168.1.10" {
		t.Errorf("A = %s, want 192.168.1.10", a.A)
	}

	event, _ := rec.last()
	if event.Verdict != policy.VerdictRewritten {
		t.Errorf("verdict = %q, want %q", event.Verdict, policy.VerdictRewritten)
	}
}

func TestFilteringDisabledForwardsEverything(t *testing.T) {
	t.Parallel()

	pol, rec := newEngine(t, "||ads.example.com^\n", func(c *config.Config) {
		c.Filtering.Enabled = false
	})

	_, forwarded := ask(t, pol, "ads.example.com", dns.TypeA, nil)
	if !forwarded {
		t.Error("with filtering off, even a listed name must resolve")
	}

	// Queries are still recorded: turning filtering off is not the same as
	// turning visibility off.
	if event, ok := rec.last(); !ok || event.Verdict != policy.VerdictAllowed {
		t.Errorf("event = %+v, want a recorded allowed query", event)
	}
}

func TestClientIDFromDoHPath(t *testing.T) {
	t.Parallel()

	pol, rec := newEngine(t, "||games.example.com^$client='kids-tablet'\n", nil)

	withPath := func(path string) func(*proxy.DNSContext) {
		return func(d *proxy.DNSContext) {
			d.Proto = proxy.ProtoHTTPS
			d.HTTPRequest = &http.Request{URL: &url.URL{Path: path}}
		}
	}

	// A roaming device names itself in the DoH path, which is the only stable
	// identity once it leaves the LAN.
	_, forwarded := ask(t, pol, "games.example.com", dns.TypeA, withPath("/dns-query/kids-tablet"))
	if forwarded {
		t.Error("the named client should have been blocked")
	}
	if event, _ := rec.last(); event.ClientID != "kids-tablet" {
		t.Errorf("client id = %q, want %q", event.ClientID, "kids-tablet")
	}

	_, forwarded = ask(t, pol, "games.example.com", dns.TypeA, withPath("/dns-query/laptop"))
	if !forwarded {
		t.Error("a different client should not be affected by the rule")
	}
}

func TestClientIDIsSanitised(t *testing.T) {
	t.Parallel()

	pol, rec := newEngine(t, "", nil)

	// Anything arriving from the network ends up in logs and in the panel, so
	// only a conservative character set is accepted.
	for _, path := range []string{
		"/dns-query/../../etc/passwd",
		"/dns-query/<script>alert(1)</script>",
		"/dns-query/" + strings.Repeat("a", 100),
	} {
		ask(t, pol, "example.com", dns.TypeA, func(d *proxy.DNSContext) {
			d.Proto = proxy.ProtoHTTPS
			d.HTTPRequest = &http.Request{URL: &url.URL{Path: path}}
		})

		if event, _ := rec.last(); event.ClientID != "" {
			t.Errorf("path %q yielded client id %q, want it rejected", path, event.ClientID)
		}
	}
}

func TestObserverSeesResolutionDetail(t *testing.T) {
	t.Parallel()

	pol, rec := newEngine(t, "", nil)

	ask(t, pol, "example.com", dns.TypeA, nil)

	event, ok := rec.last()
	if !ok {
		t.Fatal("no event recorded")
	}
	if event.Host != "example.com" {
		t.Errorf("host = %q, want %q", event.Host, "example.com")
	}
	if event.QType != dns.TypeA {
		t.Errorf("qtype = %d, want %d", event.QType, dns.TypeA)
	}
	if event.Client.String() != "192.168.1.50" {
		t.Errorf("client = %s, want 192.168.1.50", event.Client)
	}
	if event.AnswerCount != 1 {
		t.Errorf("answer count = %d, want 1", event.AnswerCount)
	}
	if event.Elapsed <= 0 {
		t.Error("elapsed time should be recorded")
	}
}

func TestConfigureSwapsBlockingMode(t *testing.T) {
	t.Parallel()

	pol, _ := newEngine(t, "||ads.example.com^\n", nil)

	resp, _ := ask(t, pol, "ads.example.com", dns.TypeA, nil)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}

	cfg := config.Default()
	cfg.Filtering.BlockingMode = config.BlockingModeNXDOMAIN
	pol.Configure(cfg)

	resp, _ = ask(t, pol, "ads.example.com", dns.TypeA, nil)
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("rcode after reconfigure = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
	}
}
