package resolver_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/MmTKya/DNS/internal/config"
	"github.com/MmTKya/DNS/internal/resolver"
	"github.com/miekg/dns"
)

// fakeUpstream is a DNS server that answers every A query with answerIP and
// counts how many queries reached it, which is how the tests tell "served from
// the hook or the cache" apart from "forwarded".
type fakeUpstream struct {
	addr    string
	queries atomic.Int64
	server  *dns.Server
}

const answerIP = "192.0.2.10"

func startFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for fake upstream: %v", err)
	}

	up := &fakeUpstream{addr: pc.LocalAddr().String()}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		up.queries.Add(1)

		resp := new(dns.Msg)
		resp.SetReply(req)

		if len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeA {
			rr, rrErr := dns.NewRR(req.Question[0].Name + " 3600 IN A " + answerIP)
			if rrErr == nil {
				resp.Answer = append(resp.Answer, rr)
			}
		}

		_ = w.WriteMsg(resp)
	})

	started := make(chan struct{})
	up.server = &dns.Server{
		PacketConn:        pc,
		Handler:           mux,
		NotifyStartedFunc: func() { close(started) },
	}

	go func() { _ = up.server.ActivateAndServe() }()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("fake upstream did not start")
	}

	t.Cleanup(func() { _ = up.server.Shutdown() })

	return up
}

// testConfig returns a config that binds to an ephemeral loopback port, so the
// tests never need privileges or a free well-known port.
func testConfig(upstreamAddr string) *config.Config {
	cfg := config.Default()
	cfg.DNS.Listen = []string{"127.0.0.1:0"}
	cfg.DNS.Upstreams = []string{upstreamAddr}
	cfg.DNS.Bootstrap = nil
	cfg.Store.Path = ""
	cfg.HTTP.Listen = "127.0.0.1:0"

	return cfg
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func startResolver(t *testing.T, cfg *config.Config) *resolver.Resolver {
	t.Helper()

	r := resolver.New(cfg, discardLogger())
	if err := r.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := r.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})

	return r
}

// udpAddr picks the bound UDP address out of Addrs.
func udpAddr(t *testing.T, r *resolver.Resolver) string {
	t.Helper()

	for _, a := range r.Addrs() {
		if addr, proto, ok := strings.Cut(a, "/"); ok && proto == "udp" {
			return addr
		}
	}

	t.Fatalf("resolver reported no udp address, got %v", r.Addrs())

	return ""
}

func query(t *testing.T, serverAddr, name string) *dns.Msg {
	t.Helper()

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), dns.TypeA)

	client := &dns.Client{Timeout: 5 * time.Second}
	resp, _, err := client.Exchange(req, serverAddr)
	if err != nil {
		t.Fatalf("querying %s for %s: %v", serverAddr, name, err)
	}

	return resp
}

func TestResolveForwardsToUpstream(t *testing.T) {
	t.Parallel()

	up := startFakeUpstream(t)
	r := startResolver(t, testConfig(up.addr))

	resp := query(t, udpAddr(t, r), "example.com")

	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}

	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer is %T, want *dns.A", resp.Answer[0])
	}
	if a.A.String() != answerIP {
		t.Errorf("answer = %s, want %s", a.A, answerIP)
	}
	if got := up.queries.Load(); got != 1 {
		t.Errorf("upstream saw %d queries, want 1", got)
	}
}

func TestCacheServesRepeatQuery(t *testing.T) {
	t.Parallel()

	up := startFakeUpstream(t)
	r := startResolver(t, testConfig(up.addr))
	addr := udpAddr(t, r)

	query(t, addr, "cached.example")
	query(t, addr, "cached.example")

	// The second query must never reach the upstream; the cache is the whole
	// point of the datapath sitting in front of it.
	if got := up.queries.Load(); got != 1 {
		t.Errorf("upstream saw %d queries, want 1: the cache did not serve the repeat", got)
	}
}

func TestHookCanAnswerWithoutUpstream(t *testing.T) {
	t.Parallel()

	up := startFakeUpstream(t)
	r := startResolver(t, testConfig(up.addr))

	const blockedIP = "0.0.0.0"

	// This is the shape phase 1's filter engine will take: inspect the
	// question, and answer it locally instead of forwarding.
	r.SetHook(func(_ context.Context, dctx *proxy.DNSContext) error {
		if len(dctx.Req.Question) == 0 || dctx.Req.Question[0].Name != "blocked.example." {
			return nil
		}

		resp := new(dns.Msg)
		resp.SetReply(dctx.Req)
		rr, err := dns.NewRR("blocked.example. 10 IN A " + blockedIP)
		if err != nil {
			return err
		}
		resp.Answer = append(resp.Answer, rr)
		dctx.Res = resp

		return nil
	})

	resp := query(t, udpAddr(t, r), "blocked.example")

	if len(resp.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(resp.Answer))
	}
	if a := resp.Answer[0].(*dns.A); a.A.String() != blockedIP {
		t.Errorf("answer = %s, want %s", a.A, blockedIP)
	}
	if got := up.queries.Load(); got != 0 {
		t.Errorf("upstream saw %d queries, want 0: a hook-answered query must not be forwarded", got)
	}

	// A name the hook ignores still resolves normally.
	if resp = query(t, udpAddr(t, r), "allowed.example"); len(resp.Answer) != 1 {
		t.Errorf("pass-through query got %d answers, want 1", len(resp.Answer))
	}
	if got := up.queries.Load(); got != 1 {
		t.Errorf("upstream saw %d queries, want 1", got)
	}
}

func TestReloadSwapsUpstream(t *testing.T) {
	t.Parallel()

	first := startFakeUpstream(t)
	second := startFakeUpstream(t)

	cfg := testConfig(first.addr)
	// A fixed port is needed here: reload rebinds, and the test has to keep
	// talking to the same address across the swap.
	port := freeUDPPort(t)
	cfg.DNS.Listen = []string{net.JoinHostPort("127.0.0.1", port)}

	r := startResolver(t, cfg)
	addr := cfg.DNS.Listen[0]

	query(t, addr, "before.example")

	next := testConfig(second.addr)
	next.DNS.Listen = cfg.DNS.Listen
	if err := r.Reload(t.Context(), next); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	query(t, addr, "after.example")

	if got := first.queries.Load(); got != 1 {
		t.Errorf("old upstream saw %d queries, want 1", got)
	}
	if got := second.queries.Load(); got != 1 {
		t.Errorf("new upstream saw %d queries, want 1: reload did not swap upstreams", got)
	}
}

func TestReloadRestoresPreviousConfigOnFailure(t *testing.T) {
	t.Parallel()

	up := startFakeUpstream(t)

	cfg := testConfig(up.addr)
	port := freeUDPPort(t)
	cfg.DNS.Listen = []string{net.JoinHostPort("127.0.0.1", port)}

	r := startResolver(t, cfg)
	addr := cfg.DNS.Listen[0]

	// Port 1 cannot be bound by an unprivileged test process, which is exactly
	// the class of failure an operator hits with a bad edit.
	broken := testConfig(up.addr)
	broken.DNS.Listen = []string{"127.0.0.1:1"}

	if err := r.Reload(t.Context(), broken); err == nil {
		t.Fatal("Reload with an unbindable address must fail")
	}

	if !r.Running() {
		t.Fatal("resolver must still be running after a failed reload")
	}

	// The old listener must be answering again, not left dead.
	resp := query(t, addr, "still-up.example")
	if len(resp.Answer) != 1 {
		t.Errorf("got %d answers after failed reload, want 1", len(resp.Answer))
	}
}

func TestShutdownIsIdempotent(t *testing.T) {
	t.Parallel()

	up := startFakeUpstream(t)
	r := resolver.New(testConfig(up.addr), discardLogger())

	// Shutting down something that never started is not an error: the process
	// unwinds the same way whether startup got this far or not.
	if err := r.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown before Start: %v", err)
	}

	if err := r.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if r.Addrs() == nil {
		t.Error("a running resolver must report its bound addresses")
	}

	if err := r.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := r.Shutdown(t.Context()); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}
	if r.Running() {
		t.Error("resolver reports running after shutdown")
	}
}

func TestStartTwiceFails(t *testing.T) {
	t.Parallel()

	up := startFakeUpstream(t)
	r := startResolver(t, testConfig(up.addr))

	if err := r.Start(t.Context()); err == nil {
		t.Error("starting an already running resolver must fail")
	}
}

// freeUDPPort returns a port that was free a moment ago.  There is an inherent
// race, but it is the standard way to get a stable address for a test that has
// to rebind the same port.
func freeUDPPort(t *testing.T) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding a free port: %v", err)
	}
	defer func() { _ = pc.Close() }()

	_, port, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("splitting %q: %v", pc.LocalAddr(), err)
	}

	return port
}
