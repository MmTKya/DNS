package upstreams

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/MmTKya/DNS/internal/store"
	"github.com/miekg/dns"
)

// fakeResolver serves A records for the names in answers and SERVFAILs for
// anything else, after waiting delay.
//
// The delay is what makes the ordering testable: a resolver has to be able to
// be both fast and wrong.
func fakeResolver(t *testing.T, delay time.Duration, answers map[string]bool) string {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}

	server := &dns.Server{PacketConn: conn}
	server.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		time.Sleep(delay)

		reply := new(dns.Msg)
		reply.SetReply(req)

		name := req.Question[0].Name
		if !answers[name] {
			reply.Rcode = dns.RcodeServerFailure
			_ = w.WriteMsg(reply)

			return
		}

		reply.Answer = append(reply.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(192, 0, 2, 1),
		})
		_ = w.WriteMsg(reply)
	})

	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	return conn.LocalAddr().String()
}

func everyProbe() map[string]bool {
	answers := make(map[string]bool, len(probes))
	for _, name := range probes {
		answers[dns.Fqdn(name)] = true
	}

	return answers
}

// The rule the whole feature rests on. A resolver that answers a reachability
// check in no time and cannot resolve one of the probes must lose to a slower
// one that resolves all of them — which is exactly the situation that made
// this necessary: the shipped default is fast and cannot resolve gib.gov.tr.
func TestBenchmarkRanksCorrectnessAboveSpeed(t *testing.T) {
	t.Parallel()

	// Fast, but blind to one name.
	partial := everyProbe()
	delete(partial, dns.Fqdn("gib.gov.tr"))
	fastBroken := fakeResolver(t, 0, partial)

	// Slower, and answers everything.
	slowGood := fakeResolver(t, 40*time.Millisecond, everyProbe())

	results, err := Benchmark(t.Context(), []string{fastBroken, slowGood}, 2*time.Second)
	if err != nil {
		t.Fatalf("Benchmark() error = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("Benchmark() returned %d results, want 2", len(results))
	}

	if results[0].Address != slowGood {
		t.Errorf("the fast resolver that cannot resolve everything was ranked first: %+v", results)
	}
	if !results[0].Usable {
		t.Error("the resolver that answered every probe was not marked usable")
	}
	if results[1].Usable {
		t.Error("a resolver that failed a probe was marked usable")
	}
	if results[1].Error == "" {
		t.Error("the failing resolver did not say what went wrong")
	}
}

// Adopting takes the best two, so a single slow moment does not leave the
// household waiting on one server.
func TestAdoptTakesTheBestTwoUsableResolvers(t *testing.T) {
	t.Parallel()

	db := openTestDB(t)

	results := []Result{
		{Address: "10.0.0.1", Usable: true, MedianMS: 10},
		{Address: "10.0.0.2", Usable: true, MedianMS: 20},
		{Address: "10.0.0.3", Usable: true, MedianMS: 30},
	}

	adopted, err := Adopt(t.Context(), db, results)
	if err != nil {
		t.Fatalf("Adopt() error = %v", err)
	}
	if len(adopted) != 2 || adopted[0] != "10.0.0.1" || adopted[1] != "10.0.0.2" {
		t.Fatalf("Adopt() = %v, want the best two", adopted)
	}

	primary, _, err := Effective(t.Context(), db)
	if err != nil {
		t.Fatalf("Effective() error = %v", err)
	}
	if len(primary) != 2 {
		t.Errorf("Effective() primary = %v, want two resolvers", primary)
	}
}

// Nothing usable must not wipe a working configuration and leave the node
// with an empty list it then treats as "use the defaults".
func TestAdoptRefusesWhenNothingIsUsable(t *testing.T) {
	t.Parallel()

	db := openTestDB(t)

	if _, err := Add(t.Context(), db, "8.8.8.8", RolePrimary, ""); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	_, err := Adopt(t.Context(), db, []Result{{Address: "10.0.0.1", Usable: false}})
	if err == nil {
		t.Fatal("Adopt() accepted a benchmark in which nothing worked")
	}

	primary, _, err := Effective(t.Context(), db)
	if err != nil {
		t.Fatalf("Effective() error = %v", err)
	}
	if len(primary) != 1 || primary[0] != "8.8.8.8" {
		t.Errorf("the working configuration was lost: %v", primary)
	}
}

// openTestDB is the in-package counterpart of the helper in the external test
// file, which cannot be reached from here.
func openTestDB(t *testing.T) *store.DB {
	t.Helper()

	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "bench.db"))
	if err != nil {
		t.Fatalf("opening the database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	return db
}
