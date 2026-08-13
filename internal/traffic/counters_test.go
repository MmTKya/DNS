package traffic_test

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/MmTKya/DNS/internal/traffic"
)

// fakeCounters serves canned nftables output.
type fakeCounters struct {
	available bool
	installed string
	readings  []string
	index     int
}

func (f *fakeCounters) Available() bool { return f.available }

func (f *fakeCounters) Install(_ context.Context, ruleset string) error {
	f.installed = ruleset

	return nil
}

func (f *fakeCounters) Read(context.Context) ([]byte, error) {
	if f.index >= len(f.readings) {
		return []byte(f.readings[len(f.readings)-1]), nil
	}

	out := f.readings[f.index]
	f.index++

	return []byte(out), nil
}

// reading builds nftables JSON with the given byte totals.
func reading(addr string, rx, tx uint64) string {
	return fmt.Sprintf(`{"nftables":[
		{"metainfo":{"version":"1.0.9"}},
		{"rule":{"family":"inet","table":"seddns_acct","chain":"accounting",
		  "comment":"tx %s","expr":[{"match":{}},{"counter":{"packets":10,"bytes":%d}}]}},
		{"rule":{"family":"inet","table":"seddns_acct","chain":"accounting",
		  "comment":"rx %s","expr":[{"match":{}},{"counter":{"packets":20,"bytes":%d}}]}}
	]}`, addr, tx, addr, rx)
}

func TestRenderCountersObservesWithoutDeciding(t *testing.T) {
	t.Parallel()

	ruleset := traffic.RenderCounters([]netip.Addr{
		netip.MustParseAddr("192.168.1.50"),
		netip.MustParseAddr("fd00::5"),
	})

	// An accounting chain that could drop a packet would be a way to take the
	// whole network down while trying to draw a graph.
	if !strings.Contains(ruleset, "policy accept") {
		t.Errorf("the accounting chain must accept everything:\n%s", ruleset)
	}
	if strings.Contains(ruleset, "drop") {
		t.Errorf("the accounting chain must not contain a drop:\n%s", ruleset)
	}

	for _, want := range []string{
		`ip saddr 192.168.1.50 counter comment "tx 192.168.1.50"`,
		`ip daddr 192.168.1.50 counter comment "rx 192.168.1.50"`,
		`ip6 saddr fd00::5 counter comment "tx fd00::5"`,
	} {
		if !strings.Contains(ruleset, want) {
			t.Errorf("ruleset is missing %q:\n%s", want, ruleset)
		}
	}

	// Stable output: the same input must produce the same ruleset, or every
	// reconcile would look like a change.
	if traffic.RenderCounters([]netip.Addr{
		netip.MustParseAddr("fd00::5"),
		netip.MustParseAddr("192.168.1.50"),
	}) != ruleset {
		t.Error("RenderCounters is order-dependent")
	}
}

func TestParseCounters(t *testing.T) {
	t.Parallel()

	now := time.Now()
	samples, err := traffic.ParseCounters([]byte(reading("192.168.1.50", 5000, 1000)), now)
	if err != nil {
		t.Fatalf("ParseCounters: %v", err)
	}

	sample, ok := samples[netip.MustParseAddr("192.168.1.50")]
	if !ok {
		t.Fatalf("no sample for the address, got %+v", samples)
	}
	if sample.RxBytes != 5000 || sample.TxBytes != 1000 {
		t.Errorf("sample = %+v, want rx=5000 tx=1000", sample)
	}
}

func TestRatesNeedTwoReadings(t *testing.T) {
	t.Parallel()

	runner := &fakeCounters{
		available: true,
		readings: []string{
			reading("192.168.1.50", 1_000, 500),
			reading("192.168.1.50", 3_000, 1_500),
		},
	}
	acct := traffic.NewAccountant().WithRunner(runner)

	first, err := acct.Rates(t.Context())
	if err != nil {
		t.Fatalf("Rates: %v", err)
	}
	if len(first) != 1 {
		t.Fatalf("got %d rates, want 1", len(first))
	}

	// Nothing to compare against yet: reporting a rate here would mean
	// inventing an interval.
	if first[0].RxBytesPerSec != 0 {
		t.Errorf("first reading reported %v bytes/s, want 0", first[0].RxBytesPerSec)
	}
	if first[0].RxBytesTotal != 1_000 {
		t.Errorf("total = %d, want 1000", first[0].RxBytesTotal)
	}

	second, err := acct.Rates(t.Context())
	if err != nil {
		t.Fatalf("second Rates: %v", err)
	}
	if second[0].RxBytesTotal != 3_000 {
		t.Errorf("total = %d, want 3000", second[0].RxBytesTotal)
	}
	// The delta is 2,000 bytes over a very short interval, so the rate is
	// large but must be positive and finite.
	if second[0].RxBytesPerSec <= 0 {
		t.Errorf("rate = %v, want a positive throughput", second[0].RxBytesPerSec)
	}
	if !second[0].Measured {
		t.Error("counter-derived figures must be marked as measured, unlike the dwell estimates")
	}
}

func TestCounterResetDoesNotProduceNegativeRates(t *testing.T) {
	t.Parallel()

	runner := &fakeCounters{
		available: true,
		readings: []string{
			reading("192.168.1.50", 10_000, 5_000),
			// Reinstalling the ruleset zeroes the counters.
			reading("192.168.1.50", 100, 50),
		},
	}
	acct := traffic.NewAccountant().WithRunner(runner)

	if _, err := acct.Rates(t.Context()); err != nil {
		t.Fatalf("Rates: %v", err)
	}

	after, err := acct.Rates(t.Context())
	if err != nil {
		t.Fatalf("second Rates: %v", err)
	}
	if after[0].RxBytesPerSec != 0 {
		t.Errorf("a counter reset produced a rate of %v; it must be treated as a restart",
			after[0].RxBytesPerSec)
	}
}

func TestTrackRequiresNftables(t *testing.T) {
	t.Parallel()

	acct := traffic.NewAccountant().WithRunner(&fakeCounters{available: false})

	if err := acct.Track(t.Context(), []netip.Addr{netip.MustParseAddr("192.168.1.50")}); err == nil {
		t.Error("Track should fail when nftables is not available")
	}
	if acct.Available() {
		t.Error("Available must report the backend honestly")
	}
}
