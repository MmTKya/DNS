package enforce_test

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/MmTKya/DNS/internal/config"
	"github.com/MmTKya/DNS/internal/enforce"
)

// fakeRunner captures rulesets instead of handing them to a kernel.
type fakeRunner struct {
	mu        sync.Mutex
	rulesets  []string
	available bool
	err       error
}

func (f *fakeRunner) Available() bool { return f.available }

func (f *fakeRunner) Run(_ context.Context, stdin string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.err != nil {
		return f.err
	}
	f.rulesets = append(f.rulesets, stdin)

	return nil
}

func (f *fakeRunner) last() string {
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(f.rulesets) == 0 {
		return ""
	}

	return f.rulesets[len(f.rulesets)-1]
}

func (f *fakeRunner) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.rulesets)
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestRenderBlocksByMACWhenKnown(t *testing.T) {
	t.Parallel()

	ruleset := enforce.Render([]enforce.Target{{
		Addr: netip.MustParseAddr("192.168.1.50"),
		MAC:  "AA:BB:CC:DD:EE:FF",
	}})

	// The hardware address is what survives the device renewing its lease onto
	// a different address, so it must be preferred.
	if !strings.Contains(ruleset, "ether saddr aa:bb:cc:dd:ee:ff drop") {
		t.Errorf("ruleset does not block by MAC:\n%s", ruleset)
	}
	if strings.Contains(ruleset, "192.168.1.50") {
		t.Errorf("ruleset fell back to the address despite knowing the MAC:\n%s", ruleset)
	}

	// Both directions: dropping only outbound leaves the device reachable.
	if !strings.Contains(ruleset, "ether daddr aa:bb:cc:dd:ee:ff drop") {
		t.Errorf("ruleset only blocks one direction:\n%s", ruleset)
	}
}

func TestRenderFallsBackToAddress(t *testing.T) {
	t.Parallel()

	ruleset := enforce.Render([]enforce.Target{
		{Addr: netip.MustParseAddr("192.168.1.50")},
		{Addr: netip.MustParseAddr("fd00::5")},
	})

	for _, want := range []string{
		"ip saddr 192.168.1.50 drop",
		"ip daddr 192.168.1.50 drop",
		"ip6 saddr fd00::5 drop",
		"ip6 daddr fd00::5 drop",
	} {
		if !strings.Contains(ruleset, want) {
			t.Errorf("ruleset is missing %q:\n%s", want, ruleset)
		}
	}
}

func TestRenderIsIdempotent(t *testing.T) {
	t.Parallel()

	targets := []enforce.Target{{Addr: netip.MustParseAddr("192.168.1.50")}}

	// Reconciling to a desired state cannot drift; patching individual rules
	// eventually leaves a device blocked that the panel says is not.
	if enforce.Render(targets) != enforce.Render(targets) {
		t.Error("Render is not deterministic")
	}

	ruleset := enforce.Render(targets)
	if !strings.Contains(ruleset, "delete table inet seddns") {
		t.Errorf("ruleset does not replace the previous state:\n%s", ruleset)
	}
	if !strings.Contains(ruleset, "policy accept") {
		t.Errorf("the chain must default to accept; a default drop would take the network down:\n%s", ruleset)
	}
}

func TestRenderRejectsMalformedMAC(t *testing.T) {
	t.Parallel()

	// Anything that is not a hardware address must never be pasted into a
	// ruleset that is fed to a privileged command.
	for _, bad := range []string{
		"not-a-mac",
		"aa:bb:cc:dd:ee",
		"aa:bb:cc:dd:ee:zz",
		"aa:bb:cc:dd:ee:ff; drop table inet filter",
	} {
		ruleset := enforce.Render([]enforce.Target{{
			Addr: netip.MustParseAddr("192.168.1.50"),
			MAC:  bad,
		}})

		if strings.Contains(ruleset, "ether") {
			t.Errorf("MAC %q was accepted:\n%s", bad, ruleset)
		}
		// It falls back to the address rather than producing nothing.
		if !strings.Contains(ruleset, "192.168.1.50") {
			t.Errorf("MAC %q left the device unblocked entirely:\n%s", bad, ruleset)
		}
	}
}

func TestDNSOnlyModeIsNotEnforceable(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{available: true}
	e := enforce.New(config.ModeDNSOnly, discard()).WithRunner(runner)

	err := e.Apply(t.Context(), []enforce.Target{{Addr: netip.MustParseAddr("192.168.1.50")}})
	if err == nil {
		t.Fatal("DNS-only mode must report that it cannot enforce a block")
	}
	if runner.count() != 0 {
		t.Error("no firewall rules should be written in DNS-only mode")
	}

	// The wording matters: this is what the panel shows, and it must not
	// promise a kill switch it cannot deliver.
	capability := e.Capability()
	if capability.Enforced {
		t.Error("DNS-only mode must not report enforcement")
	}
	if !strings.Contains(capability.Explanation, "keeps its network access") {
		t.Errorf("explanation does not say what pausing actually does: %q", capability.Explanation)
	}
}

func TestGatewayModeApplies(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{available: true}
	e := enforce.New(config.ModeGateway, discard()).WithRunner(runner)

	if capability := e.Capability(); !capability.Enforced {
		t.Error("gateway mode with nftables available should report enforcement")
	}

	targets := []enforce.Target{{Addr: netip.MustParseAddr("192.168.1.50")}}
	if err := e.Apply(t.Context(), targets); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !strings.Contains(runner.last(), "192.168.1.50") {
		t.Errorf("the applied ruleset does not block the target:\n%s", runner.last())
	}

	// Applying the same set again is a no-op: reloading the panel should not
	// reload the firewall.
	if err := e.Apply(t.Context(), targets); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if runner.count() != 1 {
		t.Errorf("the firewall was rewritten %d times for an unchanged set", runner.count())
	}

	// A change does go through.
	if err := e.Apply(t.Context(), append(targets, enforce.Target{
		Addr: netip.MustParseAddr("192.168.1.51"),
	})); err != nil {
		t.Fatalf("third Apply: %v", err)
	}
	if runner.count() != 2 {
		t.Errorf("a changed set was applied %d times, want 2 total", runner.count())
	}
}

func TestGatewayModeWithoutNftablesDegradesHonestly(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{available: false}
	e := enforce.New(config.ModeGateway, discard()).WithRunner(runner)

	capability := e.Capability()
	if capability.Enforced {
		t.Error("enforcement must not be claimed when nftables is missing")
	}
	if capability.Available {
		t.Error("availability must be reported as false when the tool is missing")
	}

	if err := e.Apply(t.Context(), []enforce.Target{{Addr: netip.MustParseAddr("192.168.1.50")}}); err == nil {
		t.Error("Apply should fail when nftables is missing")
	}
}
