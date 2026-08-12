package tunnel_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/MmTKya/DNS/internal/tunnel"
)

func TestRenderCloudflareConfig(t *testing.T) {
	t.Parallel()

	out, err := tunnel.RenderCloudflareConfig(tunnel.CloudflareConfig{
		TunnelID:        "abc-123",
		CredentialsFile: "/etc/aegisdns/tunnel.json",
		Hostname:        "panel.example.com",
		Service:         "http://127.0.0.1:8080",
	})
	if err != nil {
		t.Fatalf("RenderCloudflareConfig: %v", err)
	}

	for _, want := range []string{
		"tunnel: abc-123",
		"hostname: panel.example.com",
		"service: http://127.0.0.1:8080",
		// Without a catch-all, cloudflared refuses to start; leaving it open
		// would expose whatever else runs on this host.
		"service: http_status:404",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("config is missing %q:\n%s", want, out)
		}
	}
}

func TestCloudflareValidation(t *testing.T) {
	t.Parallel()

	if _, err := tunnel.RenderCloudflareConfig(tunnel.CloudflareConfig{}); err == nil {
		t.Error("an empty configuration should be refused")
	}
}

func TestExposuresStateTheTradeoff(t *testing.T) {
	t.Parallel()

	exposures := tunnel.Exposures(true)
	if len(exposures) < 3 {
		t.Fatalf("got %d exposure options, want the full set", len(exposures))
	}

	var recommended int
	byMethod := map[string]tunnel.Exposure{}
	for _, e := range exposures {
		byMethod[e.Method] = e
		if e.Recommended {
			recommended++
		}
		if e.Tradeoff == "" {
			t.Errorf("%s has no stated trade-off", e.Method)
		}
	}

	// Exactly one recommendation, and it has to be the one that exposes
	// nothing.
	if recommended != 1 {
		t.Errorf("%d options are recommended, want exactly 1", recommended)
	}
	if !byMethod["wireguard"].Recommended {
		t.Error("the option that exposes nothing should be the recommended one")
	}

	// The Cloudflare trade-off has to name what is given away, or it is not a
	// trade-off, it is an advert.
	if !strings.Contains(byMethod["cloudflare-tunnel"].Tradeoff, "Cloudflare terminates") {
		t.Errorf("the cloudflare option does not say what it gives away: %q",
			byMethod["cloudflare-tunnel"].Tradeoff)
	}
}

func TestExposuresReflectAvailability(t *testing.T) {
	t.Parallel()

	for _, e := range tunnel.Exposures(false) {
		if e.Method == "wireguard" && e.Available {
			t.Error("wireguard must not be offered when it is not available")
		}
	}
}

func testProfile() tunnel.EgressProfile {
	return tunnel.EgressProfile{
		Name:      "mullvad",
		Interface: "wg-egress",
		Table:     51,
		Mark:      0x51,
		Sources:   []netip.Prefix{netip.MustParsePrefix("192.168.1.50/32")},
	}
}

func TestPolicyRoutingIncludesAKillSwitch(t *testing.T) {
	t.Parallel()

	out, err := tunnel.RenderPolicyRouting(testProfile())
	if err != nil {
		t.Fatalf("RenderPolicyRouting: %v", err)
	}

	if !strings.Contains(out, "ip rule add fwmark 81 table 51") {
		t.Errorf("the routing rule is missing:\n%s", out)
	}
	if !strings.Contains(out, "meta mark set 81") {
		t.Errorf("the marking rule is missing:\n%s", out)
	}

	// Without this, a profile whose interface drops falls back to the ordinary
	// default route and the traffic leaves over the household's own line —
	// the one outcome the operator was trying to avoid.
	if !strings.Contains(out, `oifname != "wg-egress" drop`) {
		t.Errorf("the kill switch is missing:\n%s", out)
	}
}

func TestEgressValidationRefusesKernelTables(t *testing.T) {
	t.Parallel()

	profile := testProfile()
	// 253-255 are the kernel's own tables; taking one breaks routing in a way
	// that is very hard to diagnose.
	profile.Table = 254

	if err := profile.Validate(); err == nil {
		t.Error("a reserved routing table should be refused")
	}

	profile = testProfile()
	profile.Sources = nil
	if err := profile.Validate(); err == nil {
		t.Error("a profile with no sources should be refused")
	}
}

func TestTeardownUndoesTheProfile(t *testing.T) {
	t.Parallel()

	out := tunnel.RenderTeardown(testProfile())

	for _, want := range []string{"ip rule del fwmark 81", "ip route flush table 51", "delete table inet aegisdns_egress"} {
		if !strings.Contains(out, want) {
			t.Errorf("teardown is missing %q:\n%s", want, out)
		}
	}
}
