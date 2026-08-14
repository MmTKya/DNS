package shaper_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/MmTKya/DNS/internal/shaper"
)

func plan(limits ...shaper.Limit) shaper.Plan {
	return shaper.Plan{LANInterface: "eth1", WANInterface: "eth0", Limits: limits}
}

// The mistake this is most likely to make: a queue only controls what leaves
// an interface, so what a device downloads is shaped on the way out towards
// the house and what it uploads on the way out towards the modem. Doing both
// on one interface silently shapes the opposite direction.
func TestDownloadAndUploadAreShapedOnDifferentInterfaces(t *testing.T) {
	t.Parallel()

	commands, err := shaper.Render(plan(shaper.Limit{
		Address:      netip.MustParseAddr("192.168.68.79"),
		DownloadKbps: 10_000,
		UploadKbps:   2_000,
	}))
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	joined := strings.Join(commands, "\n")

	// Download: rate on the house-facing port, matched on the destination,
	// because those packets are going to the device.
	if !strings.Contains(joined, "class add dev eth1 parent 1:1 classid 1:10 htb rate 10000kbit ceil 10000kbit") {
		t.Error("the download class is not on the house-facing port at the rate asked for")
	}
	if !strings.Contains(joined, "filter add dev eth1 protocol ip parent 1: prio 1 u32 match ip dst 192.168.68.79/32 flowid 1:10") {
		t.Error("download is not matched on the destination address")
	}

	// Upload: the modem-facing port, matched on the source.
	if !strings.Contains(joined, "class add dev eth0 parent 1:1 classid 1:10 htb rate 2000kbit ceil 2000kbit") {
		t.Error("the upload class is not on the modem-facing port")
	}
	if !strings.Contains(joined, "filter add dev eth0 protocol ip parent 1: prio 1 u32 match ip src 192.168.68.79/32 flowid 1:10") {
		t.Error("upload is not matched on the source address")
	}
}

// A device nobody limited must not be slowed down by the machinery existing.
func TestUnlimitedTrafficIsNotCapped(t *testing.T) {
	t.Parallel()

	commands, err := shaper.Render(plan(shaper.Limit{
		Address:      netip.MustParseAddr("192.168.68.79"),
		DownloadKbps: 5_000,
	}))
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	joined := strings.Join(commands, "\n")
	if !strings.Contains(joined, "htb default 2") {
		t.Error("unclassified traffic has no default class and would be dropped or queued")
	}
	if !strings.Contains(joined, "classid 1:2 htb") {
		t.Error("the default class does not exist")
	}
}

// One direction only is a normal request: cap what a device uploads and leave
// its downloads alone.
func TestOneDirectionOnly(t *testing.T) {
	t.Parallel()

	commands, err := shaper.Render(plan(shaper.Limit{
		Address:    netip.MustParseAddr("192.168.68.79"),
		UploadKbps: 1_000,
	}))
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	joined := strings.Join(commands, "\n")
	if strings.Contains(joined, "match ip dst 192.168.68.79") {
		t.Error("a download filter was written for a device with no download limit")
	}
	if !strings.Contains(joined, "match ip src 192.168.68.79") {
		t.Error("the upload filter is missing")
	}
}

// The same plan must render the same commands, or nobody can tell what
// changed between two versions of a household's limits.
func TestRenderIsStable(t *testing.T) {
	t.Parallel()

	p := plan(
		shaper.Limit{Address: netip.MustParseAddr("192.168.68.90"), DownloadKbps: 1000},
		shaper.Limit{Address: netip.MustParseAddr("192.168.68.10"), DownloadKbps: 2000},
		shaper.Limit{Address: netip.MustParseAddr("192.168.68.50"), DownloadKbps: 3000},
	)

	first, err := shaper.Render(p)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	second, err := shaper.Render(p)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	if strings.Join(first, "\n") != strings.Join(second, "\n") {
		t.Error("the same plan rendered differently twice")
	}

	// Lowest address first, so a diff between two plans is readable.
	if !strings.Contains(strings.Join(first, "\n"), "192.168.68.10/32 flowid 1:10") {
		t.Error("classes are not assigned in address order")
	}
}

func TestRejectsNonsense(t *testing.T) {
	t.Parallel()

	addr := netip.MustParseAddr("192.168.68.79")

	cases := map[string]shaper.Plan{
		"same interface twice": {LANInterface: "eth0", WANInterface: "eth0"},
		"no interfaces":        {},
		"negative limit":       plan(shaper.Limit{Address: addr, DownloadKbps: -1}),
		// A limit that caps nothing is a setting somebody thought they made.
		"caps neither direction": plan(shaper.Limit{Address: addr}),
		// Someone who types 3 means 3 megabits, and 3 kbit is not a limit but
		// a broken connection.
		"unusably small": plan(shaper.Limit{Address: addr, DownloadKbps: 3}),
	}

	for name, p := range cases {
		if _, err := shaper.Render(p); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// recordingRunner stands in for the kernel.
type recordingRunner struct {
	available bool
	ran       [][]string
	failOn    string
}

func (r *recordingRunner) Available() bool { return r.available }

func (r *recordingRunner) Run(_ context.Context, args []string) error {
	r.ran = append(r.ran, args)

	if r.failOn != "" && strings.Contains(strings.Join(args, " "), r.failOn) {
		return context.DeadlineExceeded
	}

	return nil
}

// Clearing the old rules fails on a machine that has none, which is every
// machine the first time. That failure must not abort the whole apply.
func TestApplySurvivesNothingToDelete(t *testing.T) {
	t.Parallel()

	runner := &recordingRunner{available: true, failOn: "qdisc del"}
	s := shaper.New().WithRunner(runner)

	err := s.Apply(t.Context(), plan(shaper.Limit{
		Address:      netip.MustParseAddr("192.168.68.79"),
		DownloadKbps: 5_000,
	}))
	if err != nil {
		t.Fatalf("Apply() error = %v; a missing old ruleset is the normal first run", err)
	}

	if len(runner.ran) < 5 {
		t.Errorf("only %d commands ran; the plan was abandoned after the deletions", len(runner.ran))
	}
}

// Without tc nothing can be enforced, and saying so beats reporting success.
func TestApplyRefusesWithoutTheTooling(t *testing.T) {
	t.Parallel()

	s := shaper.New().WithRunner(&recordingRunner{available: false})

	if err := s.Apply(t.Context(), plan(shaper.Limit{
		Address:      netip.MustParseAddr("192.168.68.79"),
		DownloadKbps: 5_000,
	})); err == nil {
		t.Error("Apply() reported success with no way to apply anything")
	}
}
