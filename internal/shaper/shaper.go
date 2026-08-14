// Package shaper limits how fast a device may send and receive.
//
// This only means anything in gateway mode. A limit is enforced by holding
// packets back, and a node that merely answers questions about names never
// touches the packets — so the same rule that makes DNS-only mode honest about
// bandwidth makes it unable to cap it.
//
// The rules are rendered as text and applied by running tc, which keeps the
// part worth getting right — what the classes are, which direction they cover,
// what happens to traffic that matches nothing — testable without a kernel to
// hand.
package shaper

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
)

// Limit is one device's allowance.
type Limit struct {
	// Address is the device on the local network.
	Address netip.Addr

	// DownloadKbps is what it may receive, in kilobits per second. Zero means
	// unlimited in that direction.
	DownloadKbps int

	// UploadKbps is what it may send.
	UploadKbps int
}

// Validate reports what is wrong with a limit.
func (l Limit) Validate() error {
	if !l.Address.IsValid() {
		return errors.New("a device address is required")
	}
	if l.DownloadKbps < 0 || l.UploadKbps < 0 {
		return errors.New("a limit cannot be negative")
	}
	if l.DownloadKbps == 0 && l.UploadKbps == 0 {
		return errors.New("a limit that caps neither direction is not a limit")
	}

	// Below this a connection is unusable rather than limited, and someone
	// who typed 3 meant 3 megabits.
	const minKbps = 32
	if (l.DownloadKbps > 0 && l.DownloadKbps < minKbps) || (l.UploadKbps > 0 && l.UploadKbps < minKbps) {
		return fmt.Errorf("a limit below %d kbit/s leaves the device unable to load anything", minKbps)
	}

	return nil
}

// Plan is everything the kernel needs to enforce a set of limits.
type Plan struct {
	// LANInterface faces the house. Traffic going out of it is what the
	// household calls "download".
	LANInterface string

	// WANInterface faces the modem. Traffic going out of it is "upload".
	WANInterface string

	Limits []Limit
}

// ceilKbps is the total each direction is allowed, and the parent every class
// borrows from.
//
// Deliberately large: the point is to cap individual devices, not the line.
const ceilKbps = 10_000_000

// Render produces the tc commands for a plan.
//
// Download and upload are shaped on different interfaces because a queue only
// controls what leaves an interface. What a device downloads leaves the node
// towards the house; what it uploads leaves towards the modem. Trying to do
// both on one interface is the usual way this is got wrong, and it silently
// shapes the opposite direction.
func Render(plan Plan) (commands []string, err error) {
	if plan.LANInterface == "" || plan.WANInterface == "" {
		return nil, errors.New("both the house-facing and modem-facing ports are required")
	}
	if plan.LANInterface == plan.WANInterface {
		return nil, errors.New("the two ports must be different")
	}

	for _, limit := range plan.Limits {
		if err = limit.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", limit.Address, err)
		}
	}

	// Sorted so the same plan always renders the same commands: a ruleset
	// that changes order every time is one nobody can diff.
	limits := append([]Limit(nil), plan.Limits...)
	sort.Slice(limits, func(i, j int) bool { return limits[i].Address.Less(limits[j].Address) })

	commands = append(commands,
		// Removing the old root is how this stays idempotent. It fails when
		// there is nothing to remove, which the runner is told to ignore.
		"qdisc del dev "+plan.LANInterface+" root",
		"qdisc del dev "+plan.WANInterface+" root",
	)

	for _, iface := range []string{plan.LANInterface, plan.WANInterface} {
		commands = append(commands,
			// Class 1:1 is the parent everything borrows from. Unclassified
			// traffic goes to 1:2 and is not capped — a device nobody has
			// limited must not be slowed down by the existence of the
			// machinery.
			fmt.Sprintf("qdisc add dev %s root handle 1: htb default 2", iface),
			fmt.Sprintf("class add dev %s parent 1: classid 1:1 htb rate %dkbit", iface, ceilKbps),
			fmt.Sprintf("class add dev %s parent 1:1 classid 1:2 htb rate %dkbit ceil %dkbit", iface, ceilKbps, ceilKbps),
		)
	}

	// Class ids start after the two reserved ones.
	next := 10
	for _, limit := range limits {
		if limit.DownloadKbps > 0 {
			commands = append(commands, classFor(plan.LANInterface, next, limit.DownloadKbps, "dst", limit.Address)...)
		}
		if limit.UploadKbps > 0 {
			commands = append(commands, classFor(plan.WANInterface, next, limit.UploadKbps, "src", limit.Address)...)
		}

		next++
	}

	return commands, nil
}

// classFor builds one device's class and the filter that steers its packets
// into it.
func classFor(iface string, id, kbps int, match string, addr netip.Addr) []string {
	return []string{
		// ceil equal to rate: a hard cap rather than a share. Someone who
		// types 10 Mbit means 10, not "10 unless the line is quiet".
		fmt.Sprintf("class add dev %s parent 1:1 classid 1:%d htb rate %dkbit ceil %dkbit", iface, id, kbps, kbps),

		// fq_codel under the cap keeps one bulk transfer from making the
		// device's own interactive traffic unusable within its allowance.
		fmt.Sprintf("qdisc add dev %s parent 1:%d handle %d: fq_codel", iface, id, id),

		fmt.Sprintf("filter add dev %s protocol ip parent 1: prio 1 u32 match ip %s %s/32 flowid 1:%d",
			iface, match, addr.String(), id),
	}
}

// Runner applies rendered commands.
type Runner interface {
	Available() bool
	Run(ctx context.Context, args []string) error
}

type tcRunner struct{}

func (tcRunner) Available() bool {
	_, err := exec.LookPath("tc")

	return err == nil
}

func (tcRunner) Run(ctx context.Context, args []string) error {
	out, err := exec.CommandContext(ctx, "tc", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tc %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}

	return nil
}

// Shaper applies plans to the kernel.
type Shaper struct {
	runner Runner
}

// New creates a shaper backed by tc.
func New() *Shaper { return &Shaper{runner: tcRunner{}} }

// WithRunner swaps the runner, so the rules can be exercised without a kernel.
func (s *Shaper) WithRunner(r Runner) *Shaper {
	s.runner = r

	return s
}

// Available reports whether limits can be applied at all.
func (s *Shaper) Available() bool { return s.runner.Available() }

// ErrUnavailable means the tooling is missing.
var ErrUnavailable = errors.New("tc is not available, so limits cannot be applied")

// Apply installs a plan.
//
// The two deletions at the front are expected to fail on a machine with no
// rules yet, and their failure is ignored — everything after them is not.
func (s *Shaper) Apply(ctx context.Context, plan Plan) error {
	if !s.runner.Available() {
		return ErrUnavailable
	}

	commands, err := Render(plan)
	if err != nil {
		return err
	}

	for i, command := range commands {
		args := strings.Fields(command)

		if runErr := s.runner.Run(ctx, args); runErr != nil {
			// The leading deletions clear whatever was there before, and
			// there is usually nothing.
			if i < 2 && strings.HasPrefix(command, "qdisc del") {
				continue
			}

			return runErr
		}
	}

	return nil
}

// Clear removes every limit.
func (s *Shaper) Clear(ctx context.Context, plan Plan) error {
	if !s.runner.Available() {
		return ErrUnavailable
	}

	for _, iface := range []string{plan.LANInterface, plan.WANInterface} {
		if iface == "" {
			continue
		}

		// Failure here means there was nothing to remove.
		_ = s.runner.Run(ctx, strings.Fields("qdisc del dev "+iface+" root"))
	}

	return nil
}
