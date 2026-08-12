// Package enforce carries out "cut this device off".
//
// What that means depends entirely on the deployment mode, and the difference
// is not cosmetic:
//
//   - In gateway mode every packet crosses this node, so a firewall rule is a
//     real kill switch. Keying it on the hardware address survives the device
//     picking up a new lease.
//   - In DNS-only mode the node answers questions and nothing more. Refusing to
//     resolve is content filtering: the device keeps its network access, and
//     anything with a hardcoded address or its own encrypted resolver walks
//     straight around it.
//
// The panel is told which of the two it is getting, and never calls the second
// one a kill switch.
package enforce

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"strings"
	"sync"

	"github.com/MmTKya/DNS/internal/config"
)

// Table and chain names.  A dedicated table keeps AegisDNS' rules apart from
// whatever else manages the firewall, so flushing ours never touches theirs.
const (
	tableName = "aegisdns"
	chainName = "paused"
)

// Runner executes firewall commands.  It exists so the rule generation can be
// tested without root, a kernel or an nftables binary — the part most likely
// to be wrong is the ruleset, not the exec call.
type Runner interface {
	Run(ctx context.Context, stdin string) error
	Available() bool
}

// nftRunner pipes a ruleset into nft.
type nftRunner struct{}

// Available implements Runner.
func (nftRunner) Available() bool {
	_, err := exec.LookPath("nft")

	return err == nil
}

// Run implements Runner.
func (nftRunner) Run(ctx context.Context, stdin string) error {
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(stdin)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %w: %s", err, strings.TrimSpace(string(output)))
	}

	return nil
}

// Target is a device to cut off.
type Target struct {
	// Addr is its current address.
	Addr netip.Addr

	// MAC is its hardware address, when known.  Preferred over the address:
	// a device that renews its lease onto a different address would otherwise
	// escape the block by doing nothing at all.
	MAC string
}

// Enforcer applies the paused set to the firewall.
type Enforcer struct {
	runner Runner
	logger *slog.Logger

	mu      sync.Mutex
	mode    config.DeploymentMode
	applied string
}

// New creates an enforcer for the given mode.
func New(mode config.DeploymentMode, logger *slog.Logger) *Enforcer {
	if logger == nil {
		logger = slog.Default()
	}

	return &Enforcer{
		runner: nftRunner{},
		mode:   mode,
		logger: logger.With("component", "enforce"),
	}
}

// WithRunner replaces the command runner.  Tests use it.
func (e *Enforcer) WithRunner(r Runner) *Enforcer {
	e.runner = r

	return e
}

// Capability describes what this deployment can actually do about a paused
// device, in the words the panel shows.
type Capability struct {
	Mode        config.DeploymentMode `json:"mode"`
	Enforced    bool                  `json:"enforced"`
	Available   bool                  `json:"available"`
	Explanation string                `json:"explanation"`
}

// Capability reports what pausing means here.
func (e *Enforcer) Capability() Capability {
	e.mu.Lock()
	mode := e.mode
	e.mu.Unlock()

	if mode != config.ModeGateway {
		return Capability{
			Mode:      mode,
			Enforced:  false,
			Available: true,
			Explanation: "Pausing a device stops this node resolving names for it. " +
				"The device keeps its network access, and anything with hardcoded addresses " +
				"or its own encrypted DNS will get around it.",
		}
	}

	if !e.runner.Available() {
		return Capability{
			Mode:      mode,
			Enforced:  false,
			Available: false,
			Explanation: "Gateway mode is configured, but nftables is not available on this system, " +
				"so pausing falls back to refusing DNS.",
		}
	}

	return Capability{
		Mode:      mode,
		Enforced:  true,
		Available: true,
		Explanation: "Pausing a device drops its traffic at the forwarding layer. " +
			"This is a real cut-off, not a DNS refusal.",
	}
}

// ErrNotEnforceable means the current deployment cannot enforce a block at the
// network layer.  Callers fall back to refusing DNS, and say so.
var ErrNotEnforceable = errors.New("blocking is not enforceable in this deployment mode")

// Apply installs the ruleset for the given targets, replacing whatever was
// there before.
//
// The whole set is rewritten rather than patched: reconciling to a desired
// state cannot drift, while adding and removing individual rules eventually
// leaves a device blocked that the panel says is not.
func (e *Enforcer) Apply(ctx context.Context, targets []Target) error {
	e.mu.Lock()
	mode := e.mode
	e.mu.Unlock()

	if mode != config.ModeGateway {
		return ErrNotEnforceable
	}
	if !e.runner.Available() {
		return fmt.Errorf("%w: nftables is not available", ErrNotEnforceable)
	}

	ruleset := Render(targets)

	e.mu.Lock()
	unchanged := ruleset == e.applied
	e.mu.Unlock()

	if unchanged {
		return nil
	}

	if err := e.runner.Run(ctx, ruleset); err != nil {
		return fmt.Errorf("applying firewall rules: %w", err)
	}

	e.mu.Lock()
	e.applied = ruleset
	e.mu.Unlock()

	e.logger.InfoContext(ctx, "firewall rules applied", "paused_devices", len(targets))

	return nil
}

// SetMode updates the deployment mode after a reload.
func (e *Enforcer) SetMode(mode config.DeploymentMode) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.mode = mode
	// The applied ruleset is no longer known to match reality.
	e.applied = ""
}

// Render produces the nftables ruleset for a set of paused devices.
//
// It is a pure function so the rules can be inspected, diffed and tested
// without touching a kernel.
func Render(targets []Target) string {
	var b strings.Builder

	// Deleting and recreating the table makes this idempotent: whatever was
	// there before is gone, and only what is listed here survives. The delete
	// is tolerated failing on the first run, when the table does not exist.
	b.WriteString("table inet " + tableName + "\n")
	b.WriteString("delete table inet " + tableName + "\n")
	b.WriteString("table inet " + tableName + " {\n")
	b.WriteString("\tchain " + chainName + " {\n")
	b.WriteString("\t\ttype filter hook forward priority -10; policy accept;\n")

	for _, t := range targets {
		// The hardware address is checked first and on its own: it keeps
		// working when the device renews its lease onto a new address.
		if mac := normaliseMAC(t.MAC); mac != "" {
			b.WriteString("\t\tether saddr " + mac + " drop\n")
			b.WriteString("\t\tether daddr " + mac + " drop\n")

			continue
		}

		if t.Addr.IsValid() {
			family := "ip"
			if t.Addr.Is6() && !t.Addr.Is4In6() {
				family = "ip6"
			}
			addr := t.Addr.Unmap().String()

			b.WriteString("\t\t" + family + " saddr " + addr + " drop\n")
			b.WriteString("\t\t" + family + " daddr " + addr + " drop\n")
		}
	}

	b.WriteString("\t}\n")
	b.WriteString("}\n")

	return b.String()
}

// normaliseMAC lowercases and validates a hardware address.  Anything that is
// not one is dropped rather than pasted into a ruleset.
func normaliseMAC(mac string) string {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if mac == "" {
		return ""
	}

	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		return ""
	}

	for _, p := range parts {
		if len(p) != 2 {
			return ""
		}
		for _, r := range p {
			if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
				return ""
			}
		}
	}

	return mac
}

// Clear removes every rule this package installed.
func (e *Enforcer) Clear(ctx context.Context) error {
	e.mu.Lock()
	mode := e.mode
	e.mu.Unlock()

	if mode != config.ModeGateway || !e.runner.Available() {
		return nil
	}

	ruleset := "table inet " + tableName + "\ndelete table inet " + tableName + "\n"
	if err := e.runner.Run(ctx, ruleset); err != nil {
		return fmt.Errorf("clearing firewall rules: %w", err)
	}

	e.mu.Lock()
	e.applied = ""
	e.mu.Unlock()

	return nil
}
