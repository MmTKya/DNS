package traffic

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// Counter accounting is the one thing a DNS-only node genuinely cannot do, and
// the reason gateway mode exists.
//
// nftables counters are used rather than eBPF: they are in every kernel worth
// deploying on, they need no compiler or BTF on the target, and reading them is
// one command. eBPF would give per-flow detail, which is a phase of its own;
// per-client byte totals are what the panel actually shows.

// counterTable is separate from the enforcement table so that flushing one
// never disturbs the other.
const (
	counterTable = "aegisdns_acct"
	counterChain = "accounting"
)

// Sample is one client's byte counters at a point in time.
type Sample struct {
	At        time.Time  `json:"at"`
	Addr      netip.Addr `json:"addr"`
	RxBytes   uint64     `json:"rx_bytes"`
	TxBytes   uint64     `json:"tx_bytes"`
	RxPackets uint64     `json:"rx_packets"`
	TxPackets uint64     `json:"tx_packets"`
}

// Rate is the throughput between two samples.
type Rate struct {
	Addr          netip.Addr `json:"addr"`
	RxBytesPerSec float64    `json:"rx_bytes_per_sec"`
	TxBytesPerSec float64    `json:"tx_bytes_per_sec"`
	RxBytesTotal  uint64     `json:"rx_bytes_total"`
	TxBytesTotal  uint64     `json:"tx_bytes_total"`
	// Measured is always true here, in contrast to the inferred figures in
	// dwell.go. The panel shows the two side by side and must not confuse them.
	Measured bool `json:"measured"`
}

// RenderCounters produces the nftables ruleset that counts traffic per client.
//
// One counter per direction per address: the rules match and count without
// deciding anything, so this can be installed alongside whatever else manages
// the firewall.
func RenderCounters(addrs []netip.Addr) string {
	var b strings.Builder

	b.WriteString("table inet " + counterTable + "\n")
	b.WriteString("delete table inet " + counterTable + "\n")
	b.WriteString("table inet " + counterTable + " {\n")
	b.WriteString("\tchain " + counterChain + " {\n")
	// A high priority number and an accept policy: this chain observes, it
	// never decides. Getting that wrong would take the network down.
	b.WriteString("\t\ttype filter hook forward priority 0; policy accept;\n")

	// Sorted so the ruleset is stable and diffable between runs.
	sorted := make([]netip.Addr, 0, len(addrs))
	sorted = append(sorted, addrs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Less(sorted[j]) })

	for _, addr := range sorted {
		if !addr.IsValid() {
			continue
		}

		family := "ip"
		if addr.Is6() && !addr.Is4In6() {
			family = "ip6"
		}
		value := addr.Unmap().String()

		// "tx" is what the client sent, "rx" what it received, named from the
		// device's point of view because that is how the panel reads.
		b.WriteString(fmt.Sprintf("\t\t%s saddr %s counter comment \"tx %s\"\n", family, value, value))
		b.WriteString(fmt.Sprintf("\t\t%s daddr %s counter comment \"rx %s\"\n", family, value, value))
	}

	b.WriteString("\t}\n")
	b.WriteString("}\n")

	return b.String()
}

// nftJSON is the subset of `nft -j list ruleset` this needs.
type nftJSON struct {
	Nftables []struct {
		Rule *struct {
			Table   string            `json:"table"`
			Chain   string            `json:"chain"`
			Comment string            `json:"comment"`
			Expr    []json.RawMessage `json:"expr"`
		} `json:"rule,omitempty"`
	} `json:"nftables"`
}

type counterExpr struct {
	Counter *struct {
		Packets uint64 `json:"packets"`
		Bytes   uint64 `json:"bytes"`
	} `json:"counter"`
}

// ParseCounters reads `nft -j list table inet aegisdns_acct` output into
// samples.
//
// The comment carries the direction and the address, because matching on the
// expression tree would couple this to nftables' JSON shape far more tightly
// than reading back a string this package wrote itself.
func ParseCounters(data []byte, at time.Time) (samples map[netip.Addr]Sample, err error) {
	var parsed nftJSON
	if err = json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("decoding nftables output: %w", err)
	}

	samples = map[netip.Addr]Sample{}

	for _, item := range parsed.Nftables {
		if item.Rule == nil || item.Rule.Table != counterTable {
			continue
		}

		direction, rawAddr, found := strings.Cut(item.Rule.Comment, " ")
		if !found {
			continue
		}

		addr, parseErr := netip.ParseAddr(rawAddr)
		if parseErr != nil {
			continue
		}

		var packets, bytes uint64
		for _, raw := range item.Rule.Expr {
			var expr counterExpr
			if json.Unmarshal(raw, &expr) != nil || expr.Counter == nil {
				continue
			}
			packets, bytes = expr.Counter.Packets, expr.Counter.Bytes
		}

		sample := samples[addr]
		sample.Addr = addr
		sample.At = at

		switch direction {
		case "tx":
			sample.TxBytes, sample.TxPackets = bytes, packets
		case "rx":
			sample.RxBytes, sample.RxPackets = bytes, packets
		default:
			continue
		}

		samples[addr] = sample
	}

	return samples, nil
}

// Accountant reads the counters and turns them into rates.
type Accountant struct {
	runner CounterRunner

	mu       sync.Mutex
	previous map[netip.Addr]Sample
}

// CounterRunner reads the raw counter output.  It is an interface so the
// parsing and rate arithmetic can be tested without root or a kernel.
type CounterRunner interface {
	Available() bool
	Install(ctx context.Context, ruleset string) error
	Read(ctx context.Context) ([]byte, error)
}

type nftCounterRunner struct{}

// Available implements CounterRunner.
func (nftCounterRunner) Available() bool {
	_, err := exec.LookPath("nft")

	return err == nil
}

// Install implements CounterRunner.
func (nftCounterRunner) Install(ctx context.Context, ruleset string) error {
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %w: %s", err, strings.TrimSpace(string(output)))
	}

	return nil
}

// Read implements CounterRunner.
func (nftCounterRunner) Read(ctx context.Context) ([]byte, error) {
	output, err := exec.CommandContext(ctx, "nft", "-j", "list", "table", "inet", counterTable).Output()
	if err != nil {
		return nil, fmt.Errorf("reading counters: %w", err)
	}

	return output, nil
}

// NewAccountant creates an accountant backed by nftables.
func NewAccountant() *Accountant {
	return &Accountant{runner: nftCounterRunner{}, previous: map[netip.Addr]Sample{}}
}

// WithRunner replaces the counter backend.  Tests use it.
func (a *Accountant) WithRunner(r CounterRunner) *Accountant {
	a.runner = r

	return a
}

// Available reports whether counting is possible here.
func (a *Accountant) Available() bool { return a.runner.Available() }

// Track installs counters for the given clients.
func (a *Accountant) Track(ctx context.Context, addrs []netip.Addr) error {
	if !a.runner.Available() {
		return fmt.Errorf("nftables is not available")
	}

	return a.runner.Install(ctx, RenderCounters(addrs))
}

// Rates reads the counters and returns throughput since the previous read.
//
// The first call after start has nothing to compare against and returns totals
// with a zero rate, rather than inventing one from an assumed interval.
func (a *Accountant) Rates(ctx context.Context) (rates []Rate, err error) {
	data, err := a.runner.Read(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	samples, err := ParseCounters(data, now)
	if err != nil {
		return nil, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	for addr, sample := range samples {
		rate := Rate{
			Addr:         addr,
			RxBytesTotal: sample.RxBytes,
			TxBytesTotal: sample.TxBytes,
			Measured:     true,
		}

		if prev, ok := a.previous[addr]; ok {
			seconds := sample.At.Sub(prev.At).Seconds()
			// Counters reset when the ruleset is reinstalled, so a decrease
			// means "start again", not "negative throughput".
			if seconds > 0 && sample.RxBytes >= prev.RxBytes && sample.TxBytes >= prev.TxBytes {
				rate.RxBytesPerSec = float64(sample.RxBytes-prev.RxBytes) / seconds
				rate.TxBytesPerSec = float64(sample.TxBytes-prev.TxBytes) / seconds
			}
		}

		rates = append(rates, rate)
		a.previous[addr] = sample
	}

	sort.Slice(rates, func(i, j int) bool {
		return rates[i].RxBytesPerSec+rates[i].TxBytesPerSec >
			rates[j].RxBytesPerSec+rates[j].TxBytesPerSec
	})

	return rates, nil
}
