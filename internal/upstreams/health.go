package upstreams

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// probeInterval is how often each upstream is timed.
//
// Half a minute is often enough that a resolver going bad shows up while
// someone is still looking at the page, and rare enough that the probes are a
// rounding error next to a household's own traffic.
const probeInterval = 30 * time.Second

// probeName is what the health check asks for.
//
// A name that is always delegated and always answered, so a slow reply means a
// slow resolver rather than a slow authoritative server having a bad day.
const probeName = "www.google.com."

// Health is one upstream's current state.
type Health struct {
	CheckedAt time.Time `json:"checked_at,omitzero"`
	Address   string    `json:"address"`
	Role      string    `json:"role"`
	Error     string    `json:"error,omitempty"`
	LatencyMS int       `json:"latency_ms"`
	Healthy   bool      `json:"healthy"`
}

// Monitor keeps the current latency of the resolvers in use.
//
// It exists for the moment something is wrong: the first question anyone asks
// is "is it me or is it the internet", and the honest answer is on this
// screen rather than in a terminal.
type Monitor struct {
	client  *dns.Client
	current func() (primary, fallback []string)

	mu      sync.RWMutex
	results []Health
	rescues uint64
}

// NewMonitor builds a monitor over whatever the node is currently using.
//
// The addresses arrive through a function rather than a slice because they
// change: someone adopting a measurement swaps them underneath a running node,
// and a monitor still timing the old ones would be worse than none.
func NewMonitor(current func() (primary, fallback []string)) *Monitor {
	return &Monitor{
		client:  &dns.Client{Timeout: 3 * time.Second},
		current: current,
	}
}

// RecordRescue counts a lookup that only succeeded on the second resolver.
//
// The most diagnostic number here. A rescue now and then is one name with a
// broken delegation; a rescue on a large share of queries means the resolver
// in front is failing and nobody would otherwise notice, because the answers
// still arrive.
func (m *Monitor) RecordRescue() {
	m.mu.Lock()
	m.rescues++
	m.mu.Unlock()
}

// Snapshot returns the latest results.
func (m *Monitor) Snapshot() (results []Health, rescues uint64) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return append([]Health(nil), m.results...), m.rescues
}

// Run probes until the context is cancelled.
func (m *Monitor) Run(ctx context.Context) {
	m.probe(ctx)

	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.probe(ctx)
		}
	}
}

func (m *Monitor) probe(ctx context.Context) {
	primary, fallback := m.current()

	type job struct {
		address string
		role    string
	}

	jobs := make([]job, 0, len(primary)+len(fallback))
	for _, address := range primary {
		jobs = append(jobs, job{address: address, role: RolePrimary})
	}
	for _, address := range fallback {
		jobs = append(jobs, job{address: address, role: RoleFallback})
	}

	results := make([]Health, len(jobs))
	var wg sync.WaitGroup

	for i, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = m.time(ctx, j.address, j.role)
		}()
	}
	wg.Wait()

	m.mu.Lock()
	m.results = results
	m.mu.Unlock()
}

func (m *Monitor) time(ctx context.Context, address, role string) Health {
	result := Health{Address: address, Role: role, CheckedAt: time.Now()}

	if !isPlain(address) {
		// An encrypted upstream needs the proxy's own client to speak to it.
		// Reporting nothing is better than reporting a failure that is only
		// this probe's inability to ask.
		result.Healthy = true
		result.Error = "not measured from here"

		return result
	}

	server := address
	if _, _, err := splitHostPort(server); err != nil {
		server += ":53"
	}

	msg := new(dns.Msg)
	msg.SetQuestion(probeName, dns.TypeA)
	msg.RecursionDesired = true

	reply, rtt, err := m.client.ExchangeContext(ctx, msg, server)
	if err != nil {
		result.Error = err.Error()

		return result
	}

	result.LatencyMS = int(rtt.Milliseconds())

	// Answering is not the same as working: SERVFAIL is a reply, and it is
	// the failure that made this whole area worth building.
	if reply.Rcode != dns.RcodeSuccess {
		result.Error = dns.RcodeToString[reply.Rcode]

		return result
	}

	result.Healthy = true

	return result
}
