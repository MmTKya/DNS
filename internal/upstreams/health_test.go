package upstreams

import (
	"context"
	"testing"
	"time"
)

// The card exists to answer "is it me or is it them", so a resolver that has
// stopped answering has to read as broken rather than as slow.
func TestMonitorSeparatesWorkingFromBroken(t *testing.T) {
	t.Parallel()

	working := fakeResolver(t, 0, map[string]bool{probeName: true})
	// Answers, and answers SERVFAIL: the failure that looks like success to
	// anything that only checks whether a reply came back.
	failing := fakeResolver(t, 0, map[string]bool{})

	monitor := NewMonitor(func() ([]string, []string) {
		return []string{working}, []string{failing}
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	monitor.probe(ctx)

	results, _ := monitor.Snapshot()
	if len(results) != 2 {
		t.Fatalf("Snapshot() returned %d results, want 2", len(results))
	}

	byAddr := map[string]Health{}
	for _, r := range results {
		byAddr[r.Address] = r
	}

	if !byAddr[working].Healthy {
		t.Errorf("a resolver that answered was reported unhealthy: %+v", byAddr[working])
	}
	if byAddr[working].Role != RolePrimary {
		t.Errorf("role = %q, want primary", byAddr[working].Role)
	}

	if byAddr[failing].Healthy {
		t.Error("a resolver answering SERVFAIL was reported healthy")
	}
	if byAddr[failing].Error == "" {
		t.Error("the failing resolver did not say what was wrong")
	}
	if byAddr[failing].Role != RoleFallback {
		t.Errorf("role = %q, want fallback", byAddr[failing].Role)
	}
}

// The resolvers change underneath a running node when someone adopts a
// measurement. A monitor still timing the old ones would mislead at exactly
// the moment it is being read.
func TestMonitorFollowsAChangeOfResolvers(t *testing.T) {
	t.Parallel()

	first := fakeResolver(t, 0, map[string]bool{probeName: true})
	second := fakeResolver(t, 0, map[string]bool{probeName: true})

	current := first
	monitor := NewMonitor(func() ([]string, []string) { return []string{current}, nil })

	monitor.probe(t.Context())
	if results, _ := monitor.Snapshot(); results[0].Address != first {
		t.Fatalf("first probe measured %q, want %q", results[0].Address, first)
	}

	current = second
	monitor.probe(t.Context())

	results, _ := monitor.Snapshot()
	if results[0].Address != second {
		t.Errorf("after the change the monitor measured %q, want %q", results[0].Address, second)
	}
}

// The most diagnostic number on the card: answers still arrive, so nothing
// looks wrong, while the resolver in front is quietly failing.
func TestMonitorCountsRescues(t *testing.T) {
	t.Parallel()

	monitor := NewMonitor(func() ([]string, []string) { return nil, nil })

	for range 3 {
		monitor.RecordRescue()
	}

	if _, rescues := monitor.Snapshot(); rescues != 3 {
		t.Errorf("rescues = %d, want 3", rescues)
	}
}

// An encrypted upstream cannot be timed with a plain query, and reporting it
// as broken would send someone chasing a resolver that is working.
func TestMonitorDoesNotCallEncryptedUpstreamsBroken(t *testing.T) {
	t.Parallel()

	monitor := NewMonitor(func() ([]string, []string) {
		return []string{"tls://dns.quad9.net"}, nil
	})
	monitor.probe(t.Context())

	results, _ := monitor.Snapshot()
	if !results[0].Healthy {
		t.Error("an encrypted upstream was reported as unhealthy")
	}
}
