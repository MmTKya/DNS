package intel

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/MmTKya/DNS/internal/feeds"
	"github.com/MmTKya/DNS/internal/store"
)

// White-box tests for the queue's decision logic. They live in package intel,
// not intel_test, because driving check() without a real network requires
// swapping the Enricher's unexported tlsCheck/ageCheck fields and injecting a
// stub Source — none of which a black-box test can reach.

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func openQueueTestDB(t *testing.T) *store.DB {
	t.Helper()

	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "seddns.db"))
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	return db
}

// stubSource always answers with the same finding, standing in for a real
// threat source so a test can drive a specific score without a network call.
type stubSource struct{ finding *Finding }

func (s stubSource) Name() string     { return "stub" }
func (s stubSource) Configured() bool { return true }
func (s stubSource) Lookup(_ context.Context, _ string) (*Finding, error) {
	return s.finding, nil
}

// testEnricher builds an Enricher whose single source reports the given
// finding, and whose TLS/age signals are fixed rather than fetched over the
// network.
func testEnricher(db *store.DB, finding *Finding, validTLS bool, ageDays *int) *Enricher {
	e := New(db, discardLogger())
	e.sources = []Source{stubSource{finding: finding}}
	e.tlsCheck = func(_ context.Context, _ string) (bool, string) {
		if validTLS {
			return true, ""
		}

		return false, TLSNoResponse
	}
	e.ageCheck = func(_ context.Context, _ *store.DB, _ string) *int { return ageDays }

	return e
}

func maliciousFinding() *Finding {
	return &Finding{Source: "stub", Malicious: true, Score: 90, Category: "malware", Detail: "test finding"}
}

func TestDefenseModeBlocksAndWritesAUserRule(t *testing.T) {
	t.Parallel()

	db := openQueueTestDB(t)
	ctx := t.Context()

	enricher := testEnricher(db, maliciousFinding(), false, nil)
	queue := NewQueue(db, enricher, discardLogger())
	queue.SetMode(ModeDefense)

	cand := &candidate{firstSeen: time.Now(), count: 1, clients: map[string]struct{}{}}
	if err := queue.check(ctx, "bad-actor.example", cand); err != nil {
		t.Fatalf("check: %v", err)
	}

	suggestions, err := ListSuggestions(ctx, db, StatusBlocked, 10)
	if err != nil {
		t.Fatalf("ListSuggestions: %v", err)
	}
	if len(suggestions) != 1 {
		t.Fatalf("got %d blocked suggestions, want 1", len(suggestions))
	}

	// The regression test for the bug this feature fixed: a "blocked" status
	// in the database that never became a real filter rule protected no one.
	rules, err := feeds.ListUserRules(ctx, db)
	if err != nil {
		t.Fatalf("ListUserRules: %v", err)
	}
	if len(rules) != 1 || rules[0].Rule != "||bad-actor.example^" {
		t.Fatalf("user rules = %+v, want one rule blocking bad-actor.example", rules)
	}
}

func TestTransparentModeNeverSetsStatusBlocked(t *testing.T) {
	t.Parallel()

	db := openQueueTestDB(t)
	ctx := t.Context()

	enricher := testEnricher(db, maliciousFinding(), false, nil)
	queue := NewQueue(db, enricher, discardLogger())
	queue.SetMode(ModeTransparent)

	cand := &candidate{firstSeen: time.Now(), count: 1, clients: map[string]struct{}{}}
	if err := queue.check(ctx, "bad-actor.example", cand); err != nil {
		t.Fatalf("check: %v", err)
	}

	pending, err := ListSuggestions(ctx, db, StatusPending, 10)
	if err != nil {
		t.Fatalf("ListSuggestions: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("got %d pending suggestions, want 1 — transparent mode still watches and logs", len(pending))
	}

	rules, err := feeds.ListUserRules(ctx, db)
	if err != nil {
		t.Fatalf("ListUserRules: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("transparent mode wrote %d user rules, want 0", len(rules))
	}
}

func TestDefenseModeNeverAutoBlocksAValidCertDomain(t *testing.T) {
	t.Parallel()

	db := openQueueTestDB(t)
	ctx := t.Context()

	// A malicious-scoring finding, but a valid, unknown-age certificate — the
	// single most important guarantee this feature makes.
	enricher := testEnricher(db, maliciousFinding(), true, nil)
	queue := NewQueue(db, enricher, discardLogger())
	queue.SetMode(ModeDefense)

	cand := &candidate{firstSeen: time.Now(), count: 1, clients: map[string]struct{}{}}
	if err := queue.check(ctx, "actually-fine.example", cand); err != nil {
		t.Fatalf("check: %v", err)
	}

	blocked, err := ListSuggestions(ctx, db, StatusBlocked, 10)
	if err != nil {
		t.Fatalf("ListSuggestions: %v", err)
	}
	if len(blocked) != 0 {
		t.Fatalf("a domain with a valid certificate was auto-blocked: %+v", blocked)
	}

	rules, err := feeds.ListUserRules(ctx, db)
	if err != nil {
		t.Fatalf("ListUserRules: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("a domain with a valid certificate got a block rule: %+v", rules)
	}
}

func TestANewlyRegisteredUncertifiedDomainSurfacesWithoutAThreatFinding(t *testing.T) {
	t.Parallel()

	db := openQueueTestDB(t)
	ctx := t.Context()

	// No threat source has anything to say — this exercises the operator's
	// explicit ask: a warning on the combination alone, not on a score.
	enricher := testEnricher(db, nil, false, ptr(3))
	queue := NewQueue(db, enricher, discardLogger())
	queue.SetMode(ModeTransparent)

	cand := &candidate{firstSeen: time.Now(), count: 1, clients: map[string]struct{}{}}
	if err := queue.check(ctx, "brand-new-no-findings.example", cand); err != nil {
		t.Fatalf("check: %v", err)
	}

	pending, err := ListSuggestions(ctx, db, StatusPending, 10)
	if err != nil {
		t.Fatalf("ListSuggestions: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("got %d pending suggestions, want 1 for a high-risk domain with no findings", len(pending))
	}
}

func TestAnOwnedDomainNeverEntersTheQueue(t *testing.T) {
	t.Parallel()

	db := openQueueTestDB(t)
	queue := NewQueue(db, testEnricher(db, nil, false, nil), discardLogger())
	queue.SetOwned([]string{"mine.example"})

	queue.Consider("mine.example", "192.168.1.5")
	queue.Consider("sub.mine.example", "192.168.1.5")
	queue.Consider("not-mine.example", "192.168.1.5")

	if got := queue.PendingLen(); got != 1 {
		t.Errorf("pending = %d, want 1 — only the non-owned domain should queue", got)
	}
}
