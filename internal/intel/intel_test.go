package intel_test

import (
	"io"
	"log/slog"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/MmTKya/DNS/internal/intel"
	"github.com/MmTKya/DNS/internal/store"
)

func openDB(t *testing.T) *store.DB {
	t.Helper()

	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "aegisdns.db"))
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	return db
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestUnconfiguredSourcesAreSkipped(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	enricher := intel.New(db, discard())

	if err := enricher.Configure(t.Context()); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	// With no keys stored, the remote sources must report themselves as
	// unconfigured rather than failing every lookup.
	var unconfigured int
	for _, s := range enricher.Sources() {
		if !s.Configured {
			unconfigured++
		}
	}
	if unconfigured == 0 {
		t.Error("expected some sources to need an API key")
	}

	assessment, err := enricher.Assess(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if assessment.Verdict != intel.VerdictClean {
		t.Errorf("verdict = %q, want %q with nothing configured", assessment.Verdict, intel.VerdictClean)
	}
}

func TestVerdictIsCached(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	enricher := intel.New(db, discard())
	ctx := t.Context()

	first, err := enricher.Assess(ctx, "cached.example")
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if first.Cached {
		t.Error("the first assessment cannot be cached")
	}

	second, err := enricher.Assess(ctx, "cached.example")
	if err != nil {
		t.Fatalf("second Assess: %v", err)
	}

	// Every source here is rate-limited, so asking twice about the same name
	// has to come out of the cache.
	if !second.Cached {
		t.Error("the second assessment should have come from the cache")
	}
	if second.Score != first.Score {
		t.Errorf("cached score = %d, want %d", second.Score, first.Score)
	}
}

func TestSuggestionLifecycle(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	ctx := t.Context()

	// Insert a suggestion the way the queue does, then walk it through a
	// decision.
	if _, err := db.Writer().ExecContext(ctx, `
		INSERT INTO intel_suggestions (domain, score, reason, findings, clients, query_count, first_seen, last_seen, status)
		VALUES ('bad.example', 85, 'usom-sgb: listed as phishing', '[]', '192.168.1.5', 3, ?, ?, 'pending')
	`, time.Now().Unix(), time.Now().Unix()); err != nil {
		t.Fatalf("inserting suggestion: %v", err)
	}

	pending, err := intel.ListSuggestions(ctx, db, intel.StatusPending, 10)
	if err != nil {
		t.Fatalf("ListSuggestions: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("got %d pending suggestions, want 1", len(pending))
	}
	if pending[0].Score != 85 || len(pending[0].Clients) != 1 {
		t.Errorf("suggestion = %+v, want the score and the client that asked", pending[0])
	}

	count, err := intel.PendingCount(ctx, db)
	if err != nil || count != 1 {
		t.Errorf("PendingCount = %d, %v; want 1, nil", count, err)
	}

	found, err := intel.Decide(ctx, db, "bad.example", intel.StatusBlocked)
	if err != nil || !found {
		t.Fatalf("Decide: found=%t err=%v", found, err)
	}

	// A decided name must not come back: being asked the same question twice
	// is how a person learns to ignore the question.
	if pending, err = intel.ListSuggestions(ctx, db, intel.StatusPending, 10); err != nil {
		t.Fatalf("ListSuggestions: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("got %d pending suggestions after deciding, want 0", len(pending))
	}
}

func TestDecideRejectsUnknownStatus(t *testing.T) {
	t.Parallel()

	db := openDB(t)

	if _, err := intel.Decide(t.Context(), db, "x.example", "maybe"); err == nil {
		t.Error("an unknown decision should be rejected")
	}
}

func TestQueueSkipsUninterestingNames(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	queue := intel.NewQueue(db, intel.New(db, discard()), discard())

	// Reverse-DNS and local names would burn a rate-limited quota to learn
	// nothing at all.
	for _, name := range []string{
		"1.0.168.192.in-addr.arpa",
		"printer.local",
		"nas.lan",
		"bare-label",
		"",
	} {
		queue.Consider(name, "192.168.1.5")
	}

	if got := queue.PendingLen(); got != 0 {
		t.Errorf("%d names queued, want 0", got)
	}

	queue.Consider("real-site.example", "192.168.1.5")
	if got := queue.PendingLen(); got != 1 {
		t.Errorf("%d names queued, want 1", got)
	}
}

func TestQueueIsBounded(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	queue := intel.NewQueue(db, intel.New(db, discard()), discard())

	// Whatever the network resolves must not become unbounded memory here.
	for i := range 10_000 {
		queue.Consider(randomName(i), "192.168.1.5")
	}

	if got := queue.PendingLen(); got > 2_000 {
		t.Errorf("queue grew to %d entries; it must stay bounded", got)
	}
}

func randomName(i int) string {
	return "host" + strconv.Itoa(i) + ".example"
}
