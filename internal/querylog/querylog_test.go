package querylog_test

import (
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/MmTKya/DNS/internal/config"
	"github.com/MmTKya/DNS/internal/policy"
	"github.com/MmTKya/DNS/internal/querylog"
	"github.com/MmTKya/DNS/internal/store"
	"github.com/miekg/dns"
)

func newLog(t *testing.T, mutate func(*config.Config)) (*querylog.Log, *store.DB) {
	t.Helper()

	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "aegisdns.db"))
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := config.Default()
	cfg.QueryLog.RingSize = 100
	if mutate != nil {
		mutate(cfg)
	}

	return querylog.New(db, cfg, slog.New(slog.NewTextHandler(io.Discard, nil))), db
}

func event(host, verdict string, client string) policy.Event {
	return policy.Event{
		Time:    time.Now(),
		Client:  netip.MustParseAddr(client),
		Host:    host,
		QType:   dns.TypeA,
		Verdict: verdict,
		Elapsed: 5 * time.Millisecond,
	}
}

func TestRecentReturnsNewestFirst(t *testing.T) {
	t.Parallel()

	log, _ := newLog(t, nil)

	for _, host := range []string{"first.example", "second.example", "third.example"} {
		log.Observe(event(host, policy.VerdictAllowed, "192.168.1.10"))
	}

	recent := log.Recent(10)
	if len(recent) != 3 {
		t.Fatalf("got %d entries, want 3", len(recent))
	}
	if recent[0].Host != "third.example" {
		t.Errorf("newest entry = %q, want %q", recent[0].Host, "third.example")
	}
	if recent[2].Host != "first.example" {
		t.Errorf("oldest entry = %q, want %q", recent[2].Host, "first.example")
	}
}

func TestRingBufferWrapsWithoutGrowing(t *testing.T) {
	t.Parallel()

	log, _ := newLog(t, func(c *config.Config) { c.QueryLog.RingSize = 10 })

	for i := range 100 {
		log.Observe(event("host.example", policy.VerdictAllowed, "192.168.1.10"))
		_ = i
	}

	// The ring is the memory budget for the live dashboard: it must hold its
	// size no matter how long the node runs.
	recent := log.Recent(1000)
	if len(recent) != 10 {
		t.Errorf("ring holds %d entries, want 10", len(recent))
	}

	// Counters keep counting past the ring's capacity.
	if stats := log.Stats(); stats.Total != 100 {
		t.Errorf("total = %d, want 100", stats.Total)
	}
}

func TestStats(t *testing.T) {
	t.Parallel()

	log, _ := newLog(t, nil)

	for range 3 {
		log.Observe(event("ads.example", policy.VerdictBlocked, "192.168.1.10"))
	}
	log.Observe(event("ok.example", policy.VerdictAllowed, "192.168.1.11"))

	cachedEvent := event("cached.example", policy.VerdictAllowed, "192.168.1.11")
	cachedEvent.Cached = true
	log.Observe(cachedEvent)

	stats := log.Stats()
	if stats.Total != 5 {
		t.Errorf("total = %d, want 5", stats.Total)
	}
	if stats.Blocked != 3 {
		t.Errorf("blocked = %d, want 3", stats.Blocked)
	}
	if stats.Cached != 1 {
		t.Errorf("cached = %d, want 1", stats.Cached)
	}
	if got := stats.BlockedRatio; got < 0.59 || got > 0.61 {
		t.Errorf("blocked ratio = %.2f, want ~0.60", got)
	}
	if stats.AvgElapsedMS < 4.9 || stats.AvgElapsedMS > 5.1 {
		t.Errorf("average elapsed = %.2f ms, want ~5", stats.AvgElapsedMS)
	}
}

func TestAnonymizedModeTruncatesClients(t *testing.T) {
	t.Parallel()

	log, _ := newLog(t, func(c *config.Config) { c.QueryLog.Mode = config.QueryLogAnonymized })

	e := event("example.com", policy.VerdictAllowed, "192.168.1.77")
	e.ClientID = "kids-tablet"
	log.Observe(e)

	entry := log.Recent(1)[0]

	// The point of the mode is that statistics survive while attribution to
	// one device does not.
	if entry.Client != "192.168.1.0/24" {
		t.Errorf("client = %q, want a truncated prefix", entry.Client)
	}
	if entry.ClientID != "" {
		t.Errorf("client id = %q, want it dropped in anonymized mode", entry.ClientID)
	}
}

func TestRAMModeNeverWritesToDisk(t *testing.T) {
	t.Parallel()

	log, db := newLog(t, func(c *config.Config) { c.QueryLog.Mode = config.QueryLogRAM })

	for range 10 {
		log.Observe(event("example.com", policy.VerdictAllowed, "192.168.1.10"))
	}
	log.Flush(t.Context())

	var rows int
	if err := db.Reader().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM query_log`).Scan(&rows); err != nil {
		t.Fatalf("counting rows: %v", err)
	}

	// This is the SD-card setting: the live dashboard still works, but nothing
	// touches the card.
	if rows != 0 {
		t.Errorf("query_log has %d rows, want 0 in RAM mode", rows)
	}
	if len(log.Recent(10)) != 10 {
		t.Error("the live ring should still be populated in RAM mode")
	}
}

func TestOffModeRecordsNothingButCounts(t *testing.T) {
	t.Parallel()

	log, _ := newLog(t, func(c *config.Config) { c.QueryLog.Mode = config.QueryLogOff })

	log.Observe(event("example.com", policy.VerdictBlocked, "192.168.1.10"))

	if len(log.Recent(10)) != 0 {
		t.Error("off mode must not retain entries")
	}
	// Counters are cheap and are what the dashboard's headline numbers use, so
	// they keep working even with logging off.
	if stats := log.Stats(); stats.Total != 1 || stats.Blocked != 1 {
		t.Errorf("stats = %+v, want the query counted", stats)
	}
}

func TestFlushWritesBatchAndQueryReadsItBack(t *testing.T) {
	t.Parallel()

	log, db := newLog(t, nil)
	ctx := t.Context()

	log.Observe(event("ads.example", policy.VerdictBlocked, "192.168.1.10"))
	log.Observe(event("ok.example", policy.VerdictAllowed, "192.168.1.11"))

	// Nothing is written until the flush: the hot path never touches the disk.
	var before int
	if err := db.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM query_log`).Scan(&before); err != nil {
		t.Fatalf("counting rows: %v", err)
	}
	if before != 0 {
		t.Errorf("query_log has %d rows before the flush, want 0", before)
	}

	log.Flush(ctx)

	entries, err := log.Query(ctx, querylog.Search{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d stored entries, want 2", len(entries))
	}

	blocked, err := log.Query(ctx, querylog.Search{Verdict: policy.VerdictBlocked})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(blocked) != 1 || blocked[0].Host != "ads.example" {
		t.Errorf("verdict filter returned %+v, want just ads.example", blocked)
	}

	byHost, err := log.Query(ctx, querylog.Search{Host: "ok."})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(byHost) != 1 {
		t.Errorf("host filter returned %d entries, want 1", len(byHost))
	}
}

func TestSubscribeReceivesLiveEntries(t *testing.T) {
	t.Parallel()

	log, _ := newLog(t, nil)

	events, cancel := log.Subscribe(4)
	defer cancel()

	log.Observe(event("live.example", policy.VerdictAllowed, "192.168.1.10"))

	select {
	case entry := <-events:
		if entry.Host != "live.example" {
			t.Errorf("host = %q, want %q", entry.Host, "live.example")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no entry arrived on the subscription")
	}
}

func TestSlowSubscriberDoesNotBlockTheHotPath(t *testing.T) {
	t.Parallel()

	log, _ := newLog(t, nil)

	// A subscriber that never reads: a panel tab left open on a laptop that
	// went to sleep. DNS must not slow down for it.
	_, cancel := log.Subscribe(1)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 1000 {
			log.Observe(event("example.com", policy.VerdictAllowed, "192.168.1.10"))
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Observe blocked on a subscriber that stopped reading")
	}
}

func TestCancelledSubscriptionStopsReceiving(t *testing.T) {
	t.Parallel()

	log, _ := newLog(t, nil)

	events, cancel := log.Subscribe(4)
	cancel()

	log.Observe(event("example.com", policy.VerdictAllowed, "192.168.1.10"))

	// The channel is closed, so a receive returns immediately with the zero
	// value rather than an entry.
	select {
	case entry, ok := <-events:
		if ok {
			t.Errorf("received %+v after cancelling", entry)
		}
	case <-time.After(time.Second):
		t.Error("a cancelled subscription should have a closed channel")
	}
}
