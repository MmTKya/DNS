package events_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/MmTKya/DNS/internal/events"
	"github.com/MmTKya/DNS/internal/store"
)

func openDB(t *testing.T) *store.DB {
	t.Helper()

	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatalf("opening the database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	return db
}

// drain runs the recorder until the expected number of events is stored, so
// the test waits on the outcome rather than on a sleep.
func drain(t *testing.T, db *store.DB, r *events.Recorder, want int) []events.Event {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go r.Run(ctx)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		list, err := events.List(t.Context(), db, events.Filter{})
		if err != nil {
			t.Fatalf("List() error = %v", err)
		}
		if len(list) >= want {
			return list
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("only stored fewer than %d events before the deadline", want)

	return nil
}

func TestRecordAndFilter(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	recorder := events.NewRecorder(db, nil)

	recorder.Record(events.KindRescued, events.SeverityInfo, "gib.gov.tr", "the first resolver could not answer")
	recorder.Record(events.KindRebindBlocked, events.SeverityWarning, "evil.example.com", "answered with 192.168.1.1")
	recorder.Record(events.KindFeedFailed, events.SeverityWarning, "OISD Big", "could not be updated")

	drain(t, db, recorder, 3)

	only, err := events.List(t.Context(), db, events.Filter{Kind: events.KindRebindBlocked})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(only) != 1 || only[0].Subject != "evil.example.com" {
		t.Fatalf("filtering by kind returned %+v", only)
	}

	counts, err := events.Counts(t.Context(), db)
	if err != nil {
		t.Fatalf("Counts() error = %v", err)
	}
	if counts[events.KindRescued] != 1 || counts[events.KindFeedFailed] != 1 {
		t.Errorf("Counts() = %v, want one of each", counts)
	}
}

// Newest first: someone opening this screen is asking what just happened, not
// what happened when the node was installed.
func TestListIsNewestFirst(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	recorder := events.NewRecorder(db, nil)

	recorder.Record(events.KindRescued, events.SeverityInfo, "first.example.com", "")
	drain(t, db, recorder, 1)

	recorder.Record(events.KindRescued, events.SeverityInfo, "second.example.com", "")
	list := drain(t, db, recorder, 2)

	if list[0].Subject != "second.example.com" {
		t.Errorf("first row is %q, want the most recent event", list[0].Subject)
	}
}

// Recording must never make a query wait, so a recorder nobody is draining has
// to drop rather than block the datapath.
func TestRecordNeverBlocks(t *testing.T) {
	t.Parallel()

	recorder := events.NewRecorder(openDB(t), nil)

	done := make(chan struct{})
	go func() {
		// Far more than the buffer holds, with nothing draining it.
		for range 5000 {
			recorder.Record(events.KindRescued, events.SeverityInfo, "x.example.com", "")
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Record() blocked when the queue was full; a full queue must drop, not stall a query")
	}
}
