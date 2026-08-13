// Package events records the things a node notices that are not queries.
//
// It exists so that "why did that page not open" has an answer on the screen
// rather than in a shell session. Everything here was previously only in the
// journal, which is fine for whoever wrote the code and useless for the person
// whose internet is not working.
//
// The writing side is deliberately cheap and never blocks a query: an event is
// a diagnostic, and a resolver that got slower in order to explain itself
// would have its priorities backwards.
package events

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/MmTKya/DNS/internal/store"
)

// Kinds of event. Each one answers a question someone actually asks.
const (
	// KindRescued: a name resolved only because a second resolver was asked.
	// "That site was slow to load" often lands here.
	KindRescued = "rescued"

	// KindRebindBlocked: an answer pointed a public name inside this network
	// and was dropped. "That page will not open at all" lands here, and it is
	// the first thing to check when something legitimate breaks.
	KindRebindBlocked = "rebind_blocked"

	// KindFeedFailed: a blocklist could not be downloaded. Protection quietly
	// stops improving, and nothing else would say so.
	KindFeedFailed = "feed_failed"

	// KindUpstreamDown: a resolver stopped answering.
	KindUpstreamDown = "upstream_down"

	// KindUpstreamRecovered closes the loop, so a red line in the list has a
	// green one after it rather than looking permanent.
	KindUpstreamRecovered = "upstream_recovered"
)

// Severities.
const (
	SeverityInfo    = "info"
	SeverityWarning = "warning"
	SeverityError   = "error"
)

// Event is one thing that happened.
type Event struct {
	At       time.Time `json:"at"`
	Kind     string    `json:"kind"`
	Severity string    `json:"severity"`
	Subject  string    `json:"subject,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	ID       int64     `json:"id"`
}

// Recorder writes events without making a query wait for a disk.
type Recorder struct {
	db     *store.DB
	logger *slog.Logger

	queue chan Event
	once  sync.Once
}

// bufferSize bounds the queue. Full means something is producing events far
// faster than they can be useful, and dropping is the right answer: the
// resolver's job is answering DNS, not keeping a complete diary of a storm.
const bufferSize = 256

// NewRecorder creates a recorder. Call Run to start draining it.
func NewRecorder(db *store.DB, logger *slog.Logger) *Recorder {
	if logger == nil {
		logger = slog.Default()
	}

	return &Recorder{
		db:     db,
		logger: logger.With("component", "events"),
		queue:  make(chan Event, bufferSize),
	}
}

// Record queues an event. Never blocks.
func (r *Recorder) Record(kind, severity, subject, detail string) {
	if r == nil {
		return
	}

	select {
	case r.queue <- Event{At: time.Now(), Kind: kind, Severity: severity, Subject: subject, Detail: detail}:
	default:
		// Dropped on purpose. See bufferSize.
	}
}

// Run writes queued events until the context is cancelled.
func (r *Recorder) Run(ctx context.Context) {
	// Old events are swept on a timer rather than on every write, which would
	// turn one insert into two statements for no benefit.
	sweep := time.NewTicker(6 * time.Hour)
	defer sweep.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case event := <-r.queue:
			if err := r.write(ctx, event); err != nil {
				r.logger.WarnContext(ctx, "could not record an event", "kind", event.Kind, "err", err)
			}

		case <-sweep.C:
			if err := r.prune(ctx); err != nil {
				r.logger.WarnContext(ctx, "could not prune old events", "err", err)
			}
		}
	}
}

func (r *Recorder) write(ctx context.Context, e Event) error {
	_, err := r.db.Writer().ExecContext(ctx, `
		INSERT INTO events (at, kind, severity, subject, detail)
		VALUES (?, ?, ?, ?, ?)
	`, e.At.UTC().Format(time.RFC3339), e.Kind, e.Severity, e.Subject, e.Detail)

	return err
}

// retention is how long an event stays readable.
//
// Long enough to cover "it started last week", short enough that this never
// becomes the reason an SD card fills up.
const retention = 30 * 24 * time.Hour

func (r *Recorder) prune(ctx context.Context) error {
	cutoff := time.Now().Add(-retention).UTC().Format(time.RFC3339)
	_, err := r.db.Writer().ExecContext(ctx, `DELETE FROM events WHERE at < ?`, cutoff)

	return err
}

// Filter narrows a listing.
type Filter struct {
	// Kind, empty for every kind.
	Kind string

	// Severity, empty for every severity.
	Severity string

	Limit int
}

// List returns events, newest first.
func List(ctx context.Context, db *store.DB, f Filter) (list []Event, err error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 200
	}

	// Built with placeholders rather than string building: the values come
	// from a query string.
	query := `SELECT id, at, kind, severity, subject, detail FROM events WHERE 1 = 1`
	args := []any{}

	if f.Kind != "" {
		query += ` AND kind = ?`
		args = append(args, f.Kind)
	}
	if f.Severity != "" {
		query += ` AND severity = ?`
		args = append(args, f.Severity)
	}

	query += ` ORDER BY at DESC, id DESC LIMIT ?`
	args = append(args, f.Limit)

	rows, err := db.Reader().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var e Event
		var at string

		if err = rows.Scan(&e.ID, &at, &e.Kind, &e.Severity, &e.Subject, &e.Detail); err != nil {
			return nil, err
		}
		if parsed, parseErr := time.Parse(time.RFC3339, at); parseErr == nil {
			e.At = parsed
		}

		list = append(list, e)
	}

	return list, rows.Err()
}

// Counts returns how many of each kind are stored, so the panel can show which
// filters are worth offering rather than a row of empty ones.
func Counts(ctx context.Context, db *store.DB) (counts map[string]int, err error) {
	rows, err := db.Reader().QueryContext(ctx, `SELECT kind, COUNT(*) FROM events GROUP BY kind`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	counts = map[string]int{}
	for rows.Next() {
		var kind string
		var n int

		if err = rows.Scan(&kind, &n); err != nil {
			return nil, err
		}

		counts[kind] = n
	}

	return counts, rows.Err()
}
