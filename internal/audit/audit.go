// Package audit records who changed what.
//
// None of the comparable products keep one, and it is the difference between
// "the internet broke last Tuesday" and "someone disabled the malware list on
// Tuesday at nine". In a household where more than one person can reach the
// panel, that is the only way to answer the question without guessing.
//
// Reads are not recorded. An audit trail that logs every dashboard refresh
// buries the twelve entries that matter under a hundred thousand that do not.
package audit

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/MmTKya/DNS/internal/store"
)

// Entry is one recorded action.
type Entry struct {
	At       time.Time `json:"at"`
	Username string    `json:"username"`
	IP       string    `json:"ip,omitempty"`
	Action   string    `json:"action"`
	Target   string    `json:"target,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	ID       int64     `json:"id"`
	Success  bool      `json:"success"`
}

// Recorder writes the audit trail.
type Recorder struct {
	db     *store.DB
	logger *slog.Logger
}

// New creates a recorder.
func New(db *store.DB, logger *slog.Logger) *Recorder {
	if logger == nil {
		logger = slog.Default()
	}

	return &Recorder{db: db, logger: logger.With("component", "audit")}
}

// Record stores an action.
//
// A failure to write the audit trail is logged but never returned: refusing to
// perform an action because it could not be recorded would turn a full disk
// into an outage.
func (r *Recorder) Record(ctx context.Context, entry Entry) {
	if entry.At.IsZero() {
		entry.At = time.Now()
	}

	success := 0
	if entry.Success {
		success = 1
	}

	if _, err := r.db.Writer().ExecContext(ctx, `
		INSERT INTO audit_log (at, username, ip, action, target, detail, success)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, entry.At.Unix(), entry.Username, entry.IP, entry.Action, entry.Target,
		entry.Detail, success,
	); err != nil {
		r.logger.ErrorContext(ctx, "recording an audited action",
			"action", entry.Action, "err", err)
	}
}

// Query filters the audit trail.
type Query struct {
	Username string
	Action   string
	Since    time.Time
	Limit    int
}

// List returns recorded actions, most recent first.
func (r *Recorder) List(ctx context.Context, q Query) (entries []Entry, err error) {
	where := "WHERE 1 = 1"
	args := []any{}

	if q.Username != "" {
		where += " AND username = ?"
		args = append(args, q.Username)
	}
	if q.Action != "" {
		where += " AND action = ?"
		args = append(args, q.Action)
	}
	if !q.Since.IsZero() {
		where += " AND at >= ?"
		args = append(args, q.Since.Unix())
	}

	limit := q.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	args = append(args, limit)

	rows, err := r.db.Reader().QueryContext(ctx, `
		SELECT id, at, username, ip, action, target, detail, success
		FROM audit_log `+where+` ORDER BY at DESC, id DESC LIMIT ?
	`, args...)
	if err != nil {
		return nil, fmt.Errorf("reading the audit log: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			e       Entry
			at      int64
			success int
		)
		if err = rows.Scan(&e.ID, &at, &e.Username, &e.IP, &e.Action,
			&e.Target, &e.Detail, &success); err != nil {
			return nil, fmt.Errorf("scanning an audit entry: %w", err)
		}

		e.At = time.Unix(at, 0)
		e.Success = success != 0
		entries = append(entries, e)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating the audit log: %w", err)
	}

	return entries, nil
}

// Prune drops entries older than the retention window.
//
// The trail is kept far longer than the query log, because it is small and
// because the question it answers is usually asked weeks later.
func (r *Recorder) Prune(ctx context.Context, retention time.Duration) error {
	if retention <= 0 {
		retention = 365 * 24 * time.Hour
	}

	if _, err := r.db.Writer().ExecContext(ctx,
		`DELETE FROM audit_log WHERE at < ?`, time.Now().Add(-retention).Unix()); err != nil {
		return fmt.Errorf("pruning the audit log: %w", err)
	}

	return nil
}
