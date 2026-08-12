// Package querylog records what the resolver did, in memory for the live
// dashboard and on disk for history.
//
// The write pattern is the whole design. Target hardware often boots from an
// SD card, and a busy home network makes thousands of queries a minute; a row
// written per query is how comparable products end up with multi-gigabyte
// databases and worn-out cards. So the hot path only appends to a fixed
// in-memory ring, a background flush writes batches, and rows older than the
// retention window are rolled up into small hourly aggregates and deleted.
package querylog

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MmTKya/DNS/internal/config"
	"github.com/MmTKya/DNS/internal/policy"
	"github.com/MmTKya/DNS/internal/store"
	"github.com/miekg/dns"
)

// Entry is one recorded query.
type Entry struct {
	Time          time.Time `json:"time"`
	Client        string    `json:"client"`
	ClientID      string    `json:"client_id,omitempty"`
	Host          string    `json:"host"`
	QType         string    `json:"qtype"`
	Verdict       string    `json:"verdict"`
	RuleSource    string    `json:"rule_source,omitempty"`
	MatchedDomain string    `json:"matched_domain,omitempty"`
	Upstream      string    `json:"upstream,omitempty"`
	Error         string    `json:"error,omitempty"`
	ID            uint64    `json:"id"`
	ElapsedMS     float64   `json:"elapsed_ms"`
	Rcode         int       `json:"rcode"`
	Answers       int       `json:"answers"`
	Cached        bool      `json:"cached"`
}

// Log is the query recorder.  It implements policy.Observer.
type Log struct {
	db     *store.DB
	logger *slog.Logger

	mode          string
	flushInterval time.Duration
	retention     time.Duration

	mu      sync.RWMutex
	ring    []Entry
	head    int
	filled  bool
	pending []Entry

	subscribers map[int]chan Entry
	nextSub     int

	nextID atomic.Uint64

	total    atomic.Uint64
	blocked  atomic.Uint64
	allowed  atomic.Uint64
	rewrites atomic.Uint64
	errors   atomic.Uint64
	cached   atomic.Uint64
	elapsed  atomic.Uint64 // microseconds, for a running average

	// dropped counts entries lost because the disk buffer was full, which is
	// the honest signal that the flush cannot keep up.
	dropped atomic.Uint64
}

// maxPending bounds the disk buffer between flushes.  A busy network can
// outrun a slow card; dropping the overflow is better than growing until the
// process is killed.
const maxPending = 20_000

// New creates a query log.
func New(db *store.DB, cfg *config.Config, logger *slog.Logger) *Log {
	if logger == nil {
		logger = slog.Default()
	}

	size := cfg.QueryLog.RingSize
	if size <= 0 {
		size = 1
	}

	return &Log{
		db:            db,
		logger:        logger.With("component", "querylog"),
		mode:          cfg.QueryLog.Mode,
		flushInterval: cfg.QueryLog.FlushInterval.Duration(),
		retention:     cfg.QueryLog.Retention.Duration(),
		ring:          make([]Entry, size),
		subscribers:   map[int]chan Entry{},
	}
}

// Observe implements policy.Observer.  It runs on the hot path, so it does no
// I/O: everything here is an append to memory.
func (l *Log) Observe(event policy.Event) {
	l.count(event)

	if l.mode == config.QueryLogOff {
		return
	}

	entry := l.entry(event)

	l.mu.Lock()

	l.ring[l.head] = entry
	l.head = (l.head + 1) % len(l.ring)
	if l.head == 0 {
		l.filled = true
	}

	if l.persists() {
		if len(l.pending) < maxPending {
			l.pending = append(l.pending, entry)
		} else {
			l.dropped.Add(1)
		}
	}

	subs := make([]chan Entry, 0, len(l.subscribers))
	for _, ch := range l.subscribers {
		subs = append(subs, ch)
	}

	l.mu.Unlock()

	// A slow or disconnected panel must never slow down DNS, so a full
	// subscriber channel drops the entry rather than blocking.
	for _, ch := range subs {
		select {
		case ch <- entry:
		default:
		}
	}
}

func (l *Log) count(event policy.Event) {
	l.total.Add(1)
	l.elapsed.Add(uint64(event.Elapsed.Microseconds()))

	switch event.Verdict {
	case policy.VerdictBlocked:
		l.blocked.Add(1)
	case policy.VerdictRewritten:
		l.rewrites.Add(1)
	case policy.VerdictError:
		l.errors.Add(1)
	default:
		l.allowed.Add(1)
	}

	if event.Cached {
		l.cached.Add(1)
	}
}

func (l *Log) entry(event policy.Event) Entry {
	qtype := dns.TypeToString[event.QType]
	if qtype == "" {
		qtype = fmt.Sprintf("TYPE%d", event.QType)
	}

	entry := Entry{
		ID:            l.nextID.Add(1),
		Time:          event.Time,
		Client:        l.client(event.Client),
		ClientID:      event.ClientID,
		Host:          event.Host,
		QType:         qtype,
		Verdict:       event.Verdict,
		RuleSource:    event.RuleSource,
		MatchedDomain: event.MatchedDomain,
		Rcode:         event.Rcode,
		Answers:       event.AnswerCount,
		ElapsedMS:     float64(event.Elapsed.Microseconds()) / 1000,
		Cached:        event.Cached,
		Upstream:      event.Upstream,
		Error:         event.Error,
	}

	if l.mode == config.QueryLogAnonymized {
		entry.ClientID = ""
	}

	return entry
}

// client renders the source address, truncating it in anonymized mode.
//
// Truncation keeps the statistics — how much traffic, from which part of the
// network — while giving up the ability to attribute a name to one device.
// That is the trade the mode exists to make.
func (l *Log) client(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}

	if l.mode != config.QueryLogAnonymized {
		return addr.String()
	}

	switch {
	case addr.Is4():
		prefix, err := addr.Prefix(24)
		if err != nil {
			return ""
		}

		return prefix.String()
	default:
		prefix, err := addr.Prefix(48)
		if err != nil {
			return ""
		}

		return prefix.String()
	}
}

func (l *Log) persists() bool {
	return l.mode == config.QueryLogFull || l.mode == config.QueryLogAnonymized
}

// Recent returns the newest entries, most recent first.
func (l *Log) Recent(limit int) []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	size := len(l.ring)
	available := l.head
	if l.filled {
		available = size
	}

	if limit <= 0 || limit > available {
		limit = available
	}

	out := make([]Entry, 0, limit)
	for i := range limit {
		idx := (l.head - 1 - i + size*2) % size
		out = append(out, l.ring[idx])
	}

	return out
}

// Subscribe returns a channel of live entries and a function to release it.
// The channel is buffered and lossy by design; the panel batches anyway.
func (l *Log) Subscribe(buffer int) (events <-chan Entry, cancel func()) {
	if buffer <= 0 {
		buffer = 256
	}

	ch := make(chan Entry, buffer)

	l.mu.Lock()
	id := l.nextSub
	l.nextSub++
	l.subscribers[id] = ch
	l.mu.Unlock()

	return ch, func() {
		l.mu.Lock()
		defer l.mu.Unlock()

		if existing, ok := l.subscribers[id]; ok {
			delete(l.subscribers, id)
			close(existing)
		}
	}
}

// Stats are the counters behind the dashboard's headline numbers.
type Stats struct {
	Total        uint64  `json:"total"`
	Blocked      uint64  `json:"blocked"`
	Allowed      uint64  `json:"allowed"`
	Rewritten    uint64  `json:"rewritten"`
	Errors       uint64  `json:"errors"`
	Cached       uint64  `json:"cached"`
	Dropped      uint64  `json:"dropped"`
	BlockedRatio float64 `json:"blocked_ratio"`
	CacheRatio   float64 `json:"cache_ratio"`
	AvgElapsedMS float64 `json:"avg_elapsed_ms"`
	Mode         string  `json:"mode"`
}

// Stats returns the counters accumulated since start.
func (l *Log) Stats() Stats {
	total := l.total.Load()

	s := Stats{
		Total:     total,
		Blocked:   l.blocked.Load(),
		Allowed:   l.allowed.Load(),
		Rewritten: l.rewrites.Load(),
		Errors:    l.errors.Load(),
		Cached:    l.cached.Load(),
		Dropped:   l.dropped.Load(),
		Mode:      l.mode,
	}

	if total > 0 {
		s.BlockedRatio = float64(s.Blocked) / float64(total)
		s.CacheRatio = float64(s.Cached) / float64(total)
		s.AvgElapsedMS = float64(l.elapsed.Load()) / float64(total) / 1000
	}

	return s
}

// Run flushes buffered entries and rolls up history until ctx is cancelled.
func (l *Log) Run(ctx context.Context) {
	if !l.persists() {
		// RAM and off modes never touch the disk, which is the setting for an
		// SD-card install and for anyone who does not want a browsing history
		// stored on the device at all.
		<-ctx.Done()

		return
	}

	flush := time.NewTicker(l.flushInterval)
	defer flush.Stop()

	// Retention runs far less often than flushing; it is a delete and an
	// aggregate, not something to do every minute.
	rollup := time.NewTicker(time.Hour)
	defer rollup.Stop()

	for {
		select {
		case <-ctx.Done():
			// A clean shutdown should not lose the last minute of history.
			l.flush(context.WithoutCancel(ctx))

			return

		case <-flush.C:
			l.flush(ctx)

		case <-rollup.C:
			if err := l.rollup(ctx); err != nil {
				l.logger.ErrorContext(ctx, "rolling up query history", "err", err)
			}
		}
	}
}

// Flush writes buffered entries immediately.  Exposed for shutdown and tests.
func (l *Log) Flush(ctx context.Context) { l.flush(ctx) }

func (l *Log) flush(ctx context.Context) {
	l.mu.Lock()
	batch := l.pending
	l.pending = nil
	l.mu.Unlock()

	if len(batch) == 0 {
		return
	}

	if err := l.writeBatch(ctx, batch); err != nil {
		l.logger.ErrorContext(ctx, "writing query log batch", "entries", len(batch), "err", err)
	}
}

func (l *Log) writeBatch(ctx context.Context, batch []Entry) (err error) {
	tx, err := l.db.Writer().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w (rollback: %v)", err, tx.Rollback())
		}
	}()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO query_log
			(ts, client, client_id, host, qtype, verdict, rule_source,
			 matched_domain, rcode, answers, elapsed_ms, cached, upstream, proto)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("preparing insert: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, e := range batch {
		cached := 0
		if e.Cached {
			cached = 1
		}

		if _, err = stmt.ExecContext(ctx,
			e.Time.Unix(), e.Client, e.ClientID, e.Host, int(dns.StringToType[e.QType]),
			e.Verdict, e.RuleSource, e.MatchedDomain, e.Rcode, e.Answers,
			e.ElapsedMS, cached, e.Upstream, "",
		); err != nil {
			return fmt.Errorf("inserting entry: %w", err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("committing: %w", err)
	}

	return nil
}

// rollup aggregates rows past the retention window and deletes them.
func (l *Log) rollup(ctx context.Context) (err error) {
	cutoff := time.Now().Add(-l.retention).Unix()

	tx, err := l.db.Writer().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w (rollback: %v)", err, tx.Rollback())
		}
	}()

	// Hourly counts per verdict: a few rows an hour, cheap to keep forever.
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO query_stats_hourly (hour, verdict, count)
		SELECT ts / 3600 * 3600, verdict, COUNT(*)
		FROM query_log WHERE ts < ?
		GROUP BY ts / 3600 * 3600, verdict
		ON CONFLICT(hour, verdict) DO UPDATE SET count = count + excluded.count
	`, cutoff); err != nil {
		return fmt.Errorf("aggregating hourly counts: %w", err)
	}

	// Top names and clients, bounded per hour so history cannot grow without
	// limit the way a full per-name table would.
	for _, spec := range []struct {
		kind  string
		key   string
		where string
	}{
		{kind: "host", key: "host", where: ""},
		{kind: "blocked_host", key: "host", where: "AND verdict = 'blocked'"},
		{kind: "client", key: "client", where: ""},
	} {
		query := fmt.Sprintf(`
			INSERT INTO query_top_hourly (hour, kind, key, count)
			SELECT hour, ?, key, count FROM (
				SELECT ts / 3600 * 3600 AS hour, %s AS key, COUNT(*) AS count,
				       ROW_NUMBER() OVER (
				           PARTITION BY ts / 3600 * 3600 ORDER BY COUNT(*) DESC
				       ) AS rank
				FROM query_log
				WHERE ts < ? %s
				GROUP BY hour, key
			) WHERE rank <= 50
			ON CONFLICT(hour, kind, key) DO UPDATE SET count = count + excluded.count
		`, spec.key, spec.where)

		if _, err = tx.ExecContext(ctx, query, spec.kind, cutoff); err != nil {
			return fmt.Errorf("aggregating top %s: %w", spec.kind, err)
		}
	}

	res, err := tx.ExecContext(ctx, `DELETE FROM query_log WHERE ts < ?`, cutoff)
	if err != nil {
		return fmt.Errorf("deleting expired rows: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("committing: %w", err)
	}

	if deleted, rowsErr := res.RowsAffected(); rowsErr == nil && deleted > 0 {
		l.logger.InfoContext(ctx, "rolled up query history", "rows", deleted)
	}

	return nil
}

// Search returns stored entries matching a filter, newest first.
type Search struct {
	Host    string
	Client  string
	Verdict string
	Since   time.Time
	Limit   int
}

// Query reads history from the database.  The live dashboard uses Recent
// instead; this is for looking further back than the ring holds.
func (l *Log) Query(ctx context.Context, s Search) (entries []Entry, err error) {
	if !l.persists() {
		return nil, nil
	}

	where := []string{"1 = 1"}
	args := []any{}

	if s.Host != "" {
		where = append(where, "host LIKE ?")
		args = append(args, "%"+s.Host+"%")
	}
	if s.Client != "" {
		where = append(where, "client = ?")
		args = append(args, s.Client)
	}
	if s.Verdict != "" {
		where = append(where, "verdict = ?")
		args = append(args, s.Verdict)
	}
	if !s.Since.IsZero() {
		where = append(where, "ts >= ?")
		args = append(args, s.Since.Unix())
	}

	limit := s.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	args = append(args, limit)

	query := `
		SELECT id, ts, client, client_id, host, qtype, verdict, rule_source,
		       matched_domain, rcode, answers, elapsed_ms, cached, upstream
		FROM query_log
		WHERE ` + strings.Join(where, " AND ") + `
		ORDER BY ts DESC, id DESC
		LIMIT ?`

	rows, err := l.db.Reader().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying history: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			e      Entry
			ts     int64
			qtype  int
			cached int
		)

		if err = rows.Scan(&e.ID, &ts, &e.Client, &e.ClientID, &e.Host, &qtype,
			&e.Verdict, &e.RuleSource, &e.MatchedDomain, &e.Rcode, &e.Answers,
			&e.ElapsedMS, &cached, &e.Upstream,
		); err != nil {
			return nil, fmt.Errorf("scanning history row: %w", err)
		}

		e.Time = time.Unix(ts, 0)
		e.Cached = cached != 0
		if name, ok := dns.TypeToString[uint16(qtype)]; ok {
			e.QType = name
		}

		entries = append(entries, e)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating history: %w", err)
	}

	return entries, nil
}
