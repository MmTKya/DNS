package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/MmTKya/DNS/internal/store"
)

// Suggestion statuses.
const (
	StatusPending = "pending"
	StatusBlocked = "blocked"
	StatusAllowed = "allowed"
	StatusIgnored = "ignored"
)

// Suggestion is a name the node thinks is worth blocking, waiting on a human.
type Suggestion struct {
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	DecidedAt  time.Time `json:"decided_at,omitzero"`
	Domain     string    `json:"domain"`
	Reason     string    `json:"reason"`
	Status     string    `json:"status"`
	Clients    []string  `json:"clients"`
	Findings   []Finding `json:"findings"`
	Score      int       `json:"score"`
	QueryCount int       `json:"query_count"`
}

// Queue watches unknown names and asks about the ones worth asking about.
//
// The selection matters more than the lookups.  A home network resolves tens
// of thousands of distinct names a day and every source here is rate-limited,
// so this cannot check everything: it checks names that are new to this
// network, skipping the ones already decided, and it does so at a pace that
// keeps free-tier quotas intact.
type Queue struct {
	db       *store.DB
	enricher *Enricher
	logger   *slog.Logger

	mu sync.Mutex
	// pending is the set of names waiting to be checked, and seen is what has
	// already been considered in this process.  Both are bounded: an unbounded
	// set here is a memory leak driven by whatever the network resolves.
	pending map[string]*candidate
	seen    map[string]time.Time

	// autoBlock, when on, blocks anything the sources agree is malicious
	// without asking.  Off by default: an unexplained automatic block is how
	// people stop trusting the thing that is meant to protect them.
	autoBlock bool
}

type candidate struct {
	firstSeen time.Time
	clients   map[string]struct{}
	count     int
}

// Bounds on the in-memory state.
const (
	maxPending = 2_000
	maxSeen    = 50_000

	// checkInterval paces lookups.  A handful an hour is enough to surface
	// what matters on a home network and leaves every free tier untouched.
	checkInterval = 20 * time.Second
	maxPerHour    = 120
)

// NewQueue creates the suggestion queue.
func NewQueue(db *store.DB, enricher *Enricher, logger *slog.Logger) *Queue {
	if logger == nil {
		logger = slog.Default()
	}

	return &Queue{
		db:       db,
		enricher: enricher,
		logger:   logger.With("component", "intel"),
		pending:  map[string]*candidate{},
		seen:     map[string]time.Time{},
	}
}

// SetAutoBlock turns automatic blocking on or off.
func (q *Queue) SetAutoBlock(on bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.autoBlock = on
}

// Consider offers a resolved name to the queue.  It runs on the hot path, so
// it does nothing but bookkeeping in memory.
func (q *Queue) Consider(domain, client string) {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	if domain == "" || isUninteresting(domain) {
		return
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	if _, done := q.seen[domain]; done {
		return
	}

	if existing, ok := q.pending[domain]; ok {
		existing.count++
		if client != "" && len(existing.clients) < 16 {
			existing.clients[client] = struct{}{}
		}

		return
	}

	if len(q.pending) >= maxPending {
		return
	}

	c := &candidate{firstSeen: time.Now(), count: 1, clients: map[string]struct{}{}}
	if client != "" {
		c.clients[client] = struct{}{}
	}
	q.pending[domain] = c
}

// isUninteresting filters out names that are never worth a threat lookup.
//
// Reverse-DNS zones, local names and the resolver's own infrastructure would
// otherwise burn a rate-limited quota to learn nothing.
func isUninteresting(domain string) bool {
	switch {
	case strings.HasSuffix(domain, ".arpa"),
		strings.HasSuffix(domain, ".local"),
		strings.HasSuffix(domain, ".lan"),
		strings.HasSuffix(domain, ".home"),
		strings.HasSuffix(domain, ".internal"),
		strings.HasSuffix(domain, ".localdomain"),
		strings.HasSuffix(domain, ".invalid"),
		strings.HasSuffix(domain, ".test"):
		return true
	}

	// A bare label is a search-domain artefact, not a site.
	return !strings.Contains(domain, ".")
}

// LoadAutoBlock restores the automatic-blocking setting from the database, so
// a restart does not quietly change the policy the operator chose.
func (q *Queue) LoadAutoBlock(ctx context.Context) error {
	value, ok, err := q.db.GetSetting(ctx, SettingAutoBlock)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}

	q.SetAutoBlock(value == "true")

	return nil
}

// PendingLen reports how many names are waiting to be checked.
func (q *Queue) PendingLen() int {
	q.mu.Lock()
	defer q.mu.Unlock()

	return len(q.pending)
}

// Run processes the queue until ctx is cancelled.
func (q *Queue) Run(ctx context.Context) {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	// A rolling budget, so a burst of new names cannot drain an hour's quota
	// in a minute.
	budget := maxPerHour
	refill := time.NewTicker(time.Hour)
	defer refill.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-refill.C:
			budget = maxPerHour

		case <-ticker.C:
			if budget <= 0 {
				continue
			}

			domain, cand := q.take()
			if domain == "" {
				continue
			}
			budget--

			if err := q.check(ctx, domain, cand); err != nil && ctx.Err() == nil {
				q.logger.DebugContext(ctx, "checking a name", "domain", domain, "err", err)
			}
		}
	}
}

// take removes one candidate from the queue.
func (q *Queue) take() (domain string, cand *candidate) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for name, c := range q.pending {
		delete(q.pending, name)

		if len(q.seen) >= maxSeen {
			q.seen = map[string]time.Time{}
		}
		q.seen[name] = time.Now()

		return name, c
	}

	return "", nil
}

func (q *Queue) check(ctx context.Context, domain string, cand *candidate) error {
	assessment, err := q.enricher.Assess(ctx, domain)
	if err != nil {
		return err
	}

	if !assessment.Suspect() {
		return nil
	}

	clients := make([]string, 0, len(cand.clients))
	for c := range cand.clients {
		clients = append(clients, c)
	}

	q.mu.Lock()
	auto := q.autoBlock
	q.mu.Unlock()

	status := StatusPending
	if auto && assessment.Malicious() {
		status = StatusBlocked
	}

	if err = q.record(ctx, assessment, clients, cand, status); err != nil {
		return err
	}

	q.logger.InfoContext(ctx, "a name looks malicious",
		"domain", domain,
		"score", assessment.Score,
		"sources", len(assessment.Findings),
		"auto_blocked", status == StatusBlocked,
	)

	return nil
}

func (q *Queue) record(
	ctx context.Context,
	assessment Assessment,
	clients []string,
	cand *candidate,
	status string,
) error {
	findings, err := json.Marshal(assessment.Findings)
	if err != nil {
		return fmt.Errorf("encoding findings: %w", err)
	}

	reason := summarise(assessment.Findings)
	now := time.Now()

	firstSeen := now
	if cand != nil && !cand.firstSeen.IsZero() {
		firstSeen = cand.firstSeen
	}
	count := 1
	if cand != nil {
		count = cand.count
	}

	var decidedAt int64
	if status != StatusPending {
		decidedAt = now.Unix()
	}

	if _, err = q.db.Writer().ExecContext(ctx, `
		INSERT INTO intel_suggestions
			(domain, score, reason, findings, clients, query_count, first_seen, last_seen, status, decided_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET
			score = excluded.score, reason = excluded.reason, findings = excluded.findings,
			clients = excluded.clients, query_count = intel_suggestions.query_count + excluded.query_count,
			last_seen = excluded.last_seen
	`, assessment.Domain, assessment.Score, reason, string(findings),
		strings.Join(clients, ","), count, firstSeen.Unix(), now.Unix(), status, decidedAt,
	); err != nil {
		return fmt.Errorf("recording suggestion: %w", err)
	}

	return nil
}

// summarise turns findings into one line a person can act on.
func summarise(findings []Finding) string {
	if len(findings) == 0 {
		return ""
	}

	parts := make([]string, 0, len(findings))
	for _, f := range findings {
		if f.Detail != "" {
			parts = append(parts, f.Source+": "+f.Detail)
		} else {
			parts = append(parts, f.Source)
		}
	}

	return strings.Join(parts, "; ")
}

// List returns suggestions with the given status, highest score first.
func ListSuggestions(ctx context.Context, db *store.DB, status string, limit int) (suggestions []Suggestion, err error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	query := `
		SELECT domain, score, reason, findings, clients, query_count,
		       first_seen, last_seen, status, decided_at
		FROM intel_suggestions`
	args := []any{}

	if status != "" {
		query += ` WHERE status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY score DESC, last_seen DESC LIMIT ?`
	args = append(args, limit)

	rows, err := db.Reader().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing suggestions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			s                   Suggestion
			findings, clients   string
			firstSeen, lastSeen int64
			decidedAt           int64
		)

		if err = rows.Scan(&s.Domain, &s.Score, &s.Reason, &findings, &clients,
			&s.QueryCount, &firstSeen, &lastSeen, &s.Status, &decidedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning suggestion: %w", err)
		}

		s.FirstSeen = time.Unix(firstSeen, 0)
		s.LastSeen = time.Unix(lastSeen, 0)
		if decidedAt > 0 {
			s.DecidedAt = time.Unix(decidedAt, 0)
		}
		if clients != "" {
			s.Clients = strings.Split(clients, ",")
		}
		if err = json.Unmarshal([]byte(findings), &s.Findings); err != nil {
			s.Findings = nil
		}

		suggestions = append(suggestions, s)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating suggestions: %w", err)
	}

	return suggestions, nil
}

// Decide records what the operator chose.  The caller is responsible for
// turning a "block" or "allow" into an actual rule; this only remembers the
// decision so the same name is never suggested twice.
func Decide(ctx context.Context, db *store.DB, domain, status string) (found bool, err error) {
	switch status {
	case StatusBlocked, StatusAllowed, StatusIgnored:
	default:
		return false, fmt.Errorf("unknown decision %q", status)
	}

	res, err := db.Writer().ExecContext(ctx,
		`UPDATE intel_suggestions SET status = ?, decided_at = ? WHERE domain = ?`,
		status, time.Now().Unix(), domain)
	if err != nil {
		return false, fmt.Errorf("recording decision: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("checking decision: %w", err)
	}

	return affected > 0, nil
}

// PendingCount is what the panel puts on its notification badge.
func PendingCount(ctx context.Context, db *store.DB) (count int, err error) {
	if err = db.Reader().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM intel_suggestions WHERE status = ?`, StatusPending,
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("counting suggestions: %w", err)
	}

	return count, nil
}
