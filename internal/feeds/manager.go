package feeds

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MmTKya/DNS/internal/filter"
	"github.com/MmTKya/DNS/internal/store"
)

// shrinkGuard rejects an update that would drop a list below this fraction of
// its previous size.
//
// A maintainer's build breaking, or a CDN serving an error page with a 200,
// otherwise silently turns filtering off — the failure mode nobody notices
// because nothing appears broken.
const shrinkGuard = 0.5

// userRulesSourceID attributes hand-written rules in match results.
const userRulesSourceID = "user"

// Manager keeps the compiled ruleset in step with the enabled feeds.
type Manager struct {
	db     *store.DB
	dl     *Downloader
	engine *filter.Engine
	logger *slog.Logger

	// mu serialises compile, which rebuilds the index.  Only one rebuild is
	// worth doing at a time and two would race to install theirs.
	mu sync.Mutex

	// refreshing guards the download half.  Not the same lock: Refresh ends
	// by calling Compile, so sharing one would deadlock — and the two want
	// different behaviour anyway. A second compile has to wait its turn; a
	// second download of the same lists has nothing to wait for.
	refreshing atomic.Bool

	lastCompile CompileResult

	// onEvent reports a feed that could not be updated, so protection
	// quietly ceasing to improve is visible on the panel rather than only in
	// the journal.
	onEvent func(kind, subject, detail string)
}

// OnEvent registers a callback for feed failures.
func (m *Manager) OnEvent(fn func(kind, subject, detail string)) { m.onEvent = fn }

// EventFeedFailed is reported when a list could not be downloaded.
const EventFeedFailed = "feed_failed"

// CompileResult summarises a rebuild of the ruleset.
type CompileResult struct {
	At       time.Time               `json:"at"`
	Sources  map[string]SourceReport `json:"sources"`
	Rules    int                     `json:"rules"`
	Duration time.Duration           `json:"duration_ns"`
}

// SourceReport is one list's contribution to the compiled ruleset.
type SourceReport struct {
	Error       string `json:"error,omitempty"`
	Rules       int    `json:"rules"`
	Unsupported int    `json:"unsupported"`
	Invalid     int    `json:"invalid"`
}

// NewManager wires the pieces together.
func NewManager(db *store.DB, dl *Downloader, engine *filter.Engine, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}

	return &Manager{
		db:     db,
		dl:     dl,
		engine: engine,
		logger: logger.With("component", "feeds"),
	}
}

// LastCompile returns the most recent rebuild's summary.
func (m *Manager) LastCompile() CompileResult {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.lastCompile
}

// Refresh fetches every enabled feed and rebuilds the ruleset.
//
// A feed that fails keeps its previous cached copy and its previous rules:
// losing a blocklist because GitHub was briefly unreachable would quietly
// unblock everything on it.
func (m *Manager) Refresh(ctx context.Context, force bool) error {
	// A refresh already running is downloading the same lists from the same
	// servers, so a second one is not more up to date — it is the same work
	// twice. List maintainers rate-limit for exactly this, and being rate
	// limited by a mirror because the node asked itself four times is a
	// failure with nobody to blame but the node.
	if !m.refreshing.CompareAndSwap(false, true) {
		m.logger.DebugContext(ctx, "a refresh is already running; skipping this one")

		return nil
	}
	defer m.refreshing.Store(false)

	records, err := Enabled(ctx, m.db)
	if err != nil {
		return err
	}

	for _, record := range records {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Connector-backed feeds are an API, not a file; their own syncer
		// keeps the cache file up to date and this loop would only fetch the
		// API's first page as though it were a blocklist.
		if feed, ok := Lookup(record.ID); ok && feed.Connector {
			continue
		}

		if !force && !m.due(record) {
			continue
		}

		m.fetch(ctx, record)
	}

	return m.Compile(ctx)
}

// due reports whether enough time has passed to poll this feed again.
func (m *Manager) due(record Record) bool {
	if record.LastSuccessAt.IsZero() {
		return true
	}

	interval := 24 * time.Hour
	if feed, ok := Lookup(record.ID); ok && feed.PollInterval > 0 {
		interval = feed.PollInterval
	}

	return time.Since(record.LastSuccessAt) >= interval
}

func (m *Manager) fetch(ctx context.Context, record Record) {
	feed := Feed{ID: record.ID, Name: record.Name, URL: record.URL}
	if catalogued, ok := Lookup(record.ID); ok && !record.Custom {
		feed = catalogued
		feed.URL = record.URL
	}

	res, err := m.dl.Fetch(ctx, feed, record.State())
	switch {
	case errors.Is(err, ErrNotModified):
		m.logger.DebugContext(ctx, "feed unchanged", "feed", record.ID)

		if recordErr := recordFetch(ctx, m.db, record.ID, res, record.RuleCount, nil); recordErr != nil {
			m.logger.ErrorContext(ctx, "recording feed state", "feed", record.ID, "err", recordErr)
		}

		return

	case err != nil:
		m.logger.ErrorContext(ctx, "fetching feed", "feed", record.ID, "err", err)

		if m.onEvent != nil {
			m.onEvent(EventFeedFailed, record.Name, "could not be updated: "+err.Error())
		}

		if recordErr := recordFetch(ctx, m.db, record.ID, res, 0, err); recordErr != nil {
			m.logger.ErrorContext(ctx, "recording feed error", "feed", record.ID, "err", recordErr)
		}

		return
	}

	// The download is inspected while it is still staged, so a bad update is
	// thrown away instead of replacing a list the resolver is relying on.
	count, countErr := countRules(res.Path)
	if countErr != nil {
		m.logger.ErrorContext(ctx, "counting feed rules", "feed", record.ID, "err", countErr)
		m.dl.Discard(record.ID)

		if recordErr := recordFetch(ctx, m.db, record.ID, FetchResult{}, 0, countErr); recordErr != nil {
			m.logger.ErrorContext(ctx, "recording feed error", "feed", record.ID, "err", recordErr)
		}

		return
	}

	if shrank(record.RuleCount, count) {
		err = fmt.Errorf("update rejected: %d rules is less than half of the previous %d, "+
			"which usually means a broken build or an error page served with a 200",
			count, record.RuleCount)
		m.logger.WarnContext(ctx, "feed shrank suspiciously, keeping the previous copy",
			"feed", record.ID, "previous", record.RuleCount, "new", count)
		m.dl.Discard(record.ID)

		if recordErr := recordFetch(ctx, m.db, record.ID, FetchResult{}, 0, err); recordErr != nil {
			m.logger.ErrorContext(ctx, "recording feed error", "feed", record.ID, "err", recordErr)
		}

		return
	}

	if err = m.dl.Commit(record.ID); err != nil {
		m.logger.ErrorContext(ctx, "installing feed", "feed", record.ID, "err", err)

		if recordErr := recordFetch(ctx, m.db, record.ID, FetchResult{}, 0, err); recordErr != nil {
			m.logger.ErrorContext(ctx, "recording feed error", "feed", record.ID, "err", recordErr)
		}

		return
	}

	m.logger.InfoContext(ctx, "feed updated",
		"feed", record.ID, "rules", count, "bytes", res.Bytes, "mirror", res.FromMirror)

	if recordErr := recordFetch(ctx, m.db, record.ID, res, count, nil); recordErr != nil {
		m.logger.ErrorContext(ctx, "recording feed state", "feed", record.ID, "err", recordErr)
	}
}

// shrank reports whether an update lost too much of the previous list.
func shrank(previous, current int) bool {
	// A list that was small or empty before has nothing to compare against.
	if previous < 1000 {
		return false
	}

	return float64(current) < float64(previous)*shrinkGuard
}

// Compile rebuilds the ruleset from the cached feed files and the operator's
// own rules, then swaps it in atomically.
func (m *Manager) Compile(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	start := time.Now()

	records, err := Enabled(ctx, m.db)
	if err != nil {
		return err
	}

	builder := filter.NewBuilder()
	report := make(map[string]SourceReport, len(records)+1)

	// User rules are added first so that, all else being equal, the source
	// attributed to a shared domain is the one the operator wrote.
	userRules, err := ListUserRules(ctx, m.db)
	if err != nil {
		return err
	}
	if len(userRules) > 0 {
		src := builder.AddSource(userRulesSourceID, "Your rules")
		var enabled []string
		for _, r := range userRules {
			if r.Enabled {
				enabled = append(enabled, r.Rule)
			}
		}

		stats, addErr := builder.AddReader(src, strings.NewReader(strings.Join(enabled, "\n")))
		if addErr != nil {
			return fmt.Errorf("compiling user rules: %w", addErr)
		}
		report[userRulesSourceID] = SourceReport{
			Rules:       stats.Rules,
			Unsupported: stats.Unsupported,
			Invalid:     stats.Errors,
		}
	}

	for _, record := range records {
		path := m.dl.CachePath(record.ID)

		file, openErr := os.Open(path)
		if openErr != nil {
			if !errors.Is(openErr, os.ErrNotExist) {
				report[record.ID] = SourceReport{Error: openErr.Error()}
			}

			continue
		}

		src := builder.AddSource(record.ID, record.Name)
		stats, addErr := builder.AddReader(src, file)
		_ = file.Close()

		if addErr != nil {
			report[record.ID] = SourceReport{Error: addErr.Error()}

			continue
		}

		report[record.ID] = SourceReport{
			Rules:       stats.Rules,
			Unsupported: stats.Unsupported,
			Invalid:     stats.Errors,
		}
	}

	index := builder.Build()
	m.engine.Replace(index)

	m.lastCompile = CompileResult{
		At:       time.Now(),
		Rules:    index.Len(),
		Sources:  report,
		Duration: time.Since(start),
	}

	m.logger.InfoContext(ctx, "ruleset compiled",
		"rules", index.Len(),
		"sources", len(report),
		"approx_bytes", index.ApproxBytes(),
		"took", time.Since(start),
	)

	return nil
}

// Run refreshes feeds on a schedule until ctx is cancelled.
//
// The first refresh happens shortly after start rather than immediately, so a
// node that has just booted answers queries before it spends bandwidth on
// downloads.
func (m *Manager) Run(ctx context.Context, interval time.Duration) {
	// The startup compile happens before the DNS listener opens, so that the
	// node never answers with the filter switched off. Repeating it here
	// would rebuild an index that is already loaded.

	initial := time.NewTimer(30 * time.Second)
	defer initial.Stop()

	select {
	case <-ctx.Done():
		return
	case <-initial.C:
	}

	if err := m.Refresh(ctx, false); err != nil && ctx.Err() == nil {
		m.logger.ErrorContext(ctx, "refreshing feeds", "err", err)
	}

	for {
		// Each wait is jittered so that thousands of installs built from the
		// same image do not hit the same URL at the same second.
		timer := time.NewTimer(jitter(interval))

		select {
		case <-ctx.Done():
			timer.Stop()

			return
		case <-timer.C:
		}

		if err := m.Refresh(ctx, false); err != nil && ctx.Err() == nil {
			m.logger.ErrorContext(ctx, "refreshing feeds", "err", err)
		}
	}
}

// countRules counts the parseable rules in a cached feed file.  It is used for
// the shrink guard, so it must count the same way the compiler does.
func countRules(path string) (count int, err error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("opening %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	builder := filter.NewBuilder()
	src := builder.AddSource("count", "count")

	stats, err := builder.AddReader(src, file)
	if err != nil {
		return 0, err
	}

	return stats.Rules, nil
}
