package sgb

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/MmTKya/DNS/internal/store"
)

// FeedID is how this connector's rules are attributed in match results.
const FeedID = "usom-sgb"

// Settings keys for sync bookkeeping.
const (
	settingMaxID    = "sgb.max_id"
	settingLastFull = "sgb.last_full_sync"
	settingSyncRun  = "sgb.sync_run"
)

// syncedTypes are the record kinds worth having in a DNS filter.  URLs are
// skipped: a resolver sees names, not paths, and blocking a whole domain
// because one URL on it was reported would take down shared hosting.
var syncedTypes = []string{TypeDomain, TypeIP}

// reconcileInterval is how often the whole feed is re-fetched.
//
// Deltas only ever add. Entries are removed upstream when a site is cleaned
// up, and without a periodic full pass a domain would stay blocked here long
// after the national CERT cleared it.
const reconcileInterval = 24 * time.Hour

// Syncer keeps a local copy of the national feed.
type Syncer struct {
	client *Client
	db     *store.DB
	logger *slog.Logger
	dir    string
}

// NewSyncer creates a syncer that writes its compiled list into dir, where the
// ordinary feed compiler will pick it up like any other list.
func NewSyncer(client *Client, db *store.DB, dir string, logger *slog.Logger) *Syncer {
	if logger == nil {
		logger = slog.Default()
	}

	return &Syncer{
		client: client,
		db:     db,
		dir:    dir,
		logger: logger.With("component", "sgb"),
	}
}

// Result summarises a sync.
type Result struct {
	Added    int
	Removed  int
	Total    int
	FullSync bool
	Exported int
	Duration time.Duration
}

// Sync brings the local copy up to date, choosing a delta or a full pass.
func (s *Syncer) Sync(ctx context.Context, force bool) (result Result, err error) {
	start := time.Now()

	full := force || s.dueForFullSync(ctx)

	if full {
		result, err = s.fullSync(ctx)
	} else {
		result, err = s.deltaSync(ctx)
	}
	if err != nil {
		return result, err
	}

	exported, err := s.export(ctx)
	if err != nil {
		return result, err
	}

	result.Exported = exported
	result.Duration = time.Since(start)

	s.logger.InfoContext(ctx, "national threat feed synced",
		"full", result.FullSync,
		"added", result.Added,
		"removed", result.Removed,
		"total", result.Total,
		"took", result.Duration,
	)

	return result, nil
}

func (s *Syncer) dueForFullSync(ctx context.Context) bool {
	value, ok, err := s.db.GetSetting(ctx, settingLastFull)
	if err != nil || !ok {
		return true
	}

	ts, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return true
	}

	return time.Since(ts) >= reconcileInterval
}

// fullSync fetches everything and replaces the local copy, which is what
// catches upstream deletions.
func (s *Syncer) fullSync(ctx context.Context) (result Result, err error) {
	result.FullSync = true

	// Every full pass gets its own generation, and anything still carrying an
	// older one at the end is gone upstream.
	run, err := s.nextSyncRun(ctx)
	if err != nil {
		return result, err
	}

	var maxID int64

	for _, entryType := range syncedTypes {
		first, fetchErr := s.client.Fetch(ctx, entryType, 0, PageSize)
		if fetchErr != nil {
			return result, fmt.Errorf("fetching %s: %w", entryType, fetchErr)
		}

		pages := first.PageCount
		s.logger.InfoContext(ctx, "starting full sync",
			"type", entryType, "records", first.TotalCount, "pages", pages)

		page := first
		for i := 0; ; i++ {
			for _, entry := range page.Entries {
				if entry.ID > maxID {
					maxID = entry.ID
				}
			}

			if err = s.upsert(ctx, page.Entries, run); err != nil {
				return result, err
			}
			result.Added += len(page.Entries)

			if i+1 >= pages {
				break
			}

			if page, err = s.client.Fetch(ctx, entryType, i+1, PageSize); err != nil {
				// A partial sync is still better than none: what was written
				// stays, and the next run resumes from a fresh full pass.
				s.logger.ErrorContext(ctx, "full sync interrupted",
					"type", entryType, "page", i+1, "err", err)

				return result, err
			}
		}
	}

	// Anything not touched by this pass is gone upstream.
	removed, err := s.deleteStale(ctx, run)
	if err != nil {
		return result, err
	}
	result.Removed = removed

	if err = s.db.SetSetting(ctx, settingLastFull, time.Now().Format(time.RFC3339)); err != nil {
		return result, fmt.Errorf("recording sync time: %w", err)
	}
	if maxID > 0 {
		if err = s.db.SetSetting(ctx, settingMaxID, fmt.Sprint(maxID)); err != nil {
			return result, fmt.Errorf("recording max id: %w", err)
		}
	}

	result.Total, err = s.count(ctx)

	return result, err
}

// deltaSync fetches only records newer than the highest id already stored.
//
// The API orders newest first, so this walks forward until it meets a known
// id: on a quiet hour that is a single request instead of 465.
func (s *Syncer) deltaSync(ctx context.Context) (result Result, err error) {
	knownMax, err := s.maxID(ctx)
	if err != nil {
		return result, err
	}
	if knownMax == 0 {
		return s.fullSync(ctx)
	}

	// A delta joins the current generation, so the rows it adds are not swept
	// away by the next reconcile.
	run, err := s.currentSyncRun(ctx)
	if err != nil {
		return result, err
	}

	newMax := knownMax

	for _, entryType := range syncedTypes {
		for page := 0; ; page++ {
			batch, fetchErr := s.client.Fetch(ctx, entryType, page, PageSize)
			if fetchErr != nil {
				return result, fmt.Errorf("fetching %s delta: %w", entryType, fetchErr)
			}
			if len(batch.Entries) == 0 {
				break
			}

			var fresh []Entry
			caughtUp := false
			for _, entry := range batch.Entries {
				if entry.ID <= knownMax {
					caughtUp = true

					break
				}
				if entry.ID > newMax {
					newMax = entry.ID
				}
				fresh = append(fresh, entry)
			}

			if len(fresh) > 0 {
				if err = s.upsert(ctx, fresh, run); err != nil {
					return result, err
				}
				result.Added += len(fresh)
			}

			if caughtUp || page+1 >= batch.PageCount {
				break
			}
		}
	}

	if newMax > knownMax {
		if err = s.db.SetSetting(ctx, settingMaxID, fmt.Sprint(newMax)); err != nil {
			return result, fmt.Errorf("recording max id: %w", err)
		}
	}

	result.Total, err = s.count(ctx)

	return result, err
}

func (s *Syncer) upsert(ctx context.Context, entries []Entry, run int64) (err error) {
	if len(entries) == 0 {
		return nil
	}

	tx, err := s.db.Writer().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w (rollback: %v)", err, tx.Rollback())
		}
	}()

	now := time.Now().Unix()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO sgb_entries (id, value, type, category, source, criticality, added_at, sync_run, synced_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			value = excluded.value, category = excluded.category,
			source = excluded.source, criticality = excluded.criticality,
			sync_run = excluded.sync_run, synced_at = excluded.synced_at
	`)
	if err != nil {
		return fmt.Errorf("preparing upsert: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, entry := range entries {
		var addedAt int64
		if !entry.AddedAt.IsZero() {
			addedAt = entry.AddedAt.Unix()
		}

		if _, err = stmt.ExecContext(ctx, entry.ID, entry.Value, entry.Type,
			entry.Category, entry.Source, entry.Criticality, addedAt, run, now,
		); err != nil {
			return fmt.Errorf("storing entry %d: %w", entry.ID, err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("committing: %w", err)
	}

	return nil
}

func (s *Syncer) deleteStale(ctx context.Context, run int64) (removed int, err error) {
	res, err := s.db.Writer().ExecContext(ctx,
		`DELETE FROM sgb_entries WHERE sync_run != ?`, run)
	if err != nil {
		return 0, fmt.Errorf("removing stale entries: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("counting removals: %w", err)
	}

	return int(affected), nil
}

// nextSyncRun allocates a new generation for a full pass.
func (s *Syncer) nextSyncRun(ctx context.Context) (run int64, err error) {
	current, err := s.currentSyncRun(ctx)
	if err != nil {
		return 0, err
	}

	run = current + 1
	if err = s.db.SetSetting(ctx, settingSyncRun, fmt.Sprint(run)); err != nil {
		return 0, fmt.Errorf("recording sync run: %w", err)
	}

	return run, nil
}

func (s *Syncer) currentSyncRun(ctx context.Context) (run int64, err error) {
	value, ok, err := s.db.GetSetting(ctx, settingSyncRun)
	if err != nil || !ok {
		return 0, err
	}

	if _, err = fmt.Sscan(value, &run); err != nil {
		return 0, nil
	}

	return run, nil
}

func (s *Syncer) count(ctx context.Context) (total int, err error) {
	if err = s.db.Reader().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sgb_entries`).Scan(&total); err != nil {
		return 0, fmt.Errorf("counting entries: %w", err)
	}

	return total, nil
}

func (s *Syncer) maxID(ctx context.Context) (maxID int64, err error) {
	value, ok, err := s.db.GetSetting(ctx, settingMaxID)
	if err != nil || !ok {
		return 0, err
	}

	if _, err = fmt.Sscan(value, &maxID); err != nil {
		return 0, nil
	}

	return maxID, nil
}

// export writes the domains as a plain list, so the ordinary feed compiler
// consumes them exactly like any other source — same provenance, same enable
// switch, same statistics.
func (s *Syncer) export(ctx context.Context) (count int, err error) {
	if err = os.MkdirAll(s.dir, 0o750); err != nil {
		return 0, fmt.Errorf("creating feed cache directory: %w", err)
	}

	rows, err := s.db.Reader().QueryContext(ctx,
		`SELECT value FROM sgb_entries WHERE type = ? ORDER BY value`, TypeDomain)
	if err != nil {
		return 0, fmt.Errorf("reading entries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	path := filepath.Join(s.dir, FeedID+".txt")
	tmp, err := os.CreateTemp(s.dir, FeedID+".*.tmp")
	if err != nil {
		return 0, fmt.Errorf("creating temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()

	writer := bufio.NewWriter(tmp)
	for rows.Next() {
		var value string
		if err = rows.Scan(&value); err != nil {
			_ = tmp.Close()

			return 0, fmt.Errorf("scanning entry: %w", err)
		}

		if _, err = fmt.Fprintf(writer, "||%s^\n", value); err != nil {
			_ = tmp.Close()

			return 0, fmt.Errorf("writing entry: %w", err)
		}
		count++
	}

	if err = rows.Err(); err != nil {
		_ = tmp.Close()

		return 0, fmt.Errorf("iterating entries: %w", err)
	}

	if err = writer.Flush(); err != nil {
		_ = tmp.Close()

		return 0, fmt.Errorf("flushing export: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return 0, fmt.Errorf("closing export: %w", err)
	}
	if err = os.Chmod(tmpName, 0o640); err != nil {
		return 0, fmt.Errorf("setting permissions: %w", err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return 0, fmt.Errorf("installing export: %w", err)
	}

	return count, nil
}

// Lookup returns what the national feed says about a name, which is what turns
// "a blocklist said so" into "USOM lists this as banking phishing, added on
// Tuesday".
func Lookup(ctx context.Context, db *store.DB, value string) (entry Entry, found bool, err error) {
	var (
		addedAt int64
		id      int64
	)

	row := db.Reader().QueryRowContext(ctx, `
		SELECT id, value, type, category, source, criticality, added_at
		FROM sgb_entries WHERE value = ? LIMIT 1
	`, value)

	err = row.Scan(&id, &entry.Value, &entry.Type, &entry.Category,
		&entry.Source, &entry.Criticality, &addedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Entry{}, false, nil
	case err != nil:
		return Entry{}, false, fmt.Errorf("looking up %q: %w", value, err)
	}

	entry.ID = id
	if addedAt > 0 {
		entry.AddedAt = time.Unix(addedAt, 0)
	}

	return entry, true, nil
}

// CategoryCounts summarises what is stored, for the panel.
func CategoryCounts(ctx context.Context, db *store.DB) (counts map[string]int, err error) {
	rows, err := db.Reader().QueryContext(ctx,
		`SELECT category, COUNT(*) FROM sgb_entries GROUP BY category`)
	if err != nil {
		return nil, fmt.Errorf("counting categories: %w", err)
	}
	defer func() { _ = rows.Close() }()

	counts = map[string]int{}
	for rows.Next() {
		var (
			category string
			count    int
		)
		if err = rows.Scan(&category, &count); err != nil {
			return nil, fmt.Errorf("scanning category count: %w", err)
		}
		counts[category] = count
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating category counts: %w", err)
	}

	return counts, nil
}

// Run syncs on a schedule until ctx is cancelled.
func (s *Syncer) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}

	// The first sync is a full pass over 465,000 records, so it waits until
	// the node is answering queries rather than competing with startup.
	initial := time.NewTimer(time.Minute)
	defer initial.Stop()

	select {
	case <-ctx.Done():
		return
	case <-initial.C:
	}

	for {
		if _, err := s.Sync(ctx, false); err != nil && ctx.Err() == nil {
			s.logger.ErrorContext(ctx, "syncing the national threat feed", "err", err)
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()

			return
		case <-timer.C:
		}
	}
}
