package feeds

import (
	"context"
	"fmt"
	"time"

	"github.com/MmTKya/DNS/internal/store"
)

// Record is a feed's persisted state.
type Record struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	Custom bool   `json:"custom"`

	Enabled bool `json:"enabled"`

	ETag         string `json:"-"`
	LastModified string `json:"-"`

	LastFetchAt   time.Time `json:"last_fetch_at,omitzero"`
	LastSuccessAt time.Time `json:"last_success_at,omitzero"`
	LastError     string    `json:"last_error,omitempty"`
	RuleCount     int       `json:"rule_count"`
	Bytes         int64     `json:"bytes"`
}

// State returns the cache validators for a conditional request.
func (r Record) State() State {
	return State{
		ETag:         r.ETag,
		LastModified: r.LastModified,
		Bytes:        r.Bytes,
		RuleCount:    r.RuleCount,
	}
}

// UserRule is a rule the operator wrote by hand.
type UserRule struct {
	CreatedAt time.Time `json:"created_at"`
	Rule      string    `json:"rule"`
	Comment   string    `json:"comment,omitempty"`
	ID        int64     `json:"id"`
	Enabled   bool      `json:"enabled"`
}

// Seed inserts the catalogue's default-on feeds on a fresh install.  It is
// idempotent: an operator who disables a default feed does not get it switched
// back on at the next restart.
func Seed(ctx context.Context, db *store.DB) error {
	for _, feed := range Catalog() {
		if !feed.DefaultOn {
			continue
		}

		_, err := db.Writer().ExecContext(ctx, `
			INSERT INTO feeds (id, name, url, enabled, custom)
			VALUES (?, ?, ?, 1, 0)
			ON CONFLICT(id) DO NOTHING
		`, feed.ID, feed.Name, feed.URL)
		if err != nil {
			return fmt.Errorf("seeding feed %s: %w", feed.ID, err)
		}
	}

	return nil
}

// List returns every known feed: the ones stored in the database, plus the
// catalogue entries the operator has not touched yet, so the panel can show
// the whole menu rather than only what is switched on.
func List(ctx context.Context, db *store.DB) (records []Record, err error) {
	stored, err := listStored(ctx, db)
	if err != nil {
		return nil, err
	}

	byID := make(map[string]Record, len(stored))
	for _, r := range stored {
		byID[r.ID] = r
	}

	records = make([]Record, 0, len(stored))
	for _, feed := range Catalog() {
		if r, ok := byID[feed.ID]; ok {
			records = append(records, r)
			delete(byID, feed.ID)

			continue
		}

		records = append(records, Record{ID: feed.ID, Name: feed.Name, URL: feed.URL})
	}

	// Custom feeds, and any catalogue entry that has since been removed.
	for _, r := range stored {
		if _, ok := byID[r.ID]; ok {
			records = append(records, r)
		}
	}

	return records, nil
}

func listStored(ctx context.Context, db *store.DB) (records []Record, err error) {
	rows, err := db.Reader().QueryContext(ctx, `
		SELECT id, name, url, enabled, custom, etag, last_modified,
		       last_fetch_at, last_success_at, last_error, rule_count, bytes
		FROM feeds
		ORDER BY id
	`)
	if err != nil {
		return nil, fmt.Errorf("listing feeds: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			r                     Record
			fetchAt, successAt    int64
			enabledInt, customInt int
		)

		if err = rows.Scan(&r.ID, &r.Name, &r.URL, &enabledInt, &customInt, &r.ETag,
			&r.LastModified, &fetchAt, &successAt, &r.LastError, &r.RuleCount, &r.Bytes,
		); err != nil {
			return nil, fmt.Errorf("scanning feed: %w", err)
		}

		r.Enabled = enabledInt != 0
		r.Custom = customInt != 0
		if fetchAt > 0 {
			r.LastFetchAt = time.Unix(fetchAt, 0)
		}
		if successAt > 0 {
			r.LastSuccessAt = time.Unix(successAt, 0)
		}

		records = append(records, r)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating feeds: %w", err)
	}

	return records, nil
}

// Enabled returns the feeds that should be fetched and compiled.
func Enabled(ctx context.Context, db *store.DB) (records []Record, err error) {
	all, err := listStored(ctx, db)
	if err != nil {
		return nil, err
	}

	for _, r := range all {
		if r.Enabled {
			records = append(records, r)
		}
	}

	return records, nil
}

// Get returns one feed's state, falling back to the catalogue for a feed the
// operator has never configured.
func Get(ctx context.Context, db *store.DB, id string) (record Record, found bool, err error) {
	stored, err := listStored(ctx, db)
	if err != nil {
		return Record{}, false, err
	}

	for _, r := range stored {
		if r.ID == id {
			return r, true, nil
		}
	}

	if feed, ok := Lookup(id); ok {
		return Record{ID: feed.ID, Name: feed.Name, URL: feed.URL}, true, nil
	}

	return Record{}, false, nil
}

// SetEnabled switches a feed on or off, creating its row if the operator is
// enabling a catalogue entry for the first time.
func SetEnabled(ctx context.Context, db *store.DB, id string, enabled bool) error {
	feed, known := Lookup(id)

	res, err := db.Writer().ExecContext(ctx,
		`UPDATE feeds SET enabled = ? WHERE id = ?`, boolToInt(enabled), id)
	if err != nil {
		return fmt.Errorf("updating feed %s: %w", id, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking update of feed %s: %w", id, err)
	}
	if affected > 0 {
		return nil
	}

	if !known {
		return fmt.Errorf("unknown feed %q", id)
	}

	_, err = db.Writer().ExecContext(ctx, `
		INSERT INTO feeds (id, name, url, enabled, custom) VALUES (?, ?, ?, ?, 0)
		ON CONFLICT(id) DO UPDATE SET enabled = excluded.enabled
	`, feed.ID, feed.Name, feed.URL, boolToInt(enabled))
	if err != nil {
		return fmt.Errorf("enabling feed %s: %w", id, err)
	}

	return nil
}

// AddCustom registers a feed that is not in the catalogue.
func AddCustom(ctx context.Context, db *store.DB, id, name, url string) error {
	if _, clash := Lookup(id); clash {
		return fmt.Errorf("%q is a built-in feed id", id)
	}

	_, err := db.Writer().ExecContext(ctx, `
		INSERT INTO feeds (id, name, url, enabled, custom) VALUES (?, ?, ?, 1, 1)
	`, id, name, url)
	if err != nil {
		return fmt.Errorf("adding custom feed %s: %w", id, err)
	}

	return nil
}

// Delete removes a feed's row.  Built-in feeds are disabled instead, so they
// reappear in the catalogue rather than vanishing.
func Delete(ctx context.Context, db *store.DB, id string) error {
	if _, builtin := Lookup(id); builtin {
		return SetEnabled(ctx, db, id, false)
	}

	if _, err := db.Writer().ExecContext(ctx, `DELETE FROM feeds WHERE id = ?`, id); err != nil {
		return fmt.Errorf("deleting feed %s: %w", id, err)
	}

	return nil
}

// recordFetch stores the outcome of a fetch attempt.
func recordFetch(ctx context.Context, db *store.DB, id string, res FetchResult, ruleCount int, fetchErr error) error {
	now := time.Now().Unix()

	errText := ""
	successAt := now
	if fetchErr != nil {
		errText = fetchErr.Error()
		successAt = 0
	}

	query := `
		UPDATE feeds SET
			last_fetch_at = ?,
			last_error    = ?,
			etag          = CASE WHEN ? = '' THEN etag ELSE ? END,
			last_modified = CASE WHEN ? = '' THEN last_modified ELSE ? END`
	args := []any{now, errText, res.ETag, res.ETag, res.LastModified, res.LastModified}

	// A failed fetch must not overwrite the counts from the last good one:
	// the panel should keep showing what is actually loaded.
	if fetchErr == nil {
		query += `, last_success_at = ?, rule_count = ?, bytes = ?`
		args = append(args, successAt, ruleCount, res.Bytes)
	}

	query += ` WHERE id = ?`
	args = append(args, id)

	if _, err := db.Writer().ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("recording fetch of %s: %w", id, err)
	}

	return nil
}

// ListUserRules returns the operator's own rules.
func ListUserRules(ctx context.Context, db *store.DB) (rules []UserRule, err error) {
	rows, err := db.Reader().QueryContext(ctx, `
		SELECT id, rule, enabled, comment, created_at FROM user_rules ORDER BY id
	`)
	if err != nil {
		return nil, fmt.Errorf("listing user rules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			r         UserRule
			enabled   int
			createdAt int64
		)
		if err = rows.Scan(&r.ID, &r.Rule, &enabled, &r.Comment, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning user rule: %w", err)
		}

		r.Enabled = enabled != 0
		r.CreatedAt = time.Unix(createdAt, 0)
		rules = append(rules, r)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating user rules: %w", err)
	}

	return rules, nil
}

// AddUserRule stores a hand-written rule.
func AddUserRule(ctx context.Context, db *store.DB, rule, comment string) (id int64, err error) {
	res, err := db.Writer().ExecContext(ctx, `
		INSERT INTO user_rules (rule, enabled, comment, created_at) VALUES (?, 1, ?, ?)
	`, rule, comment, time.Now().Unix())
	if err != nil {
		return 0, fmt.Errorf("adding user rule: %w", err)
	}

	if id, err = res.LastInsertId(); err != nil {
		return 0, fmt.Errorf("reading new rule id: %w", err)
	}

	return id, nil
}

// DeleteUserRule removes a hand-written rule.
func DeleteUserRule(ctx context.Context, db *store.DB, id int64) (found bool, err error) {
	res, err := db.Writer().ExecContext(ctx, `DELETE FROM user_rules WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("deleting user rule %d: %w", id, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("checking deletion of user rule %d: %w", id, err)
	}

	return affected > 0, nil
}

// SetUserRuleEnabled switches a hand-written rule on or off.
func SetUserRuleEnabled(ctx context.Context, db *store.DB, id int64, enabled bool) (found bool, err error) {
	res, err := db.Writer().ExecContext(ctx,
		`UPDATE user_rules SET enabled = ? WHERE id = ?`, boolToInt(enabled), id)
	if err != nil {
		return false, fmt.Errorf("updating user rule %d: %w", id, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("checking update of user rule %d: %w", id, err)
	}

	return affected > 0, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}

	return 0
}
