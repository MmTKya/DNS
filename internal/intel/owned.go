package intel

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/MmTKya/DNS/internal/store"
)

// OwnedDomain is a name the operator has declared as their own — a
// self-hosted service this node must never mistake for an unknown
// third-party name.
type OwnedDomain struct {
	Domain    string    `json:"domain"`
	Label     string    `json:"label"`
	CreatedAt time.Time `json:"created_at"`
}

func normalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

// AddOwnedDomain records a domain as the operator's own.
func AddOwnedDomain(ctx context.Context, db *store.DB, domain, label string) error {
	domain = normalizeDomain(domain)
	if domain == "" {
		return errors.New("a domain is required")
	}

	if _, err := db.Writer().ExecContext(ctx, `
		INSERT INTO owned_domains (domain, label, created_at)
		VALUES (?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET label = excluded.label
	`, domain, strings.TrimSpace(label), time.Now().Unix()); err != nil {
		return fmt.Errorf("recording owned domain: %w", err)
	}

	return nil
}

// RemoveOwnedDomain forgets a domain the operator no longer wants excluded.
func RemoveOwnedDomain(ctx context.Context, db *store.DB, domain string) (found bool, err error) {
	domain = normalizeDomain(domain)

	res, err := db.Writer().ExecContext(ctx, `DELETE FROM owned_domains WHERE domain = ?`, domain)
	if err != nil {
		return false, fmt.Errorf("removing owned domain: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("checking removal: %w", err)
	}

	return affected > 0, nil
}

// ListOwnedDomains returns every domain the operator has declared as theirs.
func ListOwnedDomains(ctx context.Context, db *store.DB) ([]OwnedDomain, error) {
	rows, err := db.Reader().QueryContext(ctx,
		`SELECT domain, label, created_at FROM owned_domains ORDER BY domain`)
	if err != nil {
		return nil, fmt.Errorf("listing owned domains: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var domains []OwnedDomain
	for rows.Next() {
		var (
			d         OwnedDomain
			createdAt int64
		)

		if err = rows.Scan(&d.Domain, &d.Label, &createdAt); err != nil {
			return nil, fmt.Errorf("scanning owned domain: %w", err)
		}
		d.CreatedAt = time.Unix(createdAt, 0)

		domains = append(domains, d)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating owned domains: %w", err)
	}

	return domains, nil
}

// SetOwned replaces the in-memory set the hot path consults.
//
// Kept in memory rather than queried per-lookup because Consider runs on
// every resolved name: a database round trip there would turn a household's
// own traffic into its own bottleneck.
func (q *Queue) SetOwned(domains []string) {
	owned := make(map[string]bool, len(domains))
	for _, d := range domains {
		if d = normalizeDomain(d); d != "" {
			owned[d] = true
		}
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	q.owned = owned
}

// LoadOwned restores the owned-domain set from the database, so a restart
// does not briefly forget which names are the operator's own.
func (q *Queue) LoadOwned(ctx context.Context) error {
	domains, err := ListOwnedDomains(ctx, q.db)
	if err != nil {
		return err
	}

	names := make([]string, len(domains))
	for i, d := range domains {
		names[i] = d.Domain
	}
	q.SetOwned(names)

	return nil
}

// isOwned reports whether a name is the operator's own, or a subdomain of
// one — the same label-walk Reputable does, and for the same reason: a
// report against a subdomain of an owned name is a report against the
// operator's own infrastructure just the same.
func (q *Queue) isOwned(domain string) bool {
	q.mu.Lock()
	owned := q.owned
	q.mu.Unlock()

	if len(owned) == 0 {
		return false
	}

	name := domain
	for {
		if owned[name] {
			return true
		}

		_, rest, found := strings.Cut(name, ".")
		if !found {
			return false
		}

		name = rest
	}
}
