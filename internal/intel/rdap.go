package intel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/MmTKya/DNS/internal/store"
)

// rdapEndpoint is a single well-known RDAP aggregator rather than a per-TLD
// IANA bootstrap.
//
// One HTTP call, no registry of authoritative servers to maintain — the
// right tradeoff for a hobbyist box, since a lookup this fails open on
// anyway: if the aggregator is down, the domain's age is simply unknown, and
// unknown is never treated as new. A full IANA bootstrap is worth building
// only if this aggregator turns out to be unreliable in practice.
const rdapEndpoint = "https://rdap.org/domain/"

type rdapResponse struct {
	Events []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
}

// lookupRDAP asks the RDAP aggregator when a domain was registered.
//
// known is false, not an error, whenever the registry simply has nothing —
// a 404, a domain with no registration event, an unparsable date. Only a
// transport-level failure is returned as an error, and even that must be
// treated as "unknown" by every caller, never as "new".
func lookupRDAP(ctx context.Context, domain string) (registeredAt time.Time, known bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rdapEndpoint+url.PathEscape(domain), nil)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("building rdap request: %w", err)
	}
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("querying rdap: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return time.Time{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, false, fmt.Errorf("rdap returned %s", resp.Status)
	}

	var result rdapResponse
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return time.Time{}, false, fmt.Errorf("decoding rdap response: %w", err)
	}

	for _, event := range result.Events {
		if event.Action != "registration" {
			continue
		}

		parsed, parseErr := time.Parse(time.RFC3339, event.Date)
		if parseErr != nil {
			return time.Time{}, false, nil
		}

		return parsed, true, nil
	}

	return time.Time{}, false, nil
}

func getCachedAge(ctx context.Context, db *store.DB, domain string) (registeredAt time.Time, found bool, err error) {
	var registered int64

	row := db.Reader().QueryRowContext(ctx,
		`SELECT registered_at FROM domain_age WHERE domain = ?`, domain)

	switch err = row.Scan(&registered); {
	case errors.Is(err, sql.ErrNoRows):
		return time.Time{}, false, nil
	case err != nil:
		return time.Time{}, false, fmt.Errorf("reading cached domain age: %w", err)
	}

	return time.Unix(registered, 0), true, nil
}

func storeAge(ctx context.Context, db *store.DB, domain string, registeredAt time.Time) error {
	if _, err := db.Writer().ExecContext(ctx, `
		INSERT INTO domain_age (domain, registered_at, checked_at)
		VALUES (?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET
			registered_at = excluded.registered_at, checked_at = excluded.checked_at
	`, domain, registeredAt.Unix(), time.Now().Unix()); err != nil {
		return fmt.Errorf("caching domain age: %w", err)
	}

	return nil
}

// cachedAgeDays reads the permanent age cache only, never RDAP — used
// wherever a fast, cache-only answer is wanted and a live lookup is not.
func cachedAgeDays(ctx context.Context, db *store.DB, domain string) *int {
	registeredAt, found, err := getCachedAge(ctx, db, domain)
	if err != nil || !found {
		return nil
	}

	days := int(time.Since(registeredAt).Hours() / 24)

	return &days
}

// domainAge reports how old a domain is, consulting the permanent cache
// before RDAP. nil means unknown — never checked, RDAP had nothing, or the
// lookup failed — and every caller must treat that the same as "not new".
func domainAge(ctx context.Context, db *store.DB, domain string) *int {
	if registeredAt, found, err := getCachedAge(ctx, db, domain); err == nil && found {
		days := int(time.Since(registeredAt).Hours() / 24)

		return &days
	}

	registeredAt, known, err := lookupRDAP(ctx, domain)
	if err != nil || !known {
		return nil
	}

	// The lookup still succeeded even if this fails; losing the cache write
	// only costs a repeat query next time, not correctness now.
	_ = storeAge(ctx, db, domain, registeredAt)

	days := int(time.Since(registeredAt).Hours() / 24)

	return &days
}
