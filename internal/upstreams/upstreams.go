// Package upstreams stores the resolvers a node forwards to.
//
// The shipped defaults are a guess about the whole world. Which resolver is
// actually fastest depends on the country, the ISP and the time of day, and it
// is not something a configuration file written months earlier can know — so
// the choice belongs in the panel, next to the measurement that justifies it.
//
// The rule that makes this safe to hand to someone: an empty list means the
// built-in defaults apply. Deleting the last resolver cannot leave a node with
// no way to resolve anything, which is the one mistake here that takes a
// household offline.
package upstreams

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/MmTKya/DNS/internal/store"
)

// Roles an upstream can have.
const (
	// RolePrimary resolvers answer ordinary queries.
	RolePrimary = "primary"

	// RoleFallback resolvers are consulted only once every primary has
	// failed. Keeping a plain, always-reachable resolver here means an outage
	// at an encrypted provider does not take the household offline.
	RoleFallback = "fallback"
)

// Upstream is one configured resolver.
type Upstream struct {
	CreatedAt string `json:"created_at"`
	Address   string `json:"address"`
	Role      string `json:"role"`
	Note      string `json:"note,omitempty"`
	ID        int64  `json:"id"`
	Position  int    `json:"position"`
	Enabled   bool   `json:"enabled"`
}

// List returns every configured upstream, primaries first.
func List(ctx context.Context, db *store.DB) (list []Upstream, err error) {
	rows, err := db.Reader().QueryContext(ctx, `
		SELECT id, address, role, position, enabled, note, created_at
		FROM upstreams
		ORDER BY role = 'fallback', position, id
	`)
	if err != nil {
		return nil, fmt.Errorf("listing upstreams: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var item Upstream
		if err = rows.Scan(&item.ID, &item.Address, &item.Role, &item.Position,
			&item.Enabled, &item.Note, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("reading an upstream: %w", err)
		}

		list = append(list, item)
	}

	return list, rows.Err()
}

// Effective returns the addresses to resolve with, or nil to keep the ones
// that shipped.
//
// Both halves of the return matter to the caller: nil primaries is the signal
// to leave the configured defaults alone, and it is deliberately not the same
// as an empty slice.
func Effective(ctx context.Context, db *store.DB) (primary, fallback []string, err error) {
	list, err := List(ctx, db)
	if err != nil {
		return nil, nil, err
	}

	for _, item := range list {
		if !item.Enabled {
			continue
		}

		if item.Role == RoleFallback {
			fallback = append(fallback, item.Address)
		} else {
			primary = append(primary, item.Address)
		}
	}

	// A list of only fallbacks would leave nothing to ask first, so it is
	// treated as no choice having been made rather than as a broken one.
	if len(primary) == 0 {
		return nil, nil, nil
	}

	return primary, fallback, nil
}

// ErrInvalid means the address is not something the resolver can forward to.
var ErrInvalid = errors.New("not a usable resolver address")

// Validate checks an address before it is stored.
//
// Rejecting it here rather than at the next reload is the difference between
// a message next to the field and a node that quietly stops resolving.
func Validate(address string) (normalised string, err error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", fmt.Errorf("%w: empty", ErrInvalid)
	}

	// Encrypted transports, which dnsproxy takes as URLs.
	for _, scheme := range []string{"tls://", "https://", "quic://", "sdns://"} {
		if strings.HasPrefix(address, scheme) {
			if _, parseErr := url.Parse(address); parseErr != nil {
				return "", fmt.Errorf("%w: %s", ErrInvalid, parseErr)
			}

			return address, nil
		}
	}

	// A domain-specific rule, e.g. [/home.lan/]192.168.1.1, is passed through
	// once the resolver part checks out.
	if strings.HasPrefix(address, "[/") {
		end := strings.Index(address, "]")
		if end < 0 {
			return "", fmt.Errorf("%w: unclosed [/domain/] prefix", ErrInvalid)
		}

		if _, restErr := Validate(address[end+1:]); restErr != nil {
			return "", restErr
		}

		return address, nil
	}

	// A plain resolver, with or without a port.
	host := address
	if h, _, found := strings.Cut(address, ":"); found && strings.Count(address, ":") == 1 {
		host = h
	}
	if _, addrErr := netip.ParseAddr(host); addrErr != nil {
		return "", fmt.Errorf("%w: %q is not an IP address or an encrypted URL like tls://dns.quad9.net", ErrInvalid, address)
	}

	return address, nil
}

// Add stores an upstream.
func Add(ctx context.Context, db *store.DB, address, role, note string) (id int64, err error) {
	normalised, err := Validate(address)
	if err != nil {
		return 0, err
	}

	if role != RoleFallback {
		role = RolePrimary
	}

	result, err := db.Writer().ExecContext(ctx, `
		INSERT INTO upstreams (address, role, position, note)
		VALUES (?, ?, COALESCE((SELECT MAX(position) + 1 FROM upstreams WHERE role = ?), 0), ?)
	`, normalised, role, role, note)
	if err != nil {
		return 0, fmt.Errorf("adding upstream %s: %w", normalised, err)
	}

	return result.LastInsertId()
}

// SetRole moves an upstream between primary and fallback.
func SetRole(ctx context.Context, db *store.DB, id int64, role string) error {
	if role != RoleFallback {
		role = RolePrimary
	}

	_, err := db.Writer().ExecContext(ctx, `UPDATE upstreams SET role = ? WHERE id = ?`, role, id)
	if err != nil {
		return fmt.Errorf("changing the role of upstream %d: %w", id, err)
	}

	return nil
}

// SetEnabled switches an upstream on or off without forgetting it.
func SetEnabled(ctx context.Context, db *store.DB, id int64, enabled bool) error {
	_, err := db.Writer().ExecContext(ctx, `UPDATE upstreams SET enabled = ? WHERE id = ?`, enabled, id)
	if err != nil {
		return fmt.Errorf("switching upstream %d: %w", id, err)
	}

	return nil
}

// Delete removes an upstream.
//
// Removing the last one is allowed on purpose: it is how someone goes back to
// the resolvers that shipped, and refusing would leave them editing a config
// file to undo a decision they made in the panel.
func Delete(ctx context.Context, db *store.DB, id int64) error {
	_, err := db.Writer().ExecContext(ctx, `DELETE FROM upstreams WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting upstream %d: %w", id, err)
	}

	return nil
}
