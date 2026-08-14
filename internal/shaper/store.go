package shaper

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/MmTKya/DNS/internal/store"
)

// Stored is a limit as the panel holds it, before it is turned into rules.
type Stored struct {
	ClientKey    string `json:"client_key"`
	UpdatedAt    string `json:"updated_at"`
	DownloadKbps int    `json:"download_kbps"`
	UploadKbps   int    `json:"upload_kbps"`
	Enabled      bool   `json:"enabled"`
}

// List returns every stored limit.
func List(ctx context.Context, db *store.DB) (limits []Stored, err error) {
	rows, err := db.Reader().QueryContext(ctx, `
		SELECT client_key, download_kbps, upload_kbps, enabled, updated_at
		FROM device_limits ORDER BY client_key
	`)
	if err != nil {
		return nil, fmt.Errorf("listing limits: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var l Stored
		if err = rows.Scan(&l.ClientKey, &l.DownloadKbps, &l.UploadKbps, &l.Enabled, &l.UpdatedAt); err != nil {
			return nil, err
		}

		limits = append(limits, l)
	}

	return limits, rows.Err()
}

// Set stores a limit, replacing any previous one for the same device.
func Set(ctx context.Context, db *store.DB, clientKey string, download, upload int) error {
	// Validated before it is stored: a limit nobody can enforce is worse
	// stored than refused, because it reads on the screen as though it works.
	addr, parseErr := netip.ParseAddr(clientKey)
	if parseErr != nil {
		return fmt.Errorf("limits apply to a device's address, and %q is not one", clientKey)
	}

	if err := (Limit{Address: addr, DownloadKbps: download, UploadKbps: upload}).Validate(); err != nil {
		return err
	}

	_, err := db.Writer().ExecContext(ctx, `
		INSERT INTO device_limits (client_key, download_kbps, upload_kbps, enabled, updated_at)
		VALUES (?, ?, ?, 1, datetime('now'))
		ON CONFLICT(client_key) DO UPDATE SET
			download_kbps = excluded.download_kbps,
			upload_kbps   = excluded.upload_kbps,
			enabled       = 1,
			updated_at    = datetime('now')
	`, clientKey, download, upload)
	if err != nil {
		return fmt.Errorf("storing the limit for %s: %w", clientKey, err)
	}

	return nil
}

// Remove deletes a limit.
func Remove(ctx context.Context, db *store.DB, clientKey string) error {
	_, err := db.Writer().ExecContext(ctx, `DELETE FROM device_limits WHERE client_key = ?`, clientKey)

	return err
}

// PlanFrom turns the stored limits into something the kernel can be given.
//
// Anything that is switched off or no longer parses as an address is dropped
// here rather than failing the whole plan: one bad row must not leave every
// other device unshaped.
func PlanFrom(ctx context.Context, db *store.DB, lan, wan string) (Plan, error) {
	stored, err := List(ctx, db)
	if err != nil {
		return Plan{}, err
	}

	plan := Plan{LANInterface: lan, WANInterface: wan}
	for _, s := range stored {
		if !s.Enabled {
			continue
		}

		addr, parseErr := netip.ParseAddr(s.ClientKey)
		if parseErr != nil {
			continue
		}

		plan.Limits = append(plan.Limits, Limit{
			Address:      addr,
			DownloadKbps: s.DownloadKbps,
			UploadKbps:   s.UploadKbps,
		})
	}

	return plan, nil
}
