package store_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/MmTKya/DNS/internal/store"
)

func open(t *testing.T) *store.DB {
	t.Helper()

	// A subdirectory that does not exist yet also covers directory creation.
	path := filepath.Join(t.TempDir(), "data", "aegisdns.db")

	db, err := store.Open(t.Context(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	return db
}

func TestOpenAppliesMigrations(t *testing.T) {
	t.Parallel()

	db := open(t)

	version, err := db.SchemaVersion(t.Context())
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if version < 1 {
		t.Fatalf("schema version = %d, want at least 1", version)
	}

	if err = db.Ping(t.Context()); err != nil {
		t.Errorf("Ping: %v", err)
	}
}

func TestOpenEnablesWAL(t *testing.T) {
	t.Parallel()

	db := open(t)

	var mode string
	if err := db.Reader().QueryRowContext(t.Context(), `PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatalf("querying journal_mode: %v", err)
	}

	// WAL is what keeps SD-card wear and reader/writer contention in check;
	// silently falling back to the rollback journal would be a real regression.
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want %q", mode, "wal")
	}
}

func TestMigrationsAreIdempotent(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "aegisdns.db")
	ctx := context.Background()

	first, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err = first.SetSetting(ctx, "install_id", "abc123"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}

	var appliedFirst int
	if err = first.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_version`).Scan(&appliedFirst); err != nil {
		t.Fatalf("counting schema_version: %v", err)
	}
	if appliedFirst == 0 {
		t.Fatal("no migrations were applied")
	}

	if err = first.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	// Reopening must not re-run migrations or lose data.
	second, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer func() { _ = second.Close() }()

	value, ok, err := second.GetSetting(ctx, "install_id")
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if !ok || value != "abc123" {
		t.Errorf("install_id = %q (ok=%t), want %q", value, ok, "abc123")
	}

	// Comparing against the first open, rather than a literal, keeps this
	// honest as migrations are added.
	var appliedSecond int
	if err = second.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_version`).Scan(&appliedSecond); err != nil {
		t.Fatalf("counting schema_version: %v", err)
	}
	if appliedSecond != appliedFirst {
		t.Errorf("schema_version grew from %d to %d rows: migrations must run exactly once",
			appliedFirst, appliedSecond)
	}
}

func TestSettings(t *testing.T) {
	t.Parallel()

	db := open(t)
	ctx := t.Context()

	if _, ok, err := db.GetSetting(ctx, "missing"); err != nil {
		t.Fatalf("GetSetting: %v", err)
	} else if ok {
		t.Error("a key that was never set must report ok=false")
	}

	if err := db.SetSetting(ctx, "channel", "stable"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if err := db.SetSetting(ctx, "channel", "beta"); err != nil {
		t.Fatalf("SetSetting overwrite: %v", err)
	}

	value, ok, err := db.GetSetting(ctx, "channel")
	if err != nil {
		t.Fatalf("GetSetting: %v", err)
	}
	if !ok || value != "beta" {
		t.Errorf("channel = %q (ok=%t), want %q", value, ok, "beta")
	}

	// An empty value is a real value and must not read back as unset.
	if err = db.SetSetting(ctx, "empty", ""); err != nil {
		t.Fatalf("SetSetting empty: %v", err)
	}
	if value, ok, err = db.GetSetting(ctx, "empty"); err != nil {
		t.Fatalf("GetSetting: %v", err)
	} else if !ok || value != "" {
		t.Errorf(`empty = %q (ok=%t), want "" with ok=true`, value, ok)
	}
}
