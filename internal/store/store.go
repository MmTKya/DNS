// Package store owns SedDNS' SQLite persistence.
//
// Two design constraints drive everything here.  First, the target hardware
// often boots from an SD card, so writes must be batched and journalled rather
// than scattered; that is why WAL is mandatory and why later phases aggregate
// query logs instead of keeping every row forever.  Second, the binary must
// stay CGO-free for painless cross-compilation, hence modernc.org/sqlite.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // registers the CGO-free "sqlite" driver
)

// DB is a handle to the node database.  It keeps two pools: writes are
// serialised through a single connection, because SQLite allows only one
// writer and funnelling them here avoids SQLITE_BUSY storms, while reads run
// concurrently against the WAL without blocking that writer.
type DB struct {
	write *sql.DB
	read  *sql.DB
	path  string
}

// maxReadConns bounds the reader pool.  Raspberry Pi class hardware gains
// nothing from a larger pool and every connection costs page cache.
const maxReadConns = 4

// Open opens, or creates, the database at path and applies any pending
// migrations.  The parent directory is created if missing.
func Open(ctx context.Context, path string) (db *DB, err error) {
	if err = os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("creating database directory: %w", err)
	}

	write, err := openPool(path, 1)
	if err != nil {
		return nil, fmt.Errorf("opening write pool: %w", err)
	}

	read, err := openPool(path, maxReadConns)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("opening read pool: %w", err), write.Close())
	}

	db = &DB{write: write, read: read, path: path}

	if err = db.write.PingContext(ctx); err != nil {
		return nil, errors.Join(fmt.Errorf("connecting to %s: %w", path, err), db.Close())
	}

	if err = db.migrate(ctx); err != nil {
		return nil, errors.Join(fmt.Errorf("migrating %s: %w", path, err), db.Close())
	}

	return db, nil
}

// openPool opens a connection pool with the pragmas SedDNS relies on.  The
// pragmas travel in the DSN so that every new connection in the pool gets
// them, not just the first one.
func openPool(path string, maxConns int) (*sql.DB, error) {
	dsn := "file:" + path + "?" +
		// Concurrent readers alongside one writer, and a journal that survives
		// power loss without an fsync per statement.
		"_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		// Wait instead of failing immediately when the writer holds the lock.
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(ON)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(maxConns)
	// SQLite connections are cheap to keep but leak nothing when recycled; an
	// hour keeps long-lived idle handles from pinning stale WAL pages.
	db.SetConnMaxLifetime(time.Hour)

	return db, nil
}

// Writer returns the serialised write pool.  Callers doing more than one
// statement should wrap them in a transaction.
func (db *DB) Writer() *sql.DB { return db.write }

// Reader returns the concurrent read pool.  Never issue writes on it: they
// would contend with the writer and defeat the single-writer discipline.
func (db *DB) Reader() *sql.DB { return db.read }

// Path returns the database file path.
func (db *DB) Path() string { return db.path }

// Ping checks that the database is still usable.  The health endpoint uses it.
func (db *DB) Ping(ctx context.Context) error {
	if err := db.read.PingContext(ctx); err != nil {
		return fmt.Errorf("pinging database: %w", err)
	}

	return nil
}

// Close releases both pools.
func (db *DB) Close() error {
	return errors.Join(db.read.Close(), db.write.Close())
}

// GetSetting reads a value from the settings table.  ok is false when the key
// has never been set, which callers must distinguish from an empty value.
func (db *DB) GetSetting(ctx context.Context, key string) (value string, ok bool, err error) {
	err = db.read.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", false, nil
	case err != nil:
		return "", false, fmt.Errorf("reading setting %q: %w", key, err)
	default:
		return value, true, nil
	}
}

// SetSetting writes a value to the settings table, overwriting any previous
// one.
func (db *DB) SetSetting(ctx context.Context, key, value string) error {
	_, err := db.write.ExecContext(ctx, `
		INSERT INTO settings (key, value, updated_at) VALUES (?, ?, unixepoch())
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
	`, key, value)
	if err != nil {
		return fmt.Errorf("writing setting %q: %w", key, err)
	}

	return nil
}
