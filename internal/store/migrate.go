package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

// migrationFS holds the schema history.  Files are named "<version>_<name>.sql"
// with a zero-padded, strictly increasing version, and are applied in order.
//
// Migrations are append-only: once a file has shipped it must never be edited,
// because nodes in the field have already run it.  Fix a mistake with a new
// migration.
//
//go:embed migrations/*.sql
var migrationFS embed.FS

type migration struct {
	name    string
	sql     string
	version int
}

// migrate applies every migration the database has not seen yet.  Each one runs
// in its own transaction together with the bookkeeping row, so an interrupted
// upgrade can be resumed rather than leaving a half-applied schema.
func (db *DB) migrate(ctx context.Context) error {
	if _, err := db.write.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_version (
			version    INTEGER PRIMARY KEY,
			name       TEXT    NOT NULL,
			applied_at INTEGER NOT NULL
		)
	`); err != nil {
		return fmt.Errorf("creating schema_version: %w", err)
	}

	applied, err := db.appliedVersions(ctx)
	if err != nil {
		return err
	}

	migrations, err := loadMigrations()
	if err != nil {
		return err
	}

	for _, m := range migrations {
		if applied[m.version] {
			continue
		}

		if err = db.apply(ctx, m); err != nil {
			return fmt.Errorf("applying migration %04d_%s: %w", m.version, m.name, err)
		}
	}

	return nil
}

func (db *DB) apply(ctx context.Context, m migration) (err error) {
	tx, err := db.write.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w (rollback: %v)", err, tx.Rollback())
		}
	}()

	if _, err = tx.ExecContext(ctx, m.sql); err != nil {
		return fmt.Errorf("executing statements: %w", err)
	}

	if _, err = tx.ExecContext(ctx,
		`INSERT INTO schema_version (version, name, applied_at) VALUES (?, ?, unixepoch())`,
		m.version, m.name,
	); err != nil {
		return fmt.Errorf("recording version: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("committing: %w", err)
	}

	return nil
}

func (db *DB) appliedVersions(ctx context.Context) (applied map[int]bool, err error) {
	rows, err := db.write.QueryContext(ctx, `SELECT version FROM schema_version`)
	if err != nil {
		return nil, fmt.Errorf("reading schema_version: %w", err)
	}
	defer func() { _ = rows.Close() }()

	applied = map[int]bool{}
	for rows.Next() {
		var v int
		if err = rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("scanning schema_version: %w", err)
		}
		applied[v] = true
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating schema_version: %w", err)
	}

	return applied, nil
}

// SchemaVersion returns the highest migration applied to the database, or 0 for
// a database that has none.  The health endpoint and the future backup format
// report it.
func (db *DB) SchemaVersion(ctx context.Context) (version int, err error) {
	var v sql.NullInt64
	if err = db.read.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_version`).Scan(&v); err != nil {
		return 0, fmt.Errorf("reading schema version: %w", err)
	}

	return int(v.Int64), nil
}

func loadMigrations() (migrations []migration, err error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("reading embedded migrations: %w", err)
	}

	seen := map[int]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}

		version, name, ok := parseMigrationName(e.Name())
		if !ok {
			return nil, fmt.Errorf("migration %q must be named <version>_<name>.sql", e.Name())
		}

		if prev, dup := seen[version]; dup {
			return nil, fmt.Errorf("migrations %q and %q share version %d", prev, e.Name(), version)
		}
		seen[version] = e.Name()

		body, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("reading migration %q: %w", e.Name(), err)
		}

		migrations = append(migrations, migration{
			version: version,
			name:    name,
			sql:     string(body),
		})
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].version < migrations[j].version
	})

	return migrations, nil
}

func parseMigrationName(filename string) (version int, name string, ok bool) {
	base := strings.TrimSuffix(filename, ".sql")

	prefix, rest, found := strings.Cut(base, "_")
	if !found || rest == "" {
		return 0, "", false
	}

	version, err := strconv.Atoi(prefix)
	if err != nil || version <= 0 {
		return 0, "", false
	}

	return version, rest, true
}
