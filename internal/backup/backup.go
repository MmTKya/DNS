// Package backup exports and restores everything that makes a node itself.
//
// One archive serves three purposes, which is why it is worth doing properly:
// it is the operator's backup, it is the payload a replica receives from the
// primary, and it is the snapshot taken before a self-update so a bad release
// can be rolled back to a known-good state.
//
// The archive deliberately does not contain the query log. History is large,
// node-specific, and reconstructing it on a replica would be wrong: two nodes
// answering the same network each saw a different half of it.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/MmTKya/DNS/internal/config"
	"github.com/MmTKya/DNS/internal/store"
)

// FormatVersion is the archive layout version.  Restoring an archive from a
// future version is refused rather than half-applied.
const FormatVersion = 1

// maxArchiveBytes bounds a restore.  An archive arrives over the network
// during replication, so it is untrusted input.
const maxArchiveBytes = 256 << 20

// Manifest describes an archive.
type Manifest struct {
	CreatedAt     time.Time `json:"created_at"`
	NodeID        string    `json:"node_id"`
	Version       string    `json:"version"`
	FormatVersion int       `json:"format_version"`
	SchemaVersion int       `json:"schema_version"`

	// Revision and Hash identify this configuration state.  Replication
	// compares them to decide whether anything needs sending at all.
	Revision int64  `json:"revision"`
	Hash     string `json:"hash"`

	// ContainsSecrets records whether password hashes, two-factor secrets and
	// API keys are inside.  The panel warns on download when they are, because
	// the file is then as sensitive as the node itself.
	ContainsSecrets bool `json:"contains_secrets"`

	Tables map[string]int `json:"tables"`
}

// Options control what an export includes.
type Options struct {
	// IncludeSecrets carries users, sessions-worth of credentials and API keys.
	// Replication needs them — a replica that cannot authenticate the same
	// people is not a replica. A backup an operator emails to themselves may
	// not want them.
	IncludeSecrets bool

	// ConfigPath is the YAML file to embed.  Empty skips it.
	ConfigPath string

	NodeID  string
	Version string
}

// exportedTables are copied verbatim, in dependency order.
//
// The query log and its aggregates are excluded on purpose: they are large,
// they are specific to what this node happened to see, and a replica inheriting
// them would be claiming a history it does not have.
var exportedTables = []string{
	"settings",
	"feeds",
	"user_rules",
	"clients",
	"sgb_entries",
	"intel_suggestions",
}

// secretTables hold credentials and are included only with IncludeSecrets.
var secretTables = []string{
	"users",
	"recovery_codes",
}

// secretSettings are the keys within settings that carry credentials.
var secretSettings = []string{
	"intel.abusech_key",
	"intel.safebrowsing_key",
	"intel.otx_key",
	"cluster.token",
}

// Export writes an archive to w.
func Export(ctx context.Context, db *store.DB, w io.Writer, opts Options) (manifest Manifest, err error) {
	gz := gzip.NewWriter(w)
	defer func() {
		if closeErr := gz.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("closing archive: %w", closeErr)
		}
	}()

	archive := tar.NewWriter(gz)
	defer func() {
		if closeErr := archive.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("closing archive: %w", closeErr)
		}
	}()

	schemaVersion, err := db.SchemaVersion(ctx)
	if err != nil {
		return Manifest{}, err
	}

	manifest = Manifest{
		FormatVersion:   FormatVersion,
		CreatedAt:       time.Now().UTC(),
		NodeID:          opts.NodeID,
		Version:         opts.Version,
		SchemaVersion:   schemaVersion,
		ContainsSecrets: opts.IncludeSecrets,
		Tables:          map[string]int{},
	}

	tables := append([]string{}, exportedTables...)
	if opts.IncludeSecrets {
		tables = append(tables, secretTables...)
	}

	// Hashed as it goes, so the manifest can identify this exact state without
	// a second pass over the data.
	hasher := sha256.New()

	for _, table := range tables {
		rows, dumpErr := dumpTable(ctx, db, table, opts.IncludeSecrets)
		if dumpErr != nil {
			return Manifest{}, dumpErr
		}

		encoded, marshalErr := json.Marshal(rows)
		if marshalErr != nil {
			return Manifest{}, fmt.Errorf("encoding %s: %w", table, marshalErr)
		}

		hasher.Write([]byte(table))
		hasher.Write(encoded)

		if err = writeFile(archive, "tables/"+table+".json", encoded); err != nil {
			return Manifest{}, err
		}
		manifest.Tables[table] = len(rows)
	}

	if opts.ConfigPath != "" {
		raw, readErr := os.ReadFile(opts.ConfigPath)
		switch {
		case readErr == nil:
			hasher.Write(raw)
			if err = writeFile(archive, "config.yaml", raw); err != nil {
				return Manifest{}, err
			}
		case !os.IsNotExist(readErr):
			return Manifest{}, fmt.Errorf("reading config: %w", readErr)
		}
	}

	manifest.Hash = hex.EncodeToString(hasher.Sum(nil))

	encodedManifest, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Manifest{}, fmt.Errorf("encoding manifest: %w", err)
	}

	// The manifest is written last so its hash can cover everything, and read
	// first on import because tar readers stream: see Import, which buffers.
	if err = writeFile(archive, "manifest.json", encodedManifest); err != nil {
		return Manifest{}, err
	}

	return manifest, nil
}

// ImportOptions control a restore.
type ImportOptions struct {
	// ConfigPath is where an embedded config.yaml is written.  Empty discards
	// it, which is what replication wants when the peer's listeners differ.
	ConfigPath string

	// DryRun validates the archive and reports what it holds without touching
	// anything.
	DryRun bool
}

// Import restores an archive.
//
// The restore is one transaction: a half-applied backup would leave a node in a
// state that never existed, which is worse than a failed restore.
func Import(ctx context.Context, db *store.DB, r io.Reader, opts ImportOptions) (manifest Manifest, err error) {
	gz, err := gzip.NewReader(io.LimitReader(r, maxArchiveBytes))
	if err != nil {
		return Manifest{}, fmt.Errorf("opening archive: %w", err)
	}
	defer func() { _ = gz.Close() }()

	files := map[string][]byte{}

	archive := tar.NewReader(gz)
	for {
		header, nextErr := archive.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return Manifest{}, fmt.Errorf("reading archive: %w", nextErr)
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}

		// Path traversal in an archive that arrives over the network is the
		// classic way to write outside the directory you meant to.
		name := strings.TrimPrefix(header.Name, "./")
		if strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
			return Manifest{}, fmt.Errorf("archive contains an unsafe path %q", header.Name)
		}

		content, readErr := io.ReadAll(io.LimitReader(archive, maxArchiveBytes))
		if readErr != nil {
			return Manifest{}, fmt.Errorf("reading %s: %w", name, readErr)
		}
		files[name] = content
	}

	raw, ok := files["manifest.json"]
	if !ok {
		return Manifest{}, fmt.Errorf("archive has no manifest")
	}
	if err = json.Unmarshal(raw, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("decoding manifest: %w", err)
	}

	if manifest.FormatVersion > FormatVersion {
		return manifest, fmt.Errorf(
			"archive uses format version %d, this build understands up to %d — upgrade before restoring",
			manifest.FormatVersion, FormatVersion)
	}

	schemaVersion, err := db.SchemaVersion(ctx)
	if err != nil {
		return manifest, err
	}
	if manifest.SchemaVersion > schemaVersion {
		return manifest, fmt.Errorf(
			"archive was made on schema version %d, this node is on %d — upgrade before restoring",
			manifest.SchemaVersion, schemaVersion)
	}

	if opts.DryRun {
		return manifest, nil
	}

	if err = restoreTables(ctx, db, files); err != nil {
		return manifest, err
	}

	if opts.ConfigPath != "" {
		if raw, ok = files["config.yaml"]; ok {
			// Refusing to write a config the node cannot start with is the
			// difference between a failed restore and an unbootable node.
			if err = validateConfig(raw); err != nil {
				return manifest, err
			}
			if err = os.WriteFile(opts.ConfigPath, raw, 0o640); err != nil {
				return manifest, fmt.Errorf("writing config: %w", err)
			}
		}
	}

	return manifest, nil
}

func validateConfig(raw []byte) error {
	tmp, err := os.CreateTemp("", "aegisdns-restore-*.yaml")
	if err != nil {
		return fmt.Errorf("checking config: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()

	if _, err = tmp.Write(raw); err != nil {
		_ = tmp.Close()

		return fmt.Errorf("checking config: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("checking config: %w", err)
	}

	if _, err = config.Load(name); err != nil {
		return fmt.Errorf("the archive's configuration is not valid: %w", err)
	}

	return nil
}

func restoreTables(ctx context.Context, db *store.DB, files map[string][]byte) (err error) {
	tx, err := db.Writer().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w (rollback: %v)", err, tx.Rollback())
		}
	}()

	names := make([]string, 0, len(files))
	for name := range files {
		if strings.HasPrefix(name, "tables/") && strings.HasSuffix(name, ".json") {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	for _, name := range names {
		table := strings.TrimSuffix(strings.TrimPrefix(name, "tables/"), ".json")
		if !known(table) {
			// An unknown table in an archive is a newer node's data, not
			// something to guess at.
			continue
		}

		var rows []map[string]any
		if err = json.Unmarshal(files[name], &rows); err != nil {
			return fmt.Errorf("decoding %s: %w", table, err)
		}

		if _, err = tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return fmt.Errorf("clearing %s: %w", table, err)
		}

		for _, row := range rows {
			columns := make([]string, 0, len(row))
			for column := range row {
				columns = append(columns, column)
			}
			sort.Strings(columns)

			placeholders := make([]string, len(columns))
			values := make([]any, len(columns))
			for i, column := range columns {
				placeholders[i] = "?"
				values[i] = normalise(row[column])
			}

			query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
				table, strings.Join(columns, ", "), strings.Join(placeholders, ", "))

			if _, err = tx.ExecContext(ctx, query, values...); err != nil {
				return fmt.Errorf("restoring a row of %s: %w", table, err)
			}
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("committing restore: %w", err)
	}

	return nil
}

// normalise converts JSON's numbers back into something SQLite will store as
// an integer rather than a float, which matters for ids and timestamps.
func normalise(value any) any {
	number, ok := value.(float64)
	if !ok {
		return value
	}

	if number == float64(int64(number)) {
		return int64(number)
	}

	return number
}

func known(table string) bool {
	for _, t := range append(append([]string{}, exportedTables...), secretTables...) {
		if t == table {
			return true
		}
	}

	return false
}

func dumpTable(ctx context.Context, db *store.DB, table string, includeSecrets bool) (out []map[string]any, err error) {
	rows, err := db.Reader().QueryContext(ctx, "SELECT * FROM "+table)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()

	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("reading columns of %s: %w", table, err)
	}

	for rows.Next() {
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}

		if err = rows.Scan(pointers...); err != nil {
			return nil, fmt.Errorf("scanning %s: %w", table, err)
		}

		record := make(map[string]any, len(columns))
		for i, column := range columns {
			value := values[i]
			// []byte would be base64-encoded by encoding/json and come back as
			// a string that no longer matches what was stored.
			if raw, isBytes := value.([]byte); isBytes {
				value = string(raw)
			}
			record[column] = value
		}

		if table == "settings" && !includeSecrets {
			if key, isString := record["key"].(string); isString && isSecretSetting(key) {
				continue
			}
		}

		out = append(out, record)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating %s: %w", table, err)
	}

	if out == nil {
		out = []map[string]any{}
	}

	return out, nil
}

func isSecretSetting(key string) bool {
	for _, secret := range secretSettings {
		if key == secret {
			return true
		}
	}

	return false
}

func writeFile(archive *tar.Writer, name string, content []byte) error {
	if err := archive.WriteHeader(&tar.Header{
		Name:    name,
		Mode:    0o600,
		Size:    int64(len(content)),
		ModTime: time.Now(),
	}); err != nil {
		return fmt.Errorf("writing %s header: %w", name, err)
	}

	if _, err := archive.Write(content); err != nil {
		return fmt.Errorf("writing %s: %w", name, err)
	}

	return nil
}
