package backup_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MmTKya/DNS/internal/backup"
	"github.com/MmTKya/DNS/internal/config"
	"github.com/MmTKya/DNS/internal/feeds"
	"github.com/MmTKya/DNS/internal/store"
)

func openDB(t *testing.T) *store.DB {
	t.Helper()

	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "seddns.db"))
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	return db
}

// seed puts recognisable state into a node.
func seed(t *testing.T, db *store.DB) {
	t.Helper()
	ctx := t.Context()

	if err := feeds.Seed(ctx, db); err != nil {
		t.Fatalf("seeding feeds: %v", err)
	}
	if _, err := feeds.AddUserRule(ctx, db, "||seeded.example^", "from the test"); err != nil {
		t.Fatalf("adding rule: %v", err)
	}
	if err := db.SetSetting(ctx, "install_id", "node-a"); err != nil {
		t.Fatalf("setting: %v", err)
	}
	if err := db.SetSetting(ctx, "intel.otx_key", "super-secret"); err != nil {
		t.Fatalf("setting: %v", err)
	}
	if _, err := db.Writer().ExecContext(ctx, `
		INSERT INTO users (username, password_hash, role, created_at) VALUES ('admin', 'hash', 'admin', 1)
	`); err != nil {
		t.Fatalf("inserting user: %v", err)
	}
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	source := openDB(t)
	seed(t, source)

	var archive bytes.Buffer
	manifest, err := backup.Export(t.Context(), source, &archive, backup.Options{
		IncludeSecrets: true,
		NodeID:         "node-a",
		Version:        "test",
	})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if manifest.Hash == "" {
		t.Error("the manifest must identify the state it captured")
	}
	if manifest.Tables["user_rules"] != 1 {
		t.Errorf("manifest says %d user rules, want 1", manifest.Tables["user_rules"])
	}

	// Restore into a different, empty node.
	target := openDB(t)
	restored, err := backup.Import(t.Context(), target, bytes.NewReader(archive.Bytes()), backup.ImportOptions{})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if restored.Hash != manifest.Hash {
		t.Errorf("hash = %q, want %q", restored.Hash, manifest.Hash)
	}

	rules, err := feeds.ListUserRules(t.Context(), target)
	if err != nil {
		t.Fatalf("ListUserRules: %v", err)
	}
	if len(rules) != 1 || rules[0].Rule != "||seeded.example^" {
		t.Errorf("rules = %+v, want the seeded one", rules)
	}

	value, ok, err := target.GetSetting(t.Context(), "install_id")
	if err != nil || !ok || value != "node-a" {
		t.Errorf("install_id = %q (ok=%t, err=%v), want node-a", value, ok, err)
	}

	var users int
	if err = target.Reader().QueryRowContext(t.Context(), `SELECT COUNT(*) FROM users`).Scan(&users); err != nil {
		t.Fatalf("counting users: %v", err)
	}
	if users != 1 {
		t.Errorf("restored %d users, want 1: a replica that cannot authenticate the same people is not a replica", users)
	}
}

func TestExportWithoutSecrets(t *testing.T) {
	t.Parallel()

	source := openDB(t)
	seed(t, source)

	var archive bytes.Buffer
	manifest, err := backup.Export(t.Context(), source, &archive, backup.Options{IncludeSecrets: false})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if manifest.ContainsSecrets {
		t.Error("the manifest must not claim to carry secrets when it does not")
	}

	// The archive is a file people email to themselves; an API key must not be
	// sitting in it unannounced. Searching the compressed bytes would find
	// nothing either way, so this decompresses first.
	// Positive control first: without it, a broken search would make the
	// negative assertion below pass no matter what the archive held.
	if !archiveContains(t, archive.Bytes(), "seeded.example") {
		t.Fatal("the search cannot find data that is definitely in the archive")
	}
	if archiveContains(t, archive.Bytes(), "super-secret") {
		t.Error("an API key leaked into a secret-free archive")
	}
	if _, present := manifest.Tables["users"]; present {
		t.Error("credentials were exported despite IncludeSecrets being false")
	}

	target := openDB(t)
	if _, err = backup.Import(t.Context(), target, bytes.NewReader(archive.Bytes()), backup.ImportOptions{}); err != nil {
		t.Fatalf("Import: %v", err)
	}

	if _, ok, _ := target.GetSetting(t.Context(), "intel.otx_key"); ok {
		t.Error("the API key was restored from a secret-free archive")
	}
	// Everything else still arrives.
	if value, ok, _ := target.GetSetting(t.Context(), "install_id"); !ok || value != "node-a" {
		t.Errorf("install_id = %q, want it restored", value)
	}
}

func TestConfigTravelsAndIsValidated(t *testing.T) {
	t.Parallel()

	source := openDB(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "seddns.yaml")

	cfg := config.Default()
	cfg.DNS.Listen = []string{"127.0.0.1:5353"}
	if err := cfg.Write(cfgPath); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	var archive bytes.Buffer
	if _, err := backup.Export(t.Context(), source, &archive, backup.Options{ConfigPath: cfgPath}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	target := openDB(t)
	restoredPath := filepath.Join(t.TempDir(), "restored.yaml")
	if _, err := backup.Import(t.Context(), target, bytes.NewReader(archive.Bytes()),
		backup.ImportOptions{ConfigPath: restoredPath}); err != nil {
		t.Fatalf("Import: %v", err)
	}

	restored, err := config.Load(restoredPath)
	if err != nil {
		t.Fatalf("the restored config does not load: %v", err)
	}
	if restored.DNS.Listen[0] != "127.0.0.1:5353" {
		t.Errorf("listen = %v, want the archived value", restored.DNS.Listen)
	}
}

func TestImportRejectsNewerFormat(t *testing.T) {
	t.Parallel()

	source := openDB(t)

	var archive bytes.Buffer
	if _, err := backup.Export(t.Context(), source, &archive, backup.Options{}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	// Claim a future format. Byte-replacing the compressed archive would find
	// nothing, so the archive is rebuilt.
	var tampered bytes.Buffer
	writeManifestArchive(t, &tampered, `{"format_version":9,"schema_version":1}`)

	target := openDB(t)
	_, err := backup.Import(t.Context(), target, &tampered, backup.ImportOptions{})
	if err == nil {
		t.Fatal("an archive from a newer format must be refused, not half-applied")
	}
	if !strings.Contains(err.Error(), "format version") {
		t.Errorf("error = %v, want it to name the version mismatch", err)
	}
}

func TestDryRunChangesNothing(t *testing.T) {
	t.Parallel()

	source := openDB(t)
	seed(t, source)

	var archive bytes.Buffer
	if _, err := backup.Export(t.Context(), source, &archive, backup.Options{}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	target := openDB(t)
	if _, err := backup.Import(t.Context(), target, bytes.NewReader(archive.Bytes()),
		backup.ImportOptions{DryRun: true}); err != nil {
		t.Fatalf("Import: %v", err)
	}

	rules, err := feeds.ListUserRules(t.Context(), target)
	if err != nil {
		t.Fatalf("ListUserRules: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("a dry run wrote %d rules", len(rules))
	}
}

func TestImportRejectsUnsafePaths(t *testing.T) {
	t.Parallel()

	// A crafted archive arrives over the network during replication, so path
	// traversal has to be refused rather than trusted.
	var archive bytes.Buffer
	writeUnsafeArchive(t, &archive)

	target := openDB(t)
	if _, err := backup.Import(t.Context(), target, &archive, backup.ImportOptions{}); err == nil {
		t.Fatal("an archive with a traversal path must be refused")
	}
}

func TestRestoreIsAtomic(t *testing.T) {
	t.Parallel()

	target := openDB(t)
	ctx := t.Context()

	// Existing state that a failed restore must not destroy.
	if _, err := feeds.AddUserRule(ctx, target, "||existing.example^", "before"); err != nil {
		t.Fatalf("AddUserRule: %v", err)
	}

	var archive bytes.Buffer
	writeCorruptTableArchive(t, &archive)

	if _, err := backup.Import(ctx, target, &archive, backup.ImportOptions{}); err == nil {
		t.Fatal("a corrupt archive must fail the restore")
	}

	rules, err := feeds.ListUserRules(ctx, target)
	if err != nil {
		t.Fatalf("ListUserRules: %v", err)
	}
	// A half-applied backup leaves a node in a state that never existed.
	if len(rules) != 1 {
		t.Errorf("after a failed restore there are %d rules, want the original 1", len(rules))
	}
}

// archiveContains reports whether the decompressed archive holds needle.
func archiveContains(t *testing.T, data []byte, needle string) bool {
	t.Helper()

	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("opening archive: %v", err)
	}
	defer func() { _ = gz.Close() }()

	plain, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("reading archive: %v", err)
	}

	return bytes.Contains(plain, []byte(needle))
}

// writeManifestArchive builds an archive containing only the given manifest.
func writeManifestArchive(t *testing.T, w *bytes.Buffer, manifest string) {
	t.Helper()

	gz := gzip.NewWriter(w)
	archive := tar.NewWriter(gz)

	if err := archive.WriteHeader(&tar.Header{
		Name: "manifest.json", Mode: 0o600, Size: int64(len(manifest)),
	}); err != nil {
		t.Fatalf("writing header: %v", err)
	}
	if _, err := archive.Write([]byte(manifest)); err != nil {
		t.Fatalf("writing manifest: %v", err)
	}

	if err := archive.Close(); err != nil {
		t.Fatalf("closing archive: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("closing gzip: %v", err)
	}
}

// writeUnsafeArchive builds an archive whose member escapes the target
// directory.
func writeUnsafeArchive(t *testing.T, w *bytes.Buffer) {
	t.Helper()

	gz := gzip.NewWriter(w)
	archive := tar.NewWriter(gz)

	add := func(name string, content []byte) {
		if err := archive.WriteHeader(&tar.Header{
			Name: name, Mode: 0o600, Size: int64(len(content)),
		}); err != nil {
			t.Fatalf("writing header: %v", err)
		}
		if _, err := archive.Write(content); err != nil {
			t.Fatalf("writing content: %v", err)
		}
	}

	add("../../etc/passwd", []byte("root:x:0:0"))
	add("manifest.json", []byte(`{"format_version":1}`))

	if err := archive.Close(); err != nil {
		t.Fatalf("closing archive: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("closing gzip: %v", err)
	}
}

// writeCorruptTableArchive builds a valid-looking archive whose table data will
// fail on insert.
func writeCorruptTableArchive(t *testing.T, w *bytes.Buffer) {
	t.Helper()

	gz := gzip.NewWriter(w)
	archive := tar.NewWriter(gz)

	add := func(name string, content []byte) {
		if err := archive.WriteHeader(&tar.Header{
			Name: name, Mode: 0o600, Size: int64(len(content)),
		}); err != nil {
			t.Fatalf("writing header: %v", err)
		}
		if _, err := archive.Write(content); err != nil {
			t.Fatalf("writing content: %v", err)
		}
	}

	// A column that does not exist: the insert fails part-way through the
	// transaction, which is exactly the case atomicity has to cover.
	add("tables/user_rules.json", []byte(`[{"id":1,"rule":"||x^","enabled":1,"comment":"","created_at":1,"no_such_column":"x"}]`))
	add("manifest.json", []byte(`{"format_version":1,"schema_version":1}`))

	if err := archive.Close(); err != nil {
		t.Fatalf("closing archive: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("closing gzip: %v", err)
	}
}
