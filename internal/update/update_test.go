package update_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MmTKya/DNS/internal/update"
)

// buildArchive produces a release artefact containing the given binary bytes.
func buildArchive(t *testing.T, binary []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	archive := tar.NewWriter(gz)

	if err := archive.WriteHeader(&tar.Header{
		Name: "seddns", Mode: 0o755, Size: int64(len(binary)), Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatalf("writing header: %v", err)
	}
	if _, err := archive.Write(binary); err != nil {
		t.Fatalf("writing binary: %v", err)
	}
	if err := archive.Close(); err != nil {
		t.Fatalf("closing archive: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("closing gzip: %v", err)
	}

	return buf.Bytes()
}

func checksumFile(archive []byte, name string) []byte {
	sum := sha256.Sum256(archive)

	return []byte(hex.EncodeToString(sum[:]) + "  " + name + "\n")
}

func TestVerifyAcceptsASignedRelease(t *testing.T) {
	t.Parallel()

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	archive := buildArchive(t, []byte("#!/bin/sh\nexit 0\n"))
	checksums := checksumFile(archive, "seddns_1.2.3_linux_amd64.tar.gz")
	signature := ed25519.Sign(private, checksums)

	if err = update.Verify(archive, checksums, signature, "seddns_1.2.3_linux_amd64.tar.gz", public); err != nil {
		t.Errorf("a correctly signed release was rejected: %v", err)
	}
}

func TestVerifyRejectsATamperedArchive(t *testing.T) {
	t.Parallel()

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	archive := buildArchive(t, []byte("original"))
	checksums := checksumFile(archive, "release.tar.gz")
	signature := ed25519.Sign(private, checksums)

	// A compromised mirror serves a perfectly valid TLS connection; only the
	// checksum says anything about what is inside.
	tampered := buildArchive(t, []byte("malicious"))

	err = update.Verify(tampered, checksums, signature, "release.tar.gz", public)
	if !errors.Is(err, update.ErrUnverified) {
		t.Errorf("a tampered archive was accepted: %v", err)
	}
}

func TestVerifyRejectsAForgedChecksumFile(t *testing.T) {
	t.Parallel()

	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	_, attacker, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	archive := buildArchive(t, []byte("malicious"))
	checksums := checksumFile(archive, "release.tar.gz")

	// Signed by someone, just not by the release pipeline. Rewriting the
	// checksum file is exactly what an attacker with mirror access would do.
	signature := ed25519.Sign(attacker, checksums)

	err = update.Verify(archive, checksums, signature, "release.tar.gz", public)
	if !errors.Is(err, update.ErrUnverified) {
		t.Errorf("an archive signed by the wrong key was accepted: %v", err)
	}
}

func TestVerifyRequiresASignatureWhenAKeyIsConfigured(t *testing.T) {
	t.Parallel()

	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	archive := buildArchive(t, []byte("x"))
	checksums := checksumFile(archive, "release.tar.gz")

	if err = update.Verify(archive, checksums, nil, "release.tar.gz", public); !errors.Is(err, update.ErrUnverified) {
		t.Errorf("an unsigned release was accepted despite a configured key: %v", err)
	}
}

func TestVerifyRejectsAMissingChecksumLine(t *testing.T) {
	t.Parallel()

	archive := buildArchive(t, []byte("x"))
	checksums := checksumFile(archive, "some-other-file.tar.gz")

	// No key configured, so only the checksum matters — and there is not one
	// for this artefact.
	if err := update.Verify(archive, checksums, nil, "release.tar.gz", nil); !errors.Is(err, update.ErrUnverified) {
		t.Errorf("an artefact with no published checksum was accepted: %v", err)
	}
}

func TestExtractBinary(t *testing.T) {
	t.Parallel()

	const content = "#!/bin/sh\necho hello\n"
	archive := buildArchive(t, []byte(content))

	binary, err := update.ExtractBinary(archive, "seddns")
	if err != nil {
		t.Fatalf("ExtractBinary: %v", err)
	}
	if string(binary) != content {
		t.Errorf("extracted %q, want %q", binary, content)
	}

	if _, err = update.ExtractBinary(archive, "not-in-here"); err == nil {
		t.Error("extracting a missing file should fail")
	}
}

func TestInstallAndRollback(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "seddns")

	if err := os.WriteFile(binaryPath, []byte("#!/bin/sh\nexit 7\n"), 0o755); err != nil {
		t.Fatalf("writing the original: %v", err)
	}

	backup, err := update.Install(binaryPath, []byte("#!/bin/sh\nexit 0\n"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	installed, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("reading the installed binary: %v", err)
	}
	if !strings.Contains(string(installed), "exit 0") {
		t.Error("the new binary was not installed")
	}

	// The mode has to survive, or the replacement is not executable and the
	// node never comes back.
	info, err := os.Stat(binaryPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("mode = %v, want 0755", info.Mode().Perm())
	}

	// The old one is kept until the new one has proved itself.
	if _, err = os.Stat(backup); err != nil {
		t.Errorf("the previous binary was not kept: %v", err)
	}

	if err = update.Rollback(binaryPath, backup); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	restored, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("reading after rollback: %v", err)
	}
	if !strings.Contains(string(restored), "exit 7") {
		t.Error("the rollback did not restore the previous binary")
	}
}

func TestHealthGateRunsTheNewBinary(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	good := filepath.Join(dir, "good")
	if err := os.WriteFile(good, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("writing: %v", err)
	}

	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("#!/bin/sh\necho broken >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatalf("writing: %v", err)
	}

	if err := update.HealthGate(t.Context(), good, ""); err != nil {
		t.Errorf("a working binary failed the health gate: %v", err)
	}

	// This is what turns "the update installed" into "the update works".
	err := update.HealthGate(t.Context(), bad, "")
	if err == nil {
		t.Fatal("a broken binary passed the health gate")
	}
	if !strings.Contains(err.Error(), "broken") {
		t.Errorf("the failure does not say what went wrong: %v", err)
	}
}

func TestParsePublicKey(t *testing.T) {
	t.Parallel()

	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	parsed, err := update.ParsePublicKey(base64.StdEncoding.EncodeToString(public))
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if !parsed.Equal(public) {
		t.Error("the key did not survive a round trip")
	}

	// An empty key means "no signature checking configured", not an error.
	if key, keyErr := update.ParsePublicKey(""); keyErr != nil || key != nil {
		t.Errorf("an empty key = %v, %v; want nil, nil", key, keyErr)
	}

	for _, bad := range []string{"not-base64!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, keyErr := update.ParsePublicKey(bad); keyErr == nil {
			t.Errorf("ParsePublicKey(%q) accepted an invalid key", bad)
		}
	}
}

func TestArchiveName(t *testing.T) {
	t.Parallel()

	name := update.ArchiveName("1.2.3")
	if !strings.HasPrefix(name, "seddns_1.2.3_") || !strings.HasSuffix(name, ".tar.gz") {
		t.Errorf("archive name = %q, want the release artefact for this platform", name)
	}
}
