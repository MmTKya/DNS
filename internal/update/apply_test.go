package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// fakeRelease builds the three artefacts a real release publishes and serves
// them, so the download path is exercised rather than assumed.
func fakeRelease(t *testing.T, version string, payload []byte) (base string, public ed25519.PublicKey) {
	t.Helper()

	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	if err = tw.WriteHeader(&tar.Header{Name: "aegisdns", Mode: 0o755, Size: int64(len(payload))}); err != nil {
		t.Fatalf("writing the tar header: %v", err)
	}
	if _, err = tw.Write(payload); err != nil {
		t.Fatalf("writing the tar body: %v", err)
	}
	if err = tw.Close(); err != nil {
		t.Fatalf("closing the tar: %v", err)
	}
	if err = gz.Close(); err != nil {
		t.Fatalf("closing the gzip: %v", err)
	}

	archive := buf.Bytes()
	name := fmt.Sprintf("aegisdns_%s_linux_%s.tar.gz", version, archSuffix())

	sum := sha256.Sum256(archive)
	checksums := fmt.Appendf(nil, "%s  %s\n", hex.EncodeToString(sum[:]), name)
	signature := ed25519.Sign(private, checksums)

	prefix := "/v" + version
	mux := http.NewServeMux()
	mux.HandleFunc(prefix+"/"+name, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(archive) })
	mux.HandleFunc(prefix+"/checksums.txt", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(checksums) })
	mux.HandleFunc(prefix+"/checksums.txt.ed25519", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(signature)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return server.URL, public
}

// managedBinary lays out a binary the updater is allowed to replace: a shell
// script standing in for the executable, which the health gate can run.
func managedBinary(t *testing.T, body string) (path, configPath string) {
	t.Helper()

	dir := t.TempDir()
	path = filepath.Join(dir, "aegisdns")

	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("writing the binary: %v", err)
	}

	configPath = filepath.Join(dir, "aegisdns.yaml")
	if err := os.WriteFile(configPath, []byte("mode: dns-only\n"), 0o644); err != nil {
		t.Fatalf("writing the config: %v", err)
	}

	return path, configPath
}

func TestStageThenInstallReplacesTheBinary(t *testing.T) {
	t.Parallel()

	// The "new binary" has to be runnable, because the health gate runs it.
	replacement := "#!/bin/sh\nexit 0\n"

	base, public := fakeRelease(t, "0.2.1", []byte(replacement))
	path, configPath := managedBinary(t, "#!/bin/sh\nexit 0\n")
	staging := filepath.Join(t.TempDir(), "update")

	checker := New("MmTKya/DNS", "0.2.0", path, public, nil)
	checker.downloadBase = base

	if err := checker.Stage(t.Context(), "0.2.1", staging); err != nil {
		t.Fatalf("Stage() error = %v", err)
	}

	// The request file is what the privileged installer waits for, and it must
	// only exist once everything it names is on disk.
	if _, err := os.Stat(filepath.Join(staging, RequestFile)); err != nil {
		t.Fatalf("no request file was written: %v", err)
	}

	version, err := InstallStaged(t.Context(), staging, path, configPath, public)
	if err != nil {
		t.Fatalf("InstallStaged() error = %v", err)
	}
	if version != "0.2.1" {
		t.Errorf("InstallStaged() version = %q, want 0.2.1", version)
	}

	installed, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the installed binary: %v", err)
	}
	if string(installed) != replacement {
		t.Error("the new binary is not at the path the service runs")
	}

	// The old one is kept: a rollback with nothing to roll back to is not a
	// rollback.
	if _, err = os.Stat(path + ".old"); err != nil {
		t.Errorf("the previous binary was not kept: %v", err)
	}
}

// A build with no release key must refuse rather than fall back to trusting
// TLS, which is the failure this package exists to prevent.
func TestApplyRefusesWithoutAReleaseKey(t *testing.T) {
	t.Parallel()

	path, _ := managedBinary(t, "old")

	checker := New("MmTKya/DNS", "0.2.0", path, nil, nil)

	err := checker.Stage(t.Context(), "0.2.1", filepath.Join(t.TempDir(), "update"))
	if !errors.Is(err, ErrUnsigned) {
		t.Fatalf("Stage() error = %v, want ErrUnsigned", err)
	}

	current, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("reading the binary: %v", readErr)
	}
	if string(current) != "old" {
		t.Error("the binary was replaced despite the update being unverifiable")
	}
}

// The signature is checked before anything is written, so a release signed by
// the wrong key must leave the running binary exactly where it was.
func TestApplyLeavesTheBinaryAloneWhenTheSignatureIsForeign(t *testing.T) {
	t.Parallel()

	base, _ := fakeRelease(t, "0.2.1", []byte("#!/bin/sh\nexit 0\n"))

	// A key that never signed anything in this release.
	stranger, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}

	path, _ := managedBinary(t, "old")

	checker := New("MmTKya/DNS", "0.2.0", path, stranger, nil)
	checker.downloadBase = base

	if err = checker.Stage(t.Context(), "0.2.1", filepath.Join(t.TempDir(), "update")); !errors.Is(err, ErrUnverified) {
		t.Fatalf("Stage() error = %v, want ErrUnverified", err)
	}

	current, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("reading the binary: %v", readErr)
	}
	if string(current) != "old" {
		t.Error("a release signed by an unknown key was installed")
	}
	if _, statErr := os.Stat(path + ".old"); statErr == nil {
		t.Error("a backup was taken for an update that should never have started")
	}
}

// The health gate is the difference between "installed" and "works". A binary
// that cannot start must be put back rather than left in place.
func TestApplyRollsBackWhenTheNewBinaryFailsItsCheck(t *testing.T) {
	t.Parallel()

	base, public := fakeRelease(t, "0.2.1", []byte("#!/bin/sh\nexit 1\n"))
	path, configPath := managedBinary(t, "original")

	checker := New("MmTKya/DNS", "0.2.0", path, public, nil)
	checker.downloadBase = base
	staging := filepath.Join(t.TempDir(), "update")

	if err := checker.Stage(t.Context(), "0.2.1", staging); err != nil {
		t.Fatalf("Stage() error = %v", err)
	}

	if _, err := InstallStaged(t.Context(), staging, path, configPath, public); err == nil {
		t.Fatal("InstallStaged() accepted a binary that fails its own check")
	}

	current, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("reading the binary: %v", readErr)
	}
	if string(current) != "original" {
		t.Errorf("the node was left running the broken update: %q", current)
	}
}

// The staging directory is writable by the network-facing process this
// separation exists to contain, so the privileged installer must check what is
// in it rather than trust that Stage put it there. Without this, anything that
// could write that directory would have a way to run code as root.
func TestInstallStagedRejectsATamperedStagingDirectory(t *testing.T) {
	t.Parallel()

	base, public := fakeRelease(t, "0.2.1", []byte("#!/bin/sh\nexit 0\n"))
	path, configPath := managedBinary(t, "original")
	staging := filepath.Join(t.TempDir(), "update")

	checker := New("MmTKya/DNS", "0.2.0", path, public, nil)
	checker.downloadBase = base

	if err := checker.Stage(t.Context(), "0.2.1", staging); err != nil {
		t.Fatalf("Stage() error = %v", err)
	}

	// Corrupt the verified archive, exactly as a compromised service account
	// with write access to this directory would.
	archive := filepath.Join(staging, archiveName("0.2.1"))
	body, err := os.ReadFile(archive)
	if err != nil {
		t.Fatalf("reading the staged archive: %v", err)
	}
	body[len(body)/2] ^= 0xff
	if err = os.WriteFile(archive, body, 0o640); err != nil {
		t.Fatalf("tampering with the staged archive: %v", err)
	}

	if _, err = InstallStaged(t.Context(), staging, path, configPath, public); !errors.Is(err, ErrUnverified) {
		t.Fatalf("InstallStaged() error = %v, want ErrUnverified", err)
	}

	current, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("reading the binary: %v", readErr)
	}
	if string(current) != "original" {
		t.Error("a tampered staging directory replaced the running binary")
	}
}
