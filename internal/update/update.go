// Package update replaces the running binary with a newer one.
//
// Self-update is the feature most likely to turn a working household DNS
// server into a brick, so every step here is arranged around being able to go
// back: the archive is verified before it is unpacked, the configuration is
// snapshotted before anything is replaced, the old binary is kept, and the new
// one has to prove it can start and resolve before the old one is discarded.
//
// TLS is not treated as verification. A compromised mirror or CDN serves a
// perfectly valid TLS connection; only the checksum and the signature over it
// say anything about what is inside.
package update

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Release is an available version.
type Release struct {
	PublishedAt time.Time `json:"published_at"`
	Version     string    `json:"version"`
	Notes       string    `json:"notes,omitempty"`
	URL         string    `json:"url"`
	Prerelease  bool      `json:"prerelease"`
}

// Status is what the panel shows.
type Status struct {
	CheckedAt       time.Time `json:"checked_at,omitzero"`
	Current         string    `json:"current"`
	Latest          string    `json:"latest,omitempty"`
	Notes           string    `json:"notes,omitempty"`
	Error           string    `json:"error,omitempty"`
	UpdateAvailable bool      `json:"update_available"`

	// Managed is false when the binary was not installed by the updater — a
	// distribution package, or a developer build — in which case replacing it
	// underneath the package manager would be rude and confusing.
	Managed bool `json:"managed"`
}

// maxDownload bounds an archive.
const maxDownload = 128 << 20

// Checker finds and installs releases.
type Checker struct {
	logger *slog.Logger
	client *http.Client

	repo      string
	current   string
	binary    string
	publicKey ed25519.PublicKey

	// downloadBase is where release assets are fetched from. Only the tests
	// change it; production always talks to the release host.
	downloadBase string
}

// New creates a checker for the given repository.
func New(repo, current, binaryPath string, publicKey ed25519.PublicKey, logger *slog.Logger) *Checker {
	if logger == nil {
		logger = slog.Default()
	}

	return &Checker{
		logger:       logger.With("component", "update"),
		client:       &http.Client{Timeout: 10 * time.Minute},
		repo:         repo,
		current:      current,
		binary:       binaryPath,
		publicKey:    publicKey,
		downloadBase: "https://github.com/" + repo + "/releases/download",
	}
}

// Check asks the release server what is available.
func (c *Checker) Check(ctx context.Context) (status Status, err error) {
	status = Status{
		Current:   c.current,
		CheckedAt: time.Now(),
		Managed:   c.managed(),
	}

	// A build with no stamped version came from a developer's machine; there
	// is nothing sensible to compare against.
	if c.current == "dev" || c.current == "" {
		status.Error = "this build has no version stamp, so updates are not offered"

		return status, nil
	}

	release, err := c.latest(ctx)
	if err != nil {
		status.Error = err.Error()

		return status, err
	}

	status.Latest = release.Version
	status.Notes = release.Notes
	status.UpdateAvailable = newer(release.Version, c.current)

	return status, nil
}

// managed reports whether this binary looks like one the updater installed.
func (c *Checker) managed() bool {
	if c.binary == "" {
		return false
	}

	// A binary under a package manager's control should be updated by it.
	for _, prefix := range []string{"/usr/bin/", "/bin/", "/snap/"} {
		if strings.HasPrefix(c.binary, prefix) {
			return false
		}
	}

	return true
}

func (c *Checker) latest(ctx context.Context) (release Release, err error) {
	url := "https://api.github.com/repos/" + c.repo + "/releases/latest"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Release{}, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "AegisDNS/"+c.current)

	resp, err := c.client.Do(req)
	if err != nil {
		return Release{}, fmt.Errorf("checking for updates: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return Release{}, fmt.Errorf("release server returned %s", resp.Status)
	}

	var payload struct {
		TagName     string `json:"tag_name"`
		Body        string `json:"body"`
		Prerelease  bool   `json:"prerelease"`
		PublishedAt string `json:"published_at"`
		HTMLURL     string `json:"html_url"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&payload); err != nil {
		return Release{}, fmt.Errorf("decoding the release: %w", err)
	}

	release = Release{
		Version:    strings.TrimPrefix(payload.TagName, "v"),
		Notes:      payload.Body,
		Prerelease: payload.Prerelease,
		URL:        payload.HTMLURL,
	}
	if ts, parseErr := time.Parse(time.RFC3339, payload.PublishedAt); parseErr == nil {
		release.PublishedAt = ts
	}

	return release, nil
}

// newer compares dotted versions.
//
// Deliberately simple: releases here are numeric triples, and a full semver
// implementation would be more code than the thing it guards.
func newer(candidate, current string) bool {
	candidateParts := versionParts(candidate)
	currentParts := versionParts(current)

	for i := range max(len(candidateParts), len(currentParts)) {
		var a, b int
		if i < len(candidateParts) {
			a = candidateParts[i]
		}
		if i < len(currentParts) {
			b = currentParts[i]
		}

		if a != b {
			return a > b
		}
	}

	return false
}

func versionParts(version string) (parts []int) {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	// Anything after a hyphen is a prerelease tag, which this does not rank.
	if idx := strings.IndexByte(version, '-'); idx >= 0 {
		version = version[:idx]
	}

	for _, field := range strings.Split(version, ".") {
		var value int
		if _, err := fmt.Sscan(field, &value); err != nil {
			return parts
		}
		parts = append(parts, value)
	}

	return parts
}

// ErrUnverified means the download did not match its checksum or signature.
var ErrUnverified = errors.New("the download could not be verified")

// Verify checks an archive against a signed checksum file.
//
// Both halves matter: the checksum file says what the archive should hash to,
// and the signature says the checksum file came from the release pipeline. A
// checksum alone protects against a corrupt download, not a malicious one.
func Verify(archive []byte, checksums []byte, signature []byte, archiveName string, publicKey ed25519.PublicKey) error {
	if len(publicKey) > 0 {
		if len(signature) == 0 {
			return fmt.Errorf("%w: no signature was published", ErrUnverified)
		}
		if !ed25519.Verify(publicKey, checksums, signature) {
			return fmt.Errorf("%w: the checksum file is not signed by the release key", ErrUnverified)
		}
	}

	sum := sha256.Sum256(archive)
	want := hex.EncodeToString(sum[:])

	for line := range strings.Lines(string(checksums)) {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 2 {
			continue
		}

		if strings.TrimPrefix(fields[1], "*") == archiveName {
			if fields[0] == want {
				return nil
			}

			return fmt.Errorf("%w: %s hashes to %s, the release says %s",
				ErrUnverified, archiveName, want, fields[0])
		}
	}

	return fmt.Errorf("%w: no checksum was published for %s", ErrUnverified, archiveName)
}

// ParsePublicKey reads a base64-encoded Ed25519 release key.
func ParsePublicKey(encoded string) (key ed25519.PublicKey, err error) {
	if strings.TrimSpace(encoded) == "" {
		return nil, nil
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("decoding the release key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("the release key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}

	return raw, nil
}

// ExtractBinary pulls the executable out of a release archive.
func ExtractBinary(archive []byte, name string) (binary []byte, err error) {
	gz, err := gzip.NewReader(strings.NewReader(string(archive)))
	if err != nil {
		return nil, fmt.Errorf("opening the archive: %w", err)
	}
	defer func() { _ = gz.Close() }()

	reader := tar.NewReader(gz)
	for {
		header, nextErr := reader.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return nil, fmt.Errorf("reading the archive: %w", nextErr)
		}

		if header.Typeflag != tar.TypeReg || filepath.Base(header.Name) != name {
			continue
		}

		binary, err = io.ReadAll(io.LimitReader(reader, maxDownload))
		if err != nil {
			return nil, fmt.Errorf("reading the binary: %w", err)
		}

		return binary, nil
	}

	return nil, fmt.Errorf("the archive does not contain %q", name)
}

// Install replaces the running binary, keeping the old one for rollback.
//
// The write-then-rename is what makes this safe: a partially written
// executable is never at the path anything runs, and the old file stays until
// the new one has proved itself.
func Install(binaryPath string, binary []byte) (backupPath string, err error) {
	info, err := os.Stat(binaryPath)
	if err != nil {
		return "", fmt.Errorf("reading the current binary: %w", err)
	}

	dir := filepath.Dir(binaryPath)

	tmp, err := os.CreateTemp(dir, filepath.Base(binaryPath)+".new.*")
	if err != nil {
		return "", fmt.Errorf("creating the new binary: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err = tmp.Write(binary); err != nil {
		_ = tmp.Close()

		return "", fmt.Errorf("writing the new binary: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()

		return "", fmt.Errorf("flushing the new binary: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return "", fmt.Errorf("closing the new binary: %w", err)
	}
	if err = os.Chmod(tmpName, info.Mode()); err != nil {
		return "", fmt.Errorf("setting permissions: %w", err)
	}

	backupPath = binaryPath + ".old"
	if err = os.Rename(binaryPath, backupPath); err != nil {
		return "", fmt.Errorf("keeping the current binary: %w", err)
	}

	if err = os.Rename(tmpName, binaryPath); err != nil {
		// Put the old one back rather than leaving nothing at the path.
		_ = os.Rename(backupPath, binaryPath)

		return "", fmt.Errorf("installing the new binary: %w", err)
	}

	return backupPath, nil
}

// Rollback restores the previous binary.
func Rollback(binaryPath, backupPath string) error {
	if _, err := os.Stat(backupPath); err != nil {
		return fmt.Errorf("no backup to roll back to: %w", err)
	}

	if err := os.Rename(backupPath, binaryPath); err != nil {
		return fmt.Errorf("restoring the previous binary: %w", err)
	}

	return nil
}

// HealthGate runs the newly installed binary and asks it to validate itself.
//
// This is what turns "the update installed" into "the update works". A binary
// that cannot even parse the configuration it is about to run with has no
// business replacing one that could.
func HealthGate(ctx context.Context, binaryPath, configPath string) error {
	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	args := []string{"--version"}
	if configPath != "" {
		args = []string{"--config", configPath, "--check-config"}
	}

	output, err := exec.CommandContext(checkCtx, binaryPath, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("the new binary failed its health check: %w: %s",
			err, strings.TrimSpace(string(output)))
	}

	return nil
}

// ArchiveName is the release artefact for this platform.
func ArchiveName(version string) string {
	arch := runtime.GOARCH
	if arch == "arm" {
		arch = "armv7"
	}

	return fmt.Sprintf("aegisdns_%s_%s_%s.tar.gz", version, runtime.GOOS, arch)
}
