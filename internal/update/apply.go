package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ErrUnsigned means this build carries no release key.
//
// It is a refusal, not a warning. Without a key there is nothing to check a
// download against, and installing whatever the release server happens to
// serve is precisely the failure this package exists to prevent.
var ErrUnsigned = errors.New("this build has no release key, so an update cannot be verified")

// ErrUnmanaged means something else owns this binary.
var ErrUnmanaged = errors.New("this binary was not installed by the updater")

// Names of the files a staged update is made of. They keep the release's own
// names so that what was downloaded is what is verified, with no renaming step
// in between to get wrong.
const (
	stagedChecksums = "checksums.txt"
	stagedSignature = "checksums.txt.ed25519"
	stagedVersion   = "version"

	// RequestFile is what the privileged installer watches for. It is written
	// last, so it can only appear once everything it refers to is on disk.
	RequestFile = "request"
)

// archSuffix maps Go's architecture names onto the release artefact names.
//
// Only arm differs, and it differs on purpose: the release is built for armv7,
// and a name that silently did not match would turn into a confusing 404 at
// the worst possible moment.
func archSuffix() string {
	if runtime.GOARCH == "arm" {
		return "armv7"
	}

	return runtime.GOARCH
}

func archiveName(version string) string {
	return fmt.Sprintf("seddns_%s_linux_%s.tar.gz", version, archSuffix())
}

// Stage downloads a release, verifies it, and writes it where a privileged
// installer can pick it up.
//
// Downloading and installing are separate because the node must not be able to
// write its own binary: a resolver that can replace the code it runs on next
// boot turns any compromise into a permanent one. This half runs as the
// service user and touches nothing outside its own data directory.
//
// The signature is checked here as well as by the installer. Here it saves
// staging a useless archive; there it is what actually guards the swap, since
// this directory is writable by a process that is exposed to the network.
func (c *Checker) Stage(ctx context.Context, version, dir string) (err error) {
	if len(c.publicKey) == 0 {
		return ErrUnsigned
	}

	base := c.downloadBase + "/v" + version
	name := archiveName(version)

	c.logger.InfoContext(ctx, "downloading update", "version", version, "archive", name)

	archive, err := c.download(ctx, base+"/"+name)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", name, err)
	}

	checksums, err := c.download(ctx, base+"/"+stagedChecksums)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", stagedChecksums, err)
	}

	signature, err := c.download(ctx, base+"/"+stagedSignature)
	if err != nil {
		return fmt.Errorf("downloading the signature: %w", err)
	}

	if err = Verify(archive, checksums, signature, name, c.publicKey); err != nil {
		return err
	}

	// A directory left over from an interrupted attempt would otherwise mix
	// old artefacts with new ones and fail verification for confusing reasons.
	if err = os.RemoveAll(dir); err != nil {
		return fmt.Errorf("clearing the staging directory: %w", err)
	}
	if err = os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("creating the staging directory: %w", err)
	}

	for name, body := range map[string][]byte{
		name:            archive,
		stagedChecksums: checksums,
		stagedSignature: signature,
		stagedVersion:   []byte(version + "\n"),
	} {
		if err = os.WriteFile(filepath.Join(dir, name), body, 0o640); err != nil {
			return fmt.Errorf("staging %s: %w", name, err)
		}
	}

	// Written last: the installer treats this file as the signal that
	// everything it needs is already there.
	if err = os.WriteFile(filepath.Join(dir, RequestFile), []byte(version+"\n"), 0o640); err != nil {
		return fmt.Errorf("writing the request: %w", err)
	}

	c.logger.InfoContext(ctx, "update staged", "version", version, "dir", dir)

	return nil
}

// InstallStaged verifies a staged update again and swaps the binary.
//
// This runs as root, from a unit the service cannot edit, and it re-verifies
// everything. The staging directory is writable by a network-facing process,
// so trusting what is in it would hand that process a way to run code as root
// — the signature is what makes the directory safe to read from.
func InstallStaged(ctx context.Context, dir, binaryPath, configPath string, publicKey []byte) (version string, err error) {
	if len(publicKey) == 0 {
		return "", ErrUnsigned
	}

	raw, err := os.ReadFile(filepath.Join(dir, stagedVersion))
	if err != nil {
		return "", fmt.Errorf("reading the staged version: %w", err)
	}
	version = strings.TrimSpace(string(raw))
	if version == "" {
		return "", errors.New("the staged version is empty")
	}

	name := archiveName(version)

	archive, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return version, fmt.Errorf("reading the staged archive: %w", err)
	}
	checksums, err := os.ReadFile(filepath.Join(dir, stagedChecksums))
	if err != nil {
		return version, fmt.Errorf("reading the staged checksums: %w", err)
	}
	signature, err := os.ReadFile(filepath.Join(dir, stagedSignature))
	if err != nil {
		return version, fmt.Errorf("reading the staged signature: %w", err)
	}

	if err = Verify(archive, checksums, signature, name, publicKey); err != nil {
		return version, err
	}

	binary, err := ExtractBinary(archive, "seddns")
	if err != nil {
		return version, fmt.Errorf("unpacking the archive: %w", err)
	}

	backupPath, err := Install(binaryPath, binary)
	if err != nil {
		return version, fmt.Errorf("installing: %w", err)
	}

	// From here the new binary is already in place, so a failure has to put
	// the old one back rather than leave the node holding something that has
	// not proved it runs.
	if err = HealthGate(ctx, binaryPath, configPath); err != nil {
		if rollbackErr := Rollback(binaryPath, backupPath); rollbackErr != nil {
			return version, fmt.Errorf("%w (and the rollback failed: %w)", err, rollbackErr)
		}

		return version, fmt.Errorf("the new version failed its health check and was rolled back: %w", err)
	}

	return version, nil
}

// ClearStaged removes a staged update, whether it was installed or refused.
//
// Leaving the request file behind would make the installer run again on every
// change to the directory, so this is part of finishing rather than tidying.
func ClearStaged(dir string) error {
	return os.RemoveAll(dir)
}

// download fetches a release asset, bounded so a hostile or broken server
// cannot exhaust memory on a machine with 1 GB of it.
func (c *Checker) download(ctx context.Context, url string) (body []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("User-Agent", "SedDNS/"+c.current)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %s", resp.Status)
	}

	body, err = io.ReadAll(io.LimitReader(resp.Body, maxDownload))
	if err != nil {
		return nil, fmt.Errorf("reading the response: %w", err)
	}

	return body, nil
}
