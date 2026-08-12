package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
)

// ErrUnsigned means this build carries no release key.
//
// It is a refusal, not a warning. Without a key there is nothing to check a
// download against, and installing whatever the release server happens to
// serve is precisely the failure this package exists to prevent.
var ErrUnsigned = errors.New("this build has no release key, so an update cannot be verified")

// ErrUnmanaged means something else owns this binary.
var ErrUnmanaged = errors.New("this binary was not installed by the updater")

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

// Apply installs the named version over the running binary.
//
// The order is the whole design: verify before unpacking, keep the old binary,
// and make the new one prove it can parse the configuration before the old one
// is let go. Anything that fails after the swap puts the old binary back.
//
// The caller restarts the process; this function deliberately does not, so
// that the decision of how to hand over is made where the lifecycle is owned.
func (c *Checker) Apply(ctx context.Context, version, configPath string) (err error) {
	if len(c.publicKey) == 0 {
		return ErrUnsigned
	}
	if !c.managed() {
		return ErrUnmanaged
	}

	base := c.downloadBase + "/v" + version
	archiveName := fmt.Sprintf("aegisdns_%s_linux_%s.tar.gz", version, archSuffix())

	c.logger.InfoContext(ctx, "downloading update", "version", version, "archive", archiveName)

	archive, err := c.download(ctx, base+"/"+archiveName)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", archiveName, err)
	}

	checksums, err := c.download(ctx, base+"/checksums.txt")
	if err != nil {
		return fmt.Errorf("downloading checksums.txt: %w", err)
	}

	signature, err := c.download(ctx, base+"/checksums.txt.ed25519")
	if err != nil {
		return fmt.Errorf("downloading the signature: %w", err)
	}

	if err = Verify(archive, checksums, signature, archiveName, c.publicKey); err != nil {
		return err
	}

	c.logger.InfoContext(ctx, "update verified", "version", version)

	binary, err := ExtractBinary(archive, "aegisdns")
	if err != nil {
		return fmt.Errorf("unpacking the archive: %w", err)
	}

	backupPath, err := Install(c.binary, binary)
	if err != nil {
		return fmt.Errorf("installing: %w", err)
	}

	// From here the new binary is already in place, so every failure has to
	// put the old one back rather than leave the node holding something that
	// has not proved it runs.
	if err = HealthGate(ctx, c.binary, configPath); err != nil {
		if rollbackErr := Rollback(c.binary, backupPath); rollbackErr != nil {
			return fmt.Errorf("%w (and the rollback failed: %w)", err, rollbackErr)
		}

		c.logger.WarnContext(ctx, "update rolled back: the new binary did not pass its own check", "err", err)

		return fmt.Errorf("the new version failed its health check and was rolled back: %w", err)
	}

	c.logger.InfoContext(ctx, "update installed", "version", version, "previous", backupPath)

	return nil
}

// download fetches a release asset, bounded so a hostile or broken server
// cannot exhaust memory on a machine with 1 GB of it.
func (c *Checker) download(ctx context.Context, url string) (body []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("User-Agent", "AegisDNS/"+c.current)

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
