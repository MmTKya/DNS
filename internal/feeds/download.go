package feeds

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Download limits.  A community blocklist is a few tens of megabytes at most;
// anything larger is a mistake or an attack on the node's disk.
const (
	maxDownloadBytes = 256 << 20
	fetchTimeout     = 5 * time.Minute
)

// ErrNotModified reports that the server answered 304, so the cached copy is
// current.  Most fetches end this way, which is the point of sending
// validators.
var ErrNotModified = errors.New("not modified")

// State is what the node remembers about a feed between fetches.
type State struct {
	ETag         string
	LastModified string
	Bytes        int64
	RuleCount    int
}

// FetchResult describes one download.
//
// Path points at a staged file, not at the live cache.  Nothing replaces the
// copy the resolver is using until Commit is called, which is what lets the
// caller inspect a download — and reject it — before it takes effect.
type FetchResult struct {
	ETag         string
	LastModified string
	Path         string
	Bytes        int64
	FromMirror   bool
}

// Downloader fetches feeds into a cache directory.
type Downloader struct {
	client    *http.Client
	logger    *slog.Logger
	dir       string
	userAgent string
}

// NewDownloader returns a downloader that caches into dir.
func NewDownloader(dir, version string, logger *slog.Logger) *Downloader {
	if logger == nil {
		logger = slog.Default()
	}

	return &Downloader{
		client: &http.Client{
			Timeout: fetchTimeout,
			// Redirects are normal here (GitHub raw, oisd.nl), but a chain
			// this long means something is wrong.
			CheckRedirect: func(_ *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("too many redirects")
				}

				return nil
			},
		},
		// A real, identifying user agent is not politeness theatre: several
		// list maintainers block bare or absent agents outright.
		userAgent: fmt.Sprintf("SedDNS/%s (+https://github.com/MmTKya/DNS)", version),
		dir:       dir,
		logger:    logger.With("component", "feeds"),
	}
}

// CachePath is where a feed's live contents are stored.
func (d *Downloader) CachePath(id string) string {
	return filepath.Join(d.dir, id+".txt")
}

// stagePath is where a download waits until it is committed.
func (d *Downloader) stagePath(id string) string {
	return filepath.Join(d.dir, id+".new")
}

// Commit promotes a staged download to the live cache.  The rename is atomic,
// so a reader either sees the whole old file or the whole new one.
func (d *Downloader) Commit(id string) error {
	if err := os.Rename(d.stagePath(id), d.CachePath(id)); err != nil {
		return fmt.Errorf("installing feed %s: %w", id, err)
	}

	return nil
}

// Discard throws a staged download away, leaving the live cache untouched.
func (d *Downloader) Discard(id string) {
	if err := os.Remove(d.stagePath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		d.logger.Warn("removing discarded download", "feed", id, "err", err)
	}
}

// Fetch downloads a feed, trying its mirrors if the primary URL fails.
//
// It returns ErrNotModified when the server says the cached copy is current,
// which is the common case and costs a single conditional request.
func (d *Downloader) Fetch(ctx context.Context, feed Feed, prev State) (res FetchResult, err error) {
	if err = os.MkdirAll(d.dir, 0o750); err != nil {
		return res, fmt.Errorf("creating feed cache directory: %w", err)
	}

	urls := append([]string{feed.URL}, feed.Mirrors...)

	var errs []error
	for i, url := range urls {
		res, err = d.fetchOne(ctx, feed, url, prev)
		switch {
		case err == nil:
			res.FromMirror = i > 0

			return res, nil
		case errors.Is(err, ErrNotModified):
			return res, err
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return res, err
		}

		errs = append(errs, fmt.Errorf("%s: %w", url, err))
		d.logger.WarnContext(ctx, "feed source failed, trying the next one",
			"feed", feed.ID, "url", url, "err", err)
	}

	return res, fmt.Errorf("every source for %s failed: %w", feed.ID, errors.Join(errs...))
}

func (d *Downloader) fetchOne(ctx context.Context, feed Feed, url string, prev State) (res FetchResult, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return res, fmt.Errorf("building request: %w", err)
	}

	req.Header.Set("User-Agent", d.userAgent)
	// A million-entry list compresses by roughly an order of magnitude, and
	// every enabled feed on every install pays this bandwidth.
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Accept", "text/plain, */*")

	// Validators turn a daily poll of a large list into a 304 with no body.
	if prev.ETag != "" {
		req.Header.Set("If-None-Match", prev.ETag)
	}
	if prev.LastModified != "" {
		req.Header.Set("If-Modified-Since", prev.LastModified)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return res, fmt.Errorf("requesting: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusNotModified:
		return FetchResult{ETag: prev.ETag, LastModified: prev.LastModified}, ErrNotModified

	case resp.StatusCode == http.StatusTooManyRequests:
		return res, fmt.Errorf("rate limited (retry after %q)", resp.Header.Get("Retry-After"))

	case resp.StatusCode != http.StatusOK:
		return res, fmt.Errorf("unexpected status %s", resp.Status)
	}

	body := io.Reader(io.LimitReader(resp.Body, maxDownloadBytes))
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		gz, gzErr := gzip.NewReader(body)
		if gzErr != nil {
			return res, fmt.Errorf("opening gzip stream: %w", gzErr)
		}
		defer func() { _ = gz.Close() }()
		body = gz
	}

	// The download lands in a temporary file and is only staged on success, so
	// a connection that drops halfway can never replace a good list with a
	// truncated one.
	tmp, err := os.CreateTemp(d.dir, feed.ID+".*.tmp")
	if err != nil {
		return res, fmt.Errorf("creating temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()

	written, err := io.Copy(tmp, body)
	if err != nil {
		_ = tmp.Close()

		return res, fmt.Errorf("downloading: %w", err)
	}

	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()

		return res, fmt.Errorf("flushing download: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return res, fmt.Errorf("closing download: %w", err)
	}
	if err = os.Chmod(tmpName, 0o640); err != nil {
		return res, fmt.Errorf("setting permissions: %w", err)
	}

	if written == 0 {
		return res, errors.New("server returned an empty body")
	}

	stage := d.stagePath(feed.ID)
	if err = os.Rename(tmpName, stage); err != nil {
		return res, fmt.Errorf("staging download: %w", err)
	}

	return FetchResult{
		Path:         stage,
		Bytes:        written,
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
	}, nil
}

// Remove deletes a feed's cached contents.
func (d *Downloader) Remove(id string) error {
	err := os.Remove(d.CachePath(id))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing cached feed %s: %w", id, err)
	}

	return nil
}

// jitter spreads scheduled fetches out.
//
// Without it, every SedDNS install started from the same image would poll
// the same GitHub URL at the same second — the node's own users would be a
// distributed denial of service against the list maintainers.
func jitter(interval time.Duration) time.Duration {
	if interval <= 0 {
		return 0
	}

	spread := interval / 10
	if spread <= 0 {
		return interval
	}

	return interval - spread + time.Duration(rand.Int64N(int64(2*spread)))
}
