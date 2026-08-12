package feeds_test

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MmTKya/DNS/internal/feeds"
	"github.com/MmTKya/DNS/internal/filter"
	"github.com/MmTKya/DNS/internal/store"
	"github.com/miekg/dns"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func openDB(t *testing.T) *store.DB {
	t.Helper()

	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "aegisdns.db"))
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	return db
}

func TestCatalogIntegrity(t *testing.T) {
	t.Parallel()

	seen := map[string]bool{}
	defaults := 0

	for _, feed := range feeds.Catalog() {
		if feed.ID == "" || feed.Name == "" || feed.URL == "" {
			t.Errorf("%+v: id, name and url are all required", feed)
		}
		if seen[feed.ID] {
			t.Errorf("duplicate feed id %q", feed.ID)
		}
		seen[feed.ID] = true

		if feed.License == "" {
			t.Errorf("%s: a licence is required so the panel can show it", feed.ID)
		}
		if feed.PollInterval <= 0 {
			t.Errorf("%s: poll interval must be positive", feed.ID)
		}

		// Enabling a non-commercial list by default would put every
		// commercial deployment in breach of its licence.
		if feed.DefaultOn && !feed.CommercialUse {
			t.Errorf("%s: a feed that forbids commercial use must not be enabled by default", feed.ID)
		}
		// Aggressive lists break ordinary browsing; they are opt-in.
		if feed.DefaultOn && feed.HighFalsePositives {
			t.Errorf("%s: a feed known for false positives must not be enabled by default", feed.ID)
		}

		if feed.DefaultOn {
			defaults++
		}
	}

	if defaults == 0 {
		t.Error("no feed is enabled by default; a fresh install would filter nothing")
	}
}

func TestDownloadAndConditionalRefetch(t *testing.T) {
	t.Parallel()

	const body = "||ads.example.com^\n||tracker.example.net^\n"

	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)

		if r.Header.Get("User-Agent") == "" {
			t.Error("a request without a user agent would be rejected by several list maintainers")
		}

		// Honour the validator the client sent back.
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)

			return
		}

		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2026 07:28:00 GMT")
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	dl := feeds.NewDownloader(t.TempDir(), "test", discard())
	feed := feeds.Feed{ID: "test", Name: "Test", URL: srv.URL}

	res, err := dl.Fetch(t.Context(), feed, feeds.State{})
	if err != nil {
		t.Fatalf("first Fetch: %v", err)
	}
	if res.ETag != `"v1"` {
		t.Errorf("etag = %q, want %q", res.ETag, `"v1"`)
	}

	content, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("reading cached feed: %v", err)
	}
	if string(content) != body {
		t.Errorf("cached content = %q, want %q", content, body)
	}

	// The second fetch must send the validator and settle for a 304, which is
	// what keeps a daily poll of a half-million-entry list nearly free.
	_, err = dl.Fetch(t.Context(), feed, feeds.State{ETag: res.ETag})
	if !errors.Is(err, feeds.ErrNotModified) {
		t.Fatalf("second Fetch error = %v, want ErrNotModified", err)
	}
	if got := requests.Load(); got != 2 {
		t.Errorf("server saw %d requests, want 2", got)
	}
}

func TestDownloadGzip(t *testing.T) {
	t.Parallel()

	const body = "||gz.example.com^\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			t.Error("the client must ask for gzip; large lists compress by an order of magnitude")
		}

		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_, _ = io.WriteString(gz, body)
		_ = gz.Close()
	}))
	defer srv.Close()

	dl := feeds.NewDownloader(t.TempDir(), "test", discard())

	res, err := dl.Fetch(t.Context(), feeds.Feed{ID: "gz", URL: srv.URL}, feeds.State{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	content, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("reading cached feed: %v", err)
	}
	if string(content) != body {
		t.Errorf("content = %q, want %q: the gzip stream was not decoded", content, body)
	}
}

func TestDownloadFallsBackToMirror(t *testing.T) {
	t.Parallel()

	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer broken.Close()

	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "||mirror.example.com^\n")
	}))
	defer good.Close()

	dl := feeds.NewDownloader(t.TempDir(), "test", discard())

	res, err := dl.Fetch(t.Context(), feeds.Feed{
		ID:      "mirrored",
		URL:     broken.URL,
		Mirrors: []string{good.URL},
	}, feeds.State{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !res.FromMirror {
		t.Error("the result should record that a mirror served it")
	}
}

func TestDownloadLeavesCacheIntactOnFailure(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	dir := t.TempDir()
	dl := feeds.NewDownloader(dir, "test", discard())

	// Pretend a good copy is already cached.
	const previous = "||known.example.com^\n"
	if err := os.WriteFile(dl.CachePath("test"), []byte(previous), 0o640); err != nil {
		t.Fatalf("seeding cache: %v", err)
	}

	if _, err := dl.Fetch(t.Context(), feeds.Feed{ID: "test", URL: srv.URL}, feeds.State{}); err == nil {
		t.Fatal("Fetch should have failed")
	}

	// A failed download must never replace a good list, or a brief outage
	// would silently unblock everything on it.
	content, err := os.ReadFile(dl.CachePath("test"))
	if err != nil {
		t.Fatalf("reading cache: %v", err)
	}
	if string(content) != previous {
		t.Errorf("cache = %q, want the previous copy %q", content, previous)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading cache dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("a temporary file was left behind: %s", e.Name())
		}
	}
}

func TestSeedIsIdempotent(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	ctx := t.Context()

	if err := feeds.Seed(ctx, db); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	enabled, err := feeds.Enabled(ctx, db)
	if err != nil {
		t.Fatalf("Enabled: %v", err)
	}
	if len(enabled) == 0 {
		t.Fatal("seeding should enable the default feeds")
	}

	// An operator who switches a default feed off must not find it back on
	// after a restart.
	off := enabled[0].ID
	if err = feeds.SetEnabled(ctx, db, off, false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if err = feeds.Seed(ctx, db); err != nil {
		t.Fatalf("second Seed: %v", err)
	}

	after, err := feeds.Enabled(ctx, db)
	if err != nil {
		t.Fatalf("Enabled: %v", err)
	}
	for _, r := range after {
		if r.ID == off {
			t.Errorf("%s was re-enabled by seeding", off)
		}
	}
}

func TestListShowsWholeCatalogue(t *testing.T) {
	t.Parallel()

	db := openDB(t)

	records, err := feeds.List(t.Context(), db)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	// Even before anything is stored, the panel needs the full menu.
	if len(records) != len(feeds.Catalog()) {
		t.Errorf("List returned %d feeds, want %d", len(records), len(feeds.Catalog()))
	}
}

func TestCustomFeedCannotShadowBuiltIn(t *testing.T) {
	t.Parallel()

	db := openDB(t)

	if err := feeds.AddCustom(t.Context(), db, "hagezi-pro", "Fake", "http://example.invalid"); err == nil {
		t.Error("a custom feed must not be allowed to take a built-in id")
	}
}

func TestManagerCompilesCachedFeedsAndUserRules(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	ctx := t.Context()
	dir := t.TempDir()

	dl := feeds.NewDownloader(dir, "test", discard())
	engine := filter.NewEngine()
	mgr := feeds.NewManager(db, dl, engine, discard())

	if err := feeds.AddCustom(ctx, db, "local-list", "Local list", "http://example.invalid"); err != nil {
		t.Fatalf("AddCustom: %v", err)
	}
	if err := os.WriteFile(dl.CachePath("local-list"),
		[]byte("||ads.example.com^\n||tracker.example.net^\n"), 0o640); err != nil {
		t.Fatalf("writing cached feed: %v", err)
	}

	// The operator's own allow rule has to beat the feed's block.
	if _, err := feeds.AddUserRule(ctx, db, "@@||ads.example.com^", "needed for work"); err != nil {
		t.Fatalf("AddUserRule: %v", err)
	}

	if err := mgr.Compile(ctx); err != nil {
		t.Fatalf("Compile: %v", err)
	}

	if res := engine.Match("tracker.example.net", dns.TypeA, ""); res.Action != filter.ActionBlock {
		t.Errorf("tracker: action = %v, want block", res.Action)
	}
	if res := engine.Match("ads.example.com", dns.TypeA, ""); res.Action != filter.ActionAllow {
		t.Errorf("ads: action = %v, want allow (a user rule must win over a feed)", res.Action)
	}

	compile := mgr.LastCompile()
	if compile.Rules < 3 {
		t.Errorf("compiled %d rules, want at least 3", compile.Rules)
	}
	if _, ok := compile.Sources["local-list"]; !ok {
		t.Error("the compile report should name every source")
	}
}

func TestManagerCompileSurvivesMissingCache(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	ctx := t.Context()

	dl := feeds.NewDownloader(t.TempDir(), "test", discard())
	engine := filter.NewEngine()
	mgr := feeds.NewManager(db, dl, engine, discard())

	// A feed that is enabled but has never been downloaded must not stop the
	// others from compiling.
	if err := feeds.AddCustom(ctx, db, "never-fetched", "Never fetched", "http://example.invalid"); err != nil {
		t.Fatalf("AddCustom: %v", err)
	}
	if err := feeds.AddCustom(ctx, db, "present", "Present", "http://example.invalid"); err != nil {
		t.Fatalf("AddCustom: %v", err)
	}
	if err := os.WriteFile(dl.CachePath("present"), []byte("||present.example.com^\n"), 0o640); err != nil {
		t.Fatalf("writing cached feed: %v", err)
	}

	if err := mgr.Compile(ctx); err != nil {
		t.Fatalf("Compile: %v", err)
	}

	if res := engine.Match("present.example.com", dns.TypeA, ""); !res.Matched {
		t.Error("the feed that was present should still have compiled")
	}
}

func TestRefreshRejectsSuspiciousShrink(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	ctx := t.Context()

	full := strings.Repeat("", 0)
	var sb strings.Builder
	for i := range 2000 {
		fmt.Fprintf(&sb, "||host%d.example.com^\n", i)
	}
	full = sb.String()

	serveFull := &atomic.Bool{}
	serveFull.Store(true)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if serveFull.Load() {
			_, _ = io.WriteString(w, full)

			return
		}

		// A maintainer's broken build, or an error page served with a 200.
		_, _ = io.WriteString(w, "||only-one.example.com^\n")
	}))
	defer srv.Close()

	dl := feeds.NewDownloader(t.TempDir(), "test", discard())
	engine := filter.NewEngine()
	mgr := feeds.NewManager(db, dl, engine, discard())

	if err := feeds.AddCustom(ctx, db, "shrinker", "Shrinker", srv.URL); err != nil {
		t.Fatalf("AddCustom: %v", err)
	}

	if err := mgr.Refresh(ctx, true); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	if res := engine.Match("host1500.example.com", dns.TypeA, ""); !res.Matched {
		t.Fatal("the full list should be loaded after the first refresh")
	}

	serveFull.Store(false)
	if err := mgr.Refresh(ctx, true); err != nil {
		t.Fatalf("second Refresh: %v", err)
	}

	// The shrunken update must be rejected and the previous list kept.
	if res := engine.Match("host1500.example.com", dns.TypeA, ""); !res.Matched {
		t.Error("a list that lost most of its entries must not replace the previous copy")
	}

	record, found, err := feeds.Get(ctx, db, "shrinker")
	if err != nil || !found {
		t.Fatalf("Get: found=%t err=%v", found, err)
	}
	if record.LastError == "" {
		t.Error("the rejected update should be visible as an error in the panel")
	}
}
