package sgb_test

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MmTKya/DNS/internal/sgb"
	"github.com/MmTKya/DNS/internal/store"
)

// fakeAPI stands in for the national feed, with the same envelope, the same
// newest-first ordering and the same monotonic ids.
type fakeAPI struct {
	mu       sync.Mutex
	domains  []record
	ips      []record
	requests atomic.Int64
	server   *httptest.Server
}

type record struct {
	ID       int64
	Value    string
	Category string
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()

	api := &fakeAPI{}
	api.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.requests.Add(1)

		if strings.Contains(r.URL.Path, "address-description") {
			_, _ = io.WriteString(w, `{"models":[{"id":"PH","en_title":"Phishing","tr_title":"Oltalama"}]}`)

			return
		}

		entryType := r.URL.Query().Get("type")
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		perPage, _ := strconv.Atoi(r.URL.Query().Get("per-page"))
		if perPage <= 0 {
			perPage = 100
		}

		api.mu.Lock()
		source := api.domains
		if entryType == sgb.TypeIP {
			source = api.ips
		}
		// Newest first, as the real API serves it.
		ordered := make([]record, len(source))
		for i, rec := range source {
			ordered[len(source)-1-i] = rec
		}
		api.mu.Unlock()

		// The real API is one-based and treats page=0 as an alias for page=1.
		// Emulating that is the whole point of this fixture: a zero-based fake
		// hides an off-by-one that silently drops the last page.
		if page < 1 {
			page = 1
		}

		start := (page - 1) * perPage
		if start > len(ordered) {
			start = len(ordered)
		}
		end := min(start+perPage, len(ordered))

		pageCount := (len(ordered) + perPage - 1) / perPage

		models := make([]map[string]any, 0, end-start)
		for _, rec := range ordered[start:end] {
			models = append(models, map[string]any{
				"id":                rec.ID,
				"url":               rec.Value,
				"type":              entryType,
				"desc":              rec.Category,
				"source":            "IH",
				"date":              "2026-08-11 23:23:05.078547",
				"criticality_level": 4,
				"connectiontype":    rec.Category,
			})
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"totalCount": len(ordered),
			"count":      len(models),
			"page":       page,
			"pageCount":  pageCount,
			"models":     models,
		})
	}))
	t.Cleanup(api.server.Close)

	return api
}

func (a *fakeAPI) addDomains(values ...string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	next := int64(len(a.domains) + len(a.ips) + 1)
	for _, v := range values {
		a.domains = append(a.domains, record{ID: next, Value: v, Category: sgb.CategoryPhishing})
		next++
	}
}

func (a *fakeAPI) removeDomain(value string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	kept := a.domains[:0]
	for _, rec := range a.domains {
		if rec.Value != value {
			kept = append(kept, rec)
		}
	}
	a.domains = kept
}

func newSyncer(t *testing.T, api *fakeAPI) (*sgb.Syncer, *store.DB, string) {
	t.Helper()

	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "aegisdns.db"))
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	client := sgb.NewClient("test", logger)
	client.SetBaseURL(api.server.URL)

	dir := t.TempDir()

	return sgb.NewSyncer(client, db, dir, logger), db, dir
}

func TestFullSyncStoresAndExports(t *testing.T) {
	t.Parallel()

	api := newFakeAPI(t)
	api.addDomains("phish1.example", "phish2.example", "phish3.example")

	syncer, db, dir := newSyncer(t, api)

	result, err := syncer.Sync(t.Context(), true)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !result.FullSync {
		t.Error("a forced sync should be a full pass")
	}
	if result.Total != 3 {
		t.Errorf("stored %d entries, want 3", result.Total)
	}

	// The export is what the ordinary feed compiler reads, so it has to be in
	// the syntax the rule parser accepts.
	exported, err := os.ReadFile(filepath.Join(dir, sgb.FeedID+".txt"))
	if err != nil {
		t.Fatalf("reading export: %v", err)
	}
	for _, want := range []string{"||phish1.example^", "||phish2.example^", "||phish3.example^"} {
		if !strings.Contains(string(exported), want) {
			t.Errorf("export is missing %q", want)
		}
	}

	// The category travels with the entry, so the panel can say what kind of
	// threat it is rather than only that something blocked it.
	entry, found, err := sgb.Lookup(t.Context(), db, "phish2.example")
	if err != nil || !found {
		t.Fatalf("Lookup: found=%t err=%v", found, err)
	}
	if entry.Category != sgb.CategoryPhishing {
		t.Errorf("category = %q, want %q", entry.Category, sgb.CategoryPhishing)
	}
}

func TestDeltaSyncOnlyFetchesWhatIsNew(t *testing.T) {
	t.Parallel()

	api := newFakeAPI(t)
	for i := range 250 {
		api.addDomains(fmt.Sprintf("bulk%d.example", i))
	}

	syncer, _, _ := newSyncer(t, api)

	if _, err := syncer.Sync(t.Context(), true); err != nil {
		t.Fatalf("initial Sync: %v", err)
	}

	afterFull := api.requests.Load()
	api.addDomains("brand-new.example")

	result, err := syncer.Sync(t.Context(), false)
	if err != nil {
		t.Fatalf("delta Sync: %v", err)
	}
	if result.FullSync {
		t.Fatal("the second sync should have been a delta")
	}
	if result.Added != 1 {
		t.Errorf("added %d entries, want 1", result.Added)
	}

	// This is the point of tracking the id: an hourly poll of a 465,000-record
	// feed should cost a couple of requests, not hundreds.
	deltaRequests := api.requests.Load() - afterFull
	if deltaRequests > 4 {
		t.Errorf("the delta made %d requests, want a handful", deltaRequests)
	}
}

func TestReconcileRemovesClearedEntries(t *testing.T) {
	t.Parallel()

	api := newFakeAPI(t)
	api.addDomains("cleaned-up.example", "still-bad.example")

	syncer, db, dir := newSyncer(t, api)

	if _, err := syncer.Sync(t.Context(), true); err != nil {
		t.Fatalf("initial Sync: %v", err)
	}

	// A site gets cleaned up and the national CERT removes it. Deltas only
	// ever add, so without the full pass it would stay blocked here forever.
	api.removeDomain("cleaned-up.example")

	result, err := syncer.Sync(t.Context(), true)
	if err != nil {
		t.Fatalf("reconcile Sync: %v", err)
	}
	if result.Removed != 1 {
		t.Errorf("removed %d entries, want 1", result.Removed)
	}

	if _, found, lookupErr := sgb.Lookup(t.Context(), db, "cleaned-up.example"); lookupErr != nil || found {
		t.Errorf("the cleared entry is still present (found=%t err=%v)", found, lookupErr)
	}

	exported, err := os.ReadFile(filepath.Join(dir, sgb.FeedID+".txt"))
	if err != nil {
		t.Fatalf("reading export: %v", err)
	}
	if strings.Contains(string(exported), "cleaned-up.example") {
		t.Error("the export still blocks a name that was cleared upstream")
	}
	if !strings.Contains(string(exported), "still-bad.example") {
		t.Error("the export dropped a name that is still listed")
	}
}

func TestRateLimitIsRespected(t *testing.T) {
	t.Parallel()

	var throttled atomic.Bool
	throttled.Store(true)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if throttled.Swap(false) {
			w.WriteHeader(http.StatusTooManyRequests)

			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"totalCount": 0, "count": 0, "page": 0, "pageCount": 0, "models": []any{},
		})
	}))
	defer srv.Close()

	client := sgb.NewClient("test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	client.SetBaseURL(srv.URL)

	// A 429 has to be waited out rather than hammered; this only checks that
	// the retry happens and succeeds, not the full backoff schedule.
	ctx, cancel := contextWithShortDeadline(t)
	defer cancel()

	if _, err := client.Fetch(ctx, sgb.TypeDomain, 0, 10); err != nil {
		t.Errorf("Fetch after a 429: %v", err)
	}
}

func TestFullSyncFetchesEveryPageExactlyOnce(t *testing.T) {
	t.Parallel()

	api := newFakeAPI(t)

	// A deliberately partial last page: 2,435 records over three pages of
	// 1,000. Walking 0..pageCount-1 would fetch the first page twice and drop
	// the final 435 records entirely.
	const total = 2435
	for i := range total {
		api.addDomains(fmt.Sprintf("page-walk-%d.example", i))
	}

	syncer, db, _ := newSyncer(t, api)

	result, err := syncer.Sync(t.Context(), true)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	if result.Total != total {
		t.Errorf("stored %d records, want all %d", result.Total, total)
	}
	if result.Added != total {
		t.Errorf("fetched %d records, want %d with no page fetched twice", result.Added, total)
	}

	// The last record of the last page is the one an off-by-one loses.
	var stored int
	if err = db.Reader().QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM sgb_entries WHERE value = ?`, "page-walk-0.example").Scan(&stored); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if stored != 1 {
		t.Errorf("the oldest record is missing: it lives on the final page")
	}
}

func TestCategoryLabels(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		sgb.CategoryPhishing:        "phishing",
		sgb.CategoryBankingPhishing: "phishing",
		sgb.CategoryMalwareDomain:   "malware",
		sgb.CategoryC2:              "command-and-control",
		sgb.CategoryAttackSource:    "attack-source",
		"XX":                        "threat",
	}

	for code, want := range cases {
		if got := sgb.CategoryLabel(code); got != want {
			t.Errorf("CategoryLabel(%q) = %q, want %q", code, got, want)
		}
	}
}

// contextWithShortDeadline bounds a retry test so a broken backoff shows up as
// a failure rather than a hung suite.
func contextWithShortDeadline(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()

	return context.WithTimeout(t.Context(), 45*time.Second)
}

func TestGzippedResponseIsDecoded(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			t.Error("the transport should have offered gzip on its own")
		}

		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/json")

		gz := gzip.NewWriter(w)
		_ = json.NewEncoder(gz).Encode(map[string]any{
			"totalCount": 1, "count": 1, "page": 0, "pageCount": 1,
			"models": []map[string]any{{
				"id": 42, "url": "gzipped.example", "type": "domain",
				"desc": "PH", "source": "IH", "date": "2026-08-11 23:23:05.078547",
				"criticality_level": 4, "connectiontype": "PH",
			}},
		})
		_ = gz.Close()
	}))
	defer srv.Close()

	client := sgb.NewClient("test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	client.SetBaseURL(srv.URL)

	// The real API serves gzip. Requesting it by hand would disable Go's
	// transparent decompression and hand back bytes nothing unwraps.
	page, err := client.Fetch(t.Context(), sgb.TypeDomain, 0, 10)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(page.Entries) != 1 || page.Entries[0].Value != "gzipped.example" {
		t.Errorf("entries = %+v, want the decoded record", page.Entries)
	}
}
