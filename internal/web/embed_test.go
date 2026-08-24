package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The failure these tests exist for: after an update the panel opened to a
// blank page. Not an error, not a 404 anyone could see — an empty screen,
// which from the sofa is indistinguishable from the whole product being down.
//
// The cause was a browser reusing a cached index.html that referenced an asset
// bundle the update had replaced. Asset names carry a content hash, so the old
// name is genuinely gone, and the page that asks for it renders nothing.

func serve(t *testing.T, path string) *http.Response {
	t.Helper()

	recorder := httptest.NewRecorder()
	Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))

	return recorder.Result()
}

func TestTheEntryPointIsRevalidatedOnEveryLoad(t *testing.T) {
	// Without this, an updated node keeps serving a browser the page that
	// points at bundles it no longer has.
	got := serve(t, "/").Header.Get("Cache-Control")

	if !strings.Contains(got, "no-cache") {
		t.Fatalf("Cache-Control = %q, want it revalidated", got)
	}
	if strings.Contains(got, "immutable") {
		t.Fatalf("Cache-Control = %q, and the entry point is not immutable", got)
	}
}

func TestAClientSideRouteIsAlsoRevalidated(t *testing.T) {
	// A deep link is served the same entry point and must carry the same rule;
	// caching it under its own path would reintroduce the fault one URL at a
	// time.
	if got := serve(t, "/system").Header.Get("Cache-Control"); !strings.Contains(got, "no-cache") {
		t.Fatalf("Cache-Control = %q, want it revalidated", got)
	}
}

func TestHashedAssetsAreKeptForever(t *testing.T) {
	// The other half of the pair. A name that includes a hash of its own
	// contents can never mean two things, so re-fetching it is pure waste —
	// and a panel that refetches every bundle on every load is the reason
	// people cache index.html by hand and get the fault back.
	if !HasPanel() {
		t.Skip("no panel built into this binary")
	}

	// Read the real bundle name out of the page rather than guessing it: the
	// hash changes on every build, and a test that hardcoded one would pass
	// only until the next commit.
	page := serve(t, "/")
	body, err := io.ReadAll(page.Body)
	if err != nil {
		t.Fatal(err)
	}

	asset := assetPath(string(body))
	if asset == "" {
		t.Skip("this build references no hashed assets")
	}

	got := serve(t, asset).Header.Get("Cache-Control")
	if !strings.Contains(got, "immutable") || !strings.Contains(got, "max-age=") {
		t.Fatalf("Cache-Control = %q, want assets kept", got)
	}
}

func TestAMissingBundleIsANotFoundRatherThanThePanel(t *testing.T) {
	// Serving HTML in place of a missing script is worse than a 404: the
	// browser reports a syntax error somewhere inside what it thought was
	// JavaScript, and the actual problem — a stale page asking for a bundle
	// that is gone — never appears anywhere.
	if !HasPanel() {
		t.Skip("no panel built into this binary")
	}

	if got := serve(t, "/assets/index-gone000.js").StatusCode; got != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", got, http.StatusNotFound)
	}
}

// assetPath pulls the first hashed bundle reference out of the page.
func assetPath(page string) string {
	const marker = "/assets/"

	start := strings.Index(page, marker)
	if start < 0 {
		return ""
	}

	end := strings.IndexAny(page[start:], "\"'")
	if end < 0 {
		return ""
	}

	return page[start : start+end]
}
