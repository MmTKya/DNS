package blockpage_test

import (
	"context"

	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MmTKya/DNS/internal/blockpage"
)

// fetch drives the server the way a browser would: the name it was trying to
// reach arrives in the Host header, not the path.
func fetch(t *testing.T, s *blockpage.Server, host string) (status int, body string) {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = host
	rec := httptest.NewRecorder()

	s.ServeHTTP(rec, req)

	return rec.Code, rec.Body.String()
}

func blocked(host string) (blockpage.Reason, bool) {
	if host == "ads.example.com" {
		return blockpage.Reason{Host: host, Source: "OISD Big", MatchedDomain: "example.com"}, true
	}

	return blockpage.Reason{Host: host}, false
}

// The page has one job: say what was blocked and why, in a browser that just
// failed to load something.
func TestPageNamesTheSiteAndTheReason(t *testing.T) {
	t.Parallel()

	s := blockpage.New(blockpage.Config{}, blocked, nil, nil)

	status, body := fetch(t, s, "ads.example.com")
	if status != http.StatusForbidden {
		t.Errorf("status = %d, want 403", status)
	}
	for _, want := range []string{"ads.example.com", "OISD Big", "example.com", "blocked by SedDNS"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not mention %q", want)
		}
	}
}

// Without the setting there must be no button, or the setting means nothing.
func TestReleaseButtonIsAbsentUntilItIsSwitchedOn(t *testing.T) {
	t.Parallel()

	released := func(context.Context, string) error { return nil }

	off := blockpage.New(blockpage.Config{}, blocked, released, nil)
	if _, body := fetch(t, off, "ads.example.com"); strings.Contains(body, "__seddns/release") {
		t.Error("the page offers a release button while releasing is switched off")
	}

	on := blockpage.New(blockpage.Config{AllowRelease: true}, blocked, released, nil)
	if _, body := fetch(t, on, "ads.example.com"); !strings.Contains(body, "__seddns/release") {
		t.Error("the page has no release button although releasing is switched on")
	}
}

// And the endpoint has to refuse too: a button hidden in the HTML is not a
// setting, it is a decoration.
func TestReleaseEndpointRefusesWhenSwitchedOff(t *testing.T) {
	t.Parallel()

	var called bool
	s := blockpage.New(blockpage.Config{}, blocked, func(context.Context, string) error {
		called = true

		return nil
	}, nil)

	req := httptest.NewRequest(http.MethodPost, "/__seddns/release",
		strings.NewReader("host=ads.example.com"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if called {
		t.Error("a name was released through an endpoint that is switched off")
	}
}

func TestReleaseAllowsTheName(t *testing.T) {
	t.Parallel()

	var got string
	s := blockpage.New(blockpage.Config{AllowRelease: true}, blocked, func(_ context.Context, host string) error {
		got = host

		return nil
	}, nil)

	// As the browser sends it: the name is the site it navigated to.
	req := httptest.NewRequest(http.MethodPost, "/__seddns/release", nil)
	req.Host = "ads.example.com"
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if got != "ads.example.com" {
		t.Errorf("released %q, want ads.example.com", got)
	}
}

// The hole this closes: with releasing switched on, any page on the internet
// could put a form on itself that posts to this node and unblocks whatever it
// named, using a visitor's browser to do it. The name must come from the Host
// header, which a cross-site form cannot set.
func TestReleaseIgnoresTheNameInTheForm(t *testing.T) {
	t.Parallel()

	var got string
	s := blockpage.New(blockpage.Config{AllowRelease: true}, blocked, func(_ context.Context, host string) error {
		got = host

		return nil
	}, nil)

	req := httptest.NewRequest(http.MethodPost, "/__seddns/release",
		strings.NewReader("host=ads.example.com"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// A visitor's browser posting from somewhere else sends that address.
	req.Host = "192.168.1.10"
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if got == "ads.example.com" {
		t.Fatal("a name supplied in the form body was released")
	}
	if rec.Code == http.StatusOK {
		t.Errorf("status = %d; releasing a name that is not blocked should be refused", rec.Code)
	}
}

// A form on another site arrives with that site's origin on it.
func TestReleaseRefusesACrossSiteOrigin(t *testing.T) {
	t.Parallel()

	var called bool
	s := blockpage.New(blockpage.Config{AllowRelease: true}, blocked, func(context.Context, string) error {
		called = true

		return nil
	}, nil)

	req := httptest.NewRequest(http.MethodPost, "/__seddns/release", nil)
	req.Host = "ads.example.com"
	req.Header.Set("Origin", "https://evil.example.net")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if called {
		t.Error("a release was performed for a request from another site")
	}
}

// The page's own form is same-origin with the blocked name.
func TestReleaseAcceptsItsOwnOrigin(t *testing.T) {
	t.Parallel()

	s := blockpage.New(blockpage.Config{AllowRelease: true}, blocked, func(context.Context, string) error {
		return nil
	}, nil)

	req := httptest.NewRequest(http.MethodPost, "/__seddns/release", nil)
	req.Host = "ads.example.com"
	req.Header.Set("Origin", "http://ads.example.com")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

// Reaching this address for something that is not blocked means someone typed
// the node's own address. Showing a block page for a site that is not blocked
// would be a lie.
func TestUnblockedNameIsNotClaimedAsBlocked(t *testing.T) {
	t.Parallel()

	s := blockpage.New(blockpage.Config{}, blocked, nil, nil)

	status, body := fetch(t, s, "github.com")
	if status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", status)
	}
	if strings.Contains(body, "was blocked by") {
		t.Error("a name that is not blocked was presented as blocked")
	}
}
