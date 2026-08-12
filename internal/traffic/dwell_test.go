package traffic_test

import (
	"testing"
	"time"

	"github.com/MmTKya/DNS/internal/traffic"
)

func at(base time.Time, minutes int) time.Time {
	return base.Add(time.Duration(minutes) * time.Minute)
}

func TestSessionsSplitOnSilence(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 8, 12, 20, 0, 0, 0, time.UTC)

	// Two visits to the same site, an hour apart. Merging them would report an
	// hour of "time on site" that nobody spent.
	queries := []traffic.Query{
		{At: at(base, 0), Client: "192.168.1.5", Host: "www.example.com"},
		{At: at(base, 2), Client: "192.168.1.5", Host: "cdn.example.com"},
		{At: at(base, 5), Client: "192.168.1.5", Host: "api.example.com"},
		{At: at(base, 60), Client: "192.168.1.5", Host: "www.example.com"},
		{At: at(base, 63), Client: "192.168.1.5", Host: "www.example.com"},
	}

	sessions := traffic.Sessions(queries)
	if len(sessions) != 2 {
		t.Fatalf("got %d sessions, want 2", len(sessions))
	}

	if got := sessions[0].Duration(); got != 5*time.Minute {
		t.Errorf("first session lasted %v, want 5m", got)
	}
	if got := sessions[1].Duration(); got != 3*time.Minute {
		t.Errorf("second session lasted %v, want 3m", got)
	}

	// Subdomains are the same visit: a page load resolves several of them.
	if sessions[0].Queries != 3 {
		t.Errorf("first session has %d queries, want 3", sessions[0].Queries)
	}
	if sessions[0].Site != "example.com" {
		t.Errorf("site = %q, want the registrable domain", sessions[0].Site)
	}

	// Nothing here is measured, and the type says so.
	if !sessions[0].Estimated {
		t.Error("sessions must be marked as estimates")
	}
}

func TestSessionsSeparateClientsAndSites(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 8, 12, 20, 0, 0, 0, time.UTC)

	queries := []traffic.Query{
		{At: at(base, 0), Client: "192.168.1.5", Host: "example.com"},
		{At: at(base, 1), Client: "192.168.1.6", Host: "example.com"},
		{At: at(base, 2), Client: "192.168.1.5", Host: "other.example.org"},
	}

	sessions := traffic.Sessions(queries)
	if len(sessions) != 3 {
		t.Fatalf("got %d sessions, want 3: clients and sites must not be merged", len(sessions))
	}
}

func TestSiteUsesThePublicSuffixList(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"www.example.com":     "example.com",
		"a.b.c.example.com":   "example.com",
		"shop.example.co.uk":  "example.co.uk",
		"news.example.com.tr": "example.com.tr",
		"example.com":         "example.com",
		"localhost":           "",
		"":                    "",
	}

	// A naive "last two labels" rule reports "co.uk" as the site, which would
	// merge every British site into one.
	for host, want := range cases {
		if got := traffic.Site(host); got != want {
			t.Errorf("Site(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestSummariseRanksByTime(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 8, 12, 20, 0, 0, 0, time.UTC)

	queries := []traffic.Query{
		{At: at(base, 0), Client: "c", Host: "long.example"},
		{At: at(base, 10), Client: "c", Host: "long.example"},
		{At: at(base, 0), Client: "c", Host: "short.example"},
		{At: at(base, 1), Client: "c", Host: "short.example"},
	}

	sites := traffic.Summarise(traffic.Sessions(queries))
	if len(sites) != 2 {
		t.Fatalf("got %d sites, want 2", len(sites))
	}
	if sites[0].Site != "long.example" {
		t.Errorf("first site = %q, want the one with more time", sites[0].Site)
	}
	if sites[0].Duration != 10*time.Minute {
		t.Errorf("duration = %v, want 10m", sites[0].Duration)
	}
}

func TestCaveatsAreStated(t *testing.T) {
	t.Parallel()

	caveats := traffic.Caveats()
	if len(caveats) < 3 {
		t.Fatalf("got %d caveats, want the limits spelled out", len(caveats))
	}

	// The one that matters most: these numbers are a floor, because a cached
	// name produces no queries at all.
	var mentionsCache, mentionsBandwidth bool
	for _, c := range caveats {
		if contains(c, "cached") {
			mentionsCache = true
		}
		if contains(c, "Bandwidth") {
			mentionsBandwidth = true
		}
	}
	if !mentionsCache {
		t.Error("the caveats must say that caching hides activity")
	}
	if !mentionsBandwidth {
		t.Error("the caveats must say that bandwidth cannot come from DNS")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 ||
		indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}

	return -1
}
