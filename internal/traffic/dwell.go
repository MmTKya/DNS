// Package traffic turns query history into an estimate of what devices were
// doing, and is careful about the word "estimate".
//
// A DNS server sees names, not bytes and not time. What it can honestly do is
// cluster queries: a burst of lookups for a site and its assets, then silence,
// then another burst, looks like two visits. That inference is useful and it is
// also wrong in specific, knowable ways, so every number this package produces
// is labelled as an estimate and the limits are stated in the type itself
// rather than left for the UI to remember.
//
// Real byte counters and real session timing need gateway mode, where the
// packets actually cross the node.
package traffic

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/MmTKya/DNS/internal/store"
	"golang.org/x/net/publicsuffix"
)

// sessionGap is the silence that ends a visit.
//
// Fifteen minutes is long enough to survive a browser's cached DNS (most
// resolvers hold an answer for five to ten minutes, during which a device
// browsing a site asks nothing at all) and short enough that two evening
// visits do not merge into one.
const sessionGap = 15 * time.Minute

// Query is one recorded lookup, reduced to what the inference needs.
type Query struct {
	At     time.Time
	Client string
	Host   string
}

// Session is an inferred visit.
type Session struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`

	// Site is the registrable domain, so "cdn.example.com" and
	// "www.example.com" are recognised as the same visit.
	Site   string `json:"site"`
	Client string `json:"client"`

	Queries int `json:"queries"`

	// Estimated is always true, and is serialised so the panel cannot
	// accidentally present this as a measurement.
	Estimated bool `json:"estimated"`
}

// Duration is the span between the first and last query of the visit.
//
// It systematically understates: a device that loaded a page and then read it
// for twenty minutes without resolving anything looks like a zero-length
// visit. It cannot overstate by much, which makes it a floor rather than a
// guess.
func (s Session) Duration() time.Duration { return s.End.Sub(s.Start) }

// SiteTime is the estimated time a client spent on one site.
type SiteTime struct {
	Site      string        `json:"site"`
	Duration  time.Duration `json:"duration_ns"`
	Sessions  int           `json:"sessions"`
	Queries   int           `json:"queries"`
	LastVisit time.Time     `json:"last_visit"`
	Estimated bool          `json:"estimated"`
}

// Report is what the panel shows for a client.
type Report struct {
	Client string     `json:"client"`
	Sites  []SiteTime `json:"sites"`
	From   time.Time  `json:"from"`
	To     time.Time  `json:"to"`

	// Caveats are shown with the numbers, not buried in documentation. A
	// figure whose limits the reader does not know is worse than no figure.
	Caveats []string `json:"caveats"`
}

// Caveats describes what these numbers cannot tell you.
func Caveats() []string {
	return []string{
		"Estimated from DNS queries, not measured.",
		"A cached name produces no queries, so quiet reading time is missed and durations are a floor.",
		"A device using its own encrypted DNS does not appear here at all.",
		"Bandwidth cannot be derived from DNS: ten seconds and three hours of video look identical.",
	}
}

// Sessions groups queries into inferred visits.
//
// The input does not need to be sorted; it is sorted here, because callers
// reading from a database index and callers holding a ring buffer disagree
// about order and neither should have to care.
func Sessions(queries []Query) []Session {
	byKey := map[string][]Query{}

	for _, q := range queries {
		site := Site(q.Host)
		if site == "" {
			continue
		}
		key := q.Client + "\x00" + site
		byKey[key] = append(byKey[key], q)
	}

	var sessions []Session

	for key, group := range byKey {
		client, site, _ := strings.Cut(key, "\x00")

		sort.Slice(group, func(i, j int) bool { return group[i].At.Before(group[j].At) })

		current := Session{
			Client:    client,
			Site:      site,
			Start:     group[0].At,
			End:       group[0].At,
			Queries:   1,
			Estimated: true,
		}

		for _, q := range group[1:] {
			if q.At.Sub(current.End) > sessionGap {
				sessions = append(sessions, current)
				current = Session{
					Client:    client,
					Site:      site,
					Start:     q.At,
					End:       q.At,
					Queries:   1,
					Estimated: true,
				}

				continue
			}

			current.End = q.At
			current.Queries++
		}

		sessions = append(sessions, current)
	}

	sort.Slice(sessions, func(i, j int) bool { return sessions[i].Start.Before(sessions[j].Start) })

	return sessions
}

// Summarise collapses sessions into per-site totals.
func Summarise(sessions []Session) []SiteTime {
	bySite := map[string]*SiteTime{}

	for _, s := range sessions {
		entry, ok := bySite[s.Site]
		if !ok {
			entry = &SiteTime{Site: s.Site, Estimated: true}
			bySite[s.Site] = entry
		}

		entry.Duration += s.Duration()
		entry.Sessions++
		entry.Queries += s.Queries
		if s.End.After(entry.LastVisit) {
			entry.LastVisit = s.End
		}
	}

	sites := make([]SiteTime, 0, len(bySite))
	for _, entry := range bySite {
		sites = append(sites, *entry)
	}

	// Most time first, then most queries: a site with many short visits is
	// still interesting even when the inferred duration is near zero.
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].Duration != sites[j].Duration {
			return sites[i].Duration > sites[j].Duration
		}

		return sites[i].Queries > sites[j].Queries
	})

	return sites
}

// Site returns the registrable domain, so every subdomain of a site counts as
// the same visit.
//
// The public suffix list is what makes this correct for the cases a naive
// "last two labels" rule gets wrong — co.uk, com.tr, and every other
// multi-label suffix.
func Site(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || !strings.Contains(host, ".") {
		return ""
	}

	site, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return host
	}

	return site
}

// ClientReport builds a report for one client from stored history.
func ClientReport(ctx context.Context, db *store.DB, client string, since time.Time, limit int) (report Report, err error) {
	if limit <= 0 || limit > 200 {
		limit = 25
	}

	rows, err := db.Reader().QueryContext(ctx, `
		SELECT ts, client, host FROM query_log
		WHERE client = ? AND ts >= ? AND verdict IN ('allowed', 'rewritten')
		ORDER BY ts
	`, client, since.Unix())
	if err != nil {
		return Report{}, fmt.Errorf("reading history: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var queries []Query
	for rows.Next() {
		var (
			ts   int64
			q    Query
			host string
		)
		if err = rows.Scan(&ts, &q.Client, &host); err != nil {
			return Report{}, fmt.Errorf("scanning history: %w", err)
		}

		q.At = time.Unix(ts, 0)
		q.Host = host
		queries = append(queries, q)
	}

	if err = rows.Err(); err != nil {
		return Report{}, fmt.Errorf("iterating history: %w", err)
	}

	sites := Summarise(Sessions(queries))
	if len(sites) > limit {
		sites = sites[:limit]
	}

	return Report{
		Client:  client,
		Sites:   sites,
		From:    since,
		To:      time.Now(),
		Caveats: Caveats(),
	}, nil
}
