// Package sgb talks to Türkiye's national threat feed.
//
// USOM's flat url-list.txt was retired in June 2026 when USOM moved under the
// Cyber Security Directorate; the old URL now redirects to an API.  Products
// still pointed at the text file are quietly fetching nothing, which is why
// this is a native connector rather than another entry in the downloader.
//
// The API needs no authentication, pages through roughly 465,000 records, and
// hands out monotonically increasing ids ordered newest first.  That last
// property is what makes an hourly delta cheap: fetch until an id is already
// known, and stop.
package sgb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// BaseURL is the API root.
const BaseURL = "https://siberguvenlik.gov.tr/api"

// Entry types the API serves.
const (
	TypeDomain  = "domain"
	TypeIP      = "ip"
	TypeURL     = "url"
	TypeIPv6    = "ip6"
	TypeIPv6Net = "ip6net"
)

// Category codes, from the API's own taxonomy endpoint.
const (
	CategoryPhishing        = "PH" // social-engineering phishing
	CategoryBankingPhishing = "BP" // financial-sector phishing
	CategoryMalwareDomain   = "MD" // malware distribution domain
	CategoryMalwareIP       = "MI" // malware distribution address
	CategoryMalwareURL      = "MU" // malware URL
	CategoryC2              = "MC" // command and control
	CategoryAttackSource    = "CA" // scanning and brute-force source
)

// Rate limits published for the API: roughly 20 requests a second and 400 a
// minute.  The client stays well inside both — a full sync is a background
// job, and being a good citizen on a national CERT's infrastructure matters
// more than finishing a minute sooner.
const (
	requestInterval = 200 * time.Millisecond
	maxRetries      = 6
	retryBackoff    = 15 * time.Second
	// The API accepts up to 10,000, but a smaller page keeps memory flat and
	// a failed request cheap to retry.
	PageSize = 1000
)

// Entry is one record.
type Entry struct {
	Value       string
	Type        string
	Category    string
	Source      string
	AddedAt     time.Time
	ID          int64
	Criticality int
}

// Page is one API response.
type Page struct {
	Entries    []Entry
	TotalCount int
	PageCount  int
	Page       int
}

// Client is a rate-limited API client.
type Client struct {
	http      *http.Client
	logger    *slog.Logger
	baseURL   string
	userAgent string

	// lastRequest paces requests without a background goroutine; the syncer is
	// the only caller and it is sequential.
	lastRequest time.Time
}

// NewClient creates a client.
func NewClient(version string, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}

	return &Client{
		http:      &http.Client{Timeout: 60 * time.Second},
		logger:    logger.With("component", "sgb"),
		baseURL:   BaseURL,
		userAgent: fmt.Sprintf("SedDNS/%s (+https://github.com/MmTKya/DNS)", version),
	}
}

// SetBaseURL points the client at another host.  Tests use it.
func (c *Client) SetBaseURL(u string) { c.baseURL = u }

// apiResponse mirrors the API's envelope.  Fields arrive as strings in some
// responses and numbers in others, so the loosely typed ones are decoded by
// hand below.
type apiResponse struct {
	Models []struct {
		ID             json.Number `json:"id"`
		URL            string      `json:"url"`
		Type           string      `json:"type"`
		Desc           string      `json:"desc"`
		Source         string      `json:"source"`
		Date           string      `json:"date"`
		CriticalityLvl json.Number `json:"criticality_level"`
		ConnectionType string      `json:"connectiontype"`
	} `json:"models"`
	TotalCount json.Number `json:"totalCount"`
	Count      json.Number `json:"count"`
	Page       json.Number `json:"page"`
	PageCount  json.Number `json:"pageCount"`
}

// FirstPage is the index of the first page.
//
// The API is one-based: page=0 and page=1 return the same records, and the
// final page is numbered pageCount, not pageCount-1.  Walking 0..pageCount-1
// therefore fetches the first page twice and silently drops the last one.
const FirstPage = 1

// Fetch returns one page of entries of the given type.  Pages are one-based;
// see FirstPage.
func (c *Client) Fetch(ctx context.Context, entryType string, page, perPage int) (result Page, err error) {
	if perPage <= 0 {
		perPage = PageSize
	}

	query := url.Values{}
	query.Set("type", entryType)
	query.Set("page", strconv.Itoa(page))
	query.Set("per-page", strconv.Itoa(perPage))

	endpoint := c.baseURL + "/address/index?" + query.Encode()

	body, err := c.get(ctx, endpoint)
	if err != nil {
		return Page{}, err
	}

	var resp apiResponse
	if err = json.Unmarshal(body, &resp); err != nil {
		return Page{}, fmt.Errorf("decoding %s page %d: %w", entryType, page, err)
	}

	result = Page{
		TotalCount: asInt(resp.TotalCount),
		PageCount:  asInt(resp.PageCount),
		Page:       asInt(resp.Page),
		Entries:    make([]Entry, 0, len(resp.Models)),
	}

	for _, m := range resp.Models {
		value := strings.TrimSpace(strings.ToLower(m.URL))
		if value == "" {
			continue
		}

		entry := Entry{
			ID:          int64(asInt(m.ID)),
			Value:       value,
			Type:        m.Type,
			Category:    m.Desc,
			Source:      m.Source,
			Criticality: asInt(m.CriticalityLvl),
		}

		// "2026-08-11 23:23:05.078547" — not RFC 3339, and not zoned.
		if ts, parseErr := time.Parse("2006-01-02 15:04:05.999999", m.Date); parseErr == nil {
			entry.AddedAt = ts
		}

		result.Entries = append(result.Entries, entry)
	}

	return result, nil
}

// Category describes one taxonomy code.
type Category struct {
	ID      string `json:"id"`
	Title   string `json:"en_title"`
	TitleTR string `json:"tr_title"`
	DescTR  string `json:"tr_desc"`
}

// Categories returns the taxonomy, so the panel can explain a code rather than
// showing "PH".
func (c *Client) Categories(ctx context.Context) (categories []Category, err error) {
	body, err := c.get(ctx, c.baseURL+"/address-description/index")
	if err != nil {
		return nil, err
	}

	var resp struct {
		Models []Category `json:"models"`
	}
	if err = json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decoding categories: %w", err)
	}

	return resp.Models, nil
}

// get performs a paced, retrying request.
func (c *Client) get(ctx context.Context, endpoint string) (body []byte, err error) {
	for attempt := range maxRetries {
		if err = c.pace(ctx); err != nil {
			return nil, err
		}

		body, err = c.attempt(ctx, endpoint)
		if err == nil {
			return body, nil
		}

		var throttled *errThrottled
		if !errors.As(err, &throttled) {
			return nil, err
		}

		// Backing off linearly rather than immediately retrying: the limit is
		// per minute, so hammering it again in a second only prolongs it.
		wait := retryBackoff * time.Duration(attempt+1)
		c.logger.WarnContext(ctx, "rate limited by the threat feed, backing off",
			"wait", wait, "attempt", attempt+1)

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}

	return nil, fmt.Errorf("giving up after %d attempts: %w", maxRetries, err)
}

type errThrottled struct{ status int }

func (e *errThrottled) Error() string { return fmt.Sprintf("rate limited (status %d)", e.status) }

func (c *Client) attempt(ctx context.Context, endpoint string) (body []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")
	// Accept-Encoding is deliberately not set: net/http adds gzip itself and
	// decompresses transparently, but only while the header is untouched.
	// Setting it by hand hands back a compressed body that nothing unwraps.

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusTooManyRequests,
		resp.StatusCode == http.StatusServiceUnavailable:
		return nil, &errThrottled{status: resp.StatusCode}

	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("unexpected status %s from %s", resp.Status, endpoint)
	}

	// 32 MiB is far above any page and far below anything that would hurt.
	body, err = io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return body, nil
}

// pace waits out the minimum interval between requests.
func (c *Client) pace(ctx context.Context) error {
	if wait := requestInterval - time.Since(c.lastRequest); wait > 0 && !c.lastRequest.IsZero() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	c.lastRequest = time.Now()

	return nil
}

func asInt(n json.Number) int {
	v, err := n.Int64()
	if err != nil {
		return 0
	}

	return int(v)
}

// CategoryLabel maps a code onto SedDNS' own vocabulary, so the panel can
// group a national feed's categories with everything else.
func CategoryLabel(code string) string {
	switch code {
	case CategoryPhishing, CategoryBankingPhishing:
		return "phishing"
	case CategoryMalwareDomain, CategoryMalwareIP, CategoryMalwareURL:
		return "malware"
	case CategoryC2:
		return "command-and-control"
	case CategoryAttackSource:
		return "attack-source"
	default:
		return "threat"
	}
}
