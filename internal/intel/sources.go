// Package intel asks external sources what they know about a domain.
//
// Every source here is free, and every free source is rate-limited, so the
// design is defensive: local knowledge is consulted first and costs nothing,
// remote lookups are cached for days, and a source with no API key configured
// simply reports that it has nothing to say rather than failing the request.
//
// Note on HYAS, which is often suggested for this role: HYAS Insight and HYAS
// Protect are commercial, there is no free public API or downloadable feed,
// and the "at home" programme moved to Silent Push after the 2025 acquisition.
// It is not something a self-hosted node can ingest, so it is not here.
package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MmTKya/DNS/internal/sgb"
	"github.com/MmTKya/DNS/internal/store"
)

// Finding is one source's opinion.
type Finding struct {
	Source    string `json:"source"`
	Category  string `json:"category,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Reference string `json:"reference,omitempty"`
	Score     int    `json:"score"`
	Malicious bool   `json:"malicious"`
}

// Source is one place to ask about a domain.
type Source interface {
	// Name identifies the source in findings and in the panel.
	Name() string

	// Configured reports whether the source can be used at all.  Most need an
	// API key the operator has to supply.
	Configured() bool

	// Lookup returns a finding, or nil when the source knows nothing.
	Lookup(ctx context.Context, domain string) (*Finding, error)
}

// httpClient is shared by the remote sources.  The timeout is short: this runs
// behind a query the user is waiting on nothing for, but a slow source must
// not hold a worker.
var httpClient = &http.Client{Timeout: 15 * time.Second}

// --- local sources ---

// SGBSource answers from the national feed already synced to disk.  It is the
// cheapest source there is: a local index lookup, no network, no rate limit.
type SGBSource struct {
	DB *store.DB
}

// Name implements Source.
func (s *SGBSource) Name() string { return "usom-sgb" }

// Configured implements Source.
func (s *SGBSource) Configured() bool { return s.DB != nil }

// Lookup implements Source.
func (s *SGBSource) Lookup(ctx context.Context, domain string) (*Finding, error) {
	entry, found, err := sgb.Lookup(ctx, s.DB, domain)
	if err != nil || !found {
		return nil, err
	}

	// A national CERT listing is strong evidence: these are reported,
	// reviewed and published by the state's own incident response team.
	return &Finding{
		Source:    s.Name(),
		Malicious: true,
		Score:     70,
		Category:  sgb.CategoryLabel(entry.Category),
		Detail: fmt.Sprintf("listed by USOM as %s (criticality %d)",
			sgb.CategoryLabel(entry.Category), entry.Criticality),
		Reference: "https://siberguvenlik.gov.tr",
	}, nil
}

// --- abuse.ch ---

// URLhausSource queries abuse.ch's malware URL database.
//
// abuse.ch introduced mandatory authentication in 2025; the key is free from
// auth.abuse.ch but must be supplied by the operator.
type URLhausSource struct {
	AuthKey string
}

// Name implements Source.
func (s *URLhausSource) Name() string { return "urlhaus" }

// Configured implements Source.
func (s *URLhausSource) Configured() bool { return s.AuthKey != "" }

// Lookup implements Source.
func (s *URLhausSource) Lookup(ctx context.Context, domain string) (*Finding, error) {
	body := url.Values{"host": {domain}}

	var result struct {
		QueryStatus string `json:"query_status"`
		URLs        []struct {
			Threat    string `json:"threat"`
			URLStatus string `json:"url_status"`
		} `json:"urls"`
	}

	if err := s.post(ctx, "https://urlhaus-api.abuse.ch/v1/host/", body, &result); err != nil {
		return nil, err
	}

	if result.QueryStatus != "ok" || len(result.URLs) == 0 {
		return nil, nil
	}

	// An entry that is still online is a live threat; a taken-down one is
	// history and should weigh less.
	online := 0
	for _, u := range result.URLs {
		if u.URLStatus == "online" {
			online++
		}
	}

	score := 45
	detail := fmt.Sprintf("%d malware URLs recorded", len(result.URLs))
	if online > 0 {
		score = 75
		detail = fmt.Sprintf("%d malware URLs, %d still online", len(result.URLs), online)
	}

	return &Finding{
		Source:    s.Name(),
		Malicious: true,
		Score:     score,
		Category:  "malware",
		Detail:    detail,
		Reference: "https://urlhaus.abuse.ch/host/" + domain + "/",
	}, nil
}

func (s *URLhausSource) post(ctx context.Context, endpoint string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Auth-Key", s.AuthKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("querying %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("%s rejected the auth key", endpoint)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %s", endpoint, resp.Status)
	}

	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
}

// ThreatFoxSource queries abuse.ch's indicator-of-compromise database, which
// is where command-and-control domains show up first.
type ThreatFoxSource struct {
	AuthKey string
}

// Name implements Source.
func (s *ThreatFoxSource) Name() string { return "threatfox" }

// Configured implements Source.
func (s *ThreatFoxSource) Configured() bool { return s.AuthKey != "" }

// Lookup implements Source.
func (s *ThreatFoxSource) Lookup(ctx context.Context, domain string) (*Finding, error) {
	payload, err := json.Marshal(map[string]any{
		"query":       "search_ioc",
		"search_term": domain,
	})
	if err != nil {
		return nil, fmt.Errorf("encoding request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://threatfox-api.abuse.ch/api/v1/", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Auth-Key", s.AuthKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying threatfox: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("threatfox returned %s", resp.Status)
	}

	var result struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			ThreatType       string `json:"threat_type"`
			MalwarePrintable string `json:"malware_printable"`
			Confidence       int    `json:"confidence_level"`
		} `json:"data"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding threatfox response: %w", err)
	}

	if result.QueryStatus != "ok" || len(result.Data) == 0 {
		return nil, nil
	}

	first := result.Data[0]
	score := 60
	if first.Confidence >= 75 {
		score = 80
	}

	detail := first.ThreatType
	if first.MalwarePrintable != "" {
		detail = fmt.Sprintf("%s (%s)", first.ThreatType, first.MalwarePrintable)
	}

	return &Finding{
		Source:    s.Name(),
		Malicious: true,
		Score:     score,
		Category:  "command-and-control",
		Detail:    detail,
		Reference: "https://threatfox.abuse.ch/browse.php?search=ioc%3A" + url.QueryEscape(domain),
	}, nil
}

// --- Google Safe Browsing ---

// SafeBrowsingSource queries Google's Safe Browsing lookup API, which is the
// same data a browser's own warning page uses.
type SafeBrowsingSource struct {
	APIKey string
}

// Name implements Source.
func (s *SafeBrowsingSource) Name() string { return "safe-browsing" }

// Configured implements Source.
func (s *SafeBrowsingSource) Configured() bool { return s.APIKey != "" }

// Lookup implements Source.
func (s *SafeBrowsingSource) Lookup(ctx context.Context, domain string) (*Finding, error) {
	payload, err := json.Marshal(map[string]any{
		"client": map[string]string{"clientId": "aegisdns", "clientVersion": "1.0"},
		"threatInfo": map[string]any{
			"threatTypes": []string{
				"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
			},
			"platformTypes":    []string{"ANY_PLATFORM"},
			"threatEntryTypes": []string{"URL"},
			"threatEntries": []map[string]string{
				{"url": "http://" + domain + "/"},
				{"url": "https://" + domain + "/"},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("encoding request: %w", err)
	}

	endpoint := "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + url.QueryEscape(s.APIKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying safe browsing: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("safe browsing returned %s", resp.Status)
	}

	var result struct {
		Matches []struct {
			ThreatType string `json:"threatType"`
		} `json:"matches"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding safe browsing response: %w", err)
	}

	if len(result.Matches) == 0 {
		return nil, nil
	}

	category := "malware"
	if strings.Contains(result.Matches[0].ThreatType, "SOCIAL_ENGINEERING") {
		category = "phishing"
	}

	return &Finding{
		Source:    s.Name(),
		Malicious: true,
		Score:     80,
		Category:  category,
		Detail:    "Google Safe Browsing: " + strings.ToLower(strings.ReplaceAll(result.Matches[0].ThreatType, "_", " ")),
		Reference: "https://transparencyreport.google.com/safe-browsing/search?url=" + url.QueryEscape(domain),
	}, nil
}

// --- AlienVault OTX ---

// OTXSource queries the AlienVault Open Threat Exchange, a community feed
// whose "pulses" are contributed by researchers.
type OTXSource struct {
	APIKey string
}

// Name implements Source.
func (s *OTXSource) Name() string { return "otx" }

// Configured implements Source.
func (s *OTXSource) Configured() bool { return s.APIKey != "" }

// Lookup implements Source.
func (s *OTXSource) Lookup(ctx context.Context, domain string) (*Finding, error) {
	endpoint := "https://otx.alienvault.com/api/v1/indicators/domain/" + url.PathEscape(domain) + "/general"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("X-OTX-API-KEY", s.APIKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying otx: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("otx returned %s", resp.Status)
	}

	var result struct {
		PulseInfo struct {
			Count  int `json:"count"`
			Pulses []struct {
				Name string   `json:"name"`
				Tags []string `json:"tags"`
			} `json:"pulses"`
		} `json:"pulse_info"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding otx response: %w", err)
	}

	if result.PulseInfo.Count == 0 {
		return nil, nil
	}

	// A single community pulse is weak evidence — anyone can publish one — so
	// this contributes less on its own and more when several agree.
	score := 25
	if result.PulseInfo.Count >= 3 {
		score = 45
	}

	detail := fmt.Sprintf("named in %d community threat reports", result.PulseInfo.Count)
	if len(result.PulseInfo.Pulses) > 0 {
		detail += ": " + result.PulseInfo.Pulses[0].Name
	}

	return &Finding{
		Source:    s.Name(),
		Malicious: true,
		Score:     score,
		Category:  "threat",
		Detail:    detail,
		Reference: "https://otx.alienvault.com/indicator/domain/" + url.PathEscape(domain),
	}, nil
}
