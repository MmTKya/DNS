// Package feeds manages blocklist sources: which lists exist, which are
// enabled, how they are fetched and when.
//
// The catalogue below is curated rather than open-ended.  Anyone can add a
// custom URL, but the built-in entries carry the metadata that decides whether
// a list is safe to enable by default: its licence, whether it permits
// commercial use, how often its author publishes, and whether it is known to
// produce false positives.  Shipping a list that forbids commercial use, or
// one that over-blocks, is a decision the operator has to be able to see.
package feeds

import "time"

// Categories describe what a list targets.
const (
	CategoryAds       = "ads"
	CategoryTracking  = "tracking"
	CategoryMalware   = "malware"
	CategoryPhishing  = "phishing"
	CategoryNSFW      = "nsfw"
	CategoryNRD       = "nrd"
	CategoryAggregate = "aggregate"
)

// Feed describes a blocklist source.
type Feed struct {
	// ID is stable across releases and is what rules are attributed to.
	ID string `json:"id"`

	Name        string `json:"name"`
	Description string `json:"description"`
	Homepage    string `json:"homepage"`

	// URL is the primary download location.  Mirrors are tried in order when
	// it fails, which matters because most of these live on one GitHub repo.
	URL     string   `json:"url"`
	Mirrors []string `json:"mirrors,omitempty"`

	Category string `json:"category"`

	// License is the SPDX identifier or a short description.
	License string `json:"license"`

	// CommercialUse records whether the licence permits commercial use.  A
	// list with false here is never enabled by default, no matter how good it
	// is: shipping it enabled would put every commercial deployment in breach.
	CommercialUse bool `json:"commercial_use"`

	// DefaultOn lists are enabled on a fresh install.
	DefaultOn bool `json:"default_on"`

	// PollInterval matches the publisher's actual cadence.  Fetching a daily
	// list every five minutes is just rude to the maintainer's bandwidth.
	PollInterval time.Duration `json:"poll_interval"`

	// ApproxEntries sets expectations in the panel before a list is enabled.
	ApproxEntries int `json:"approx_entries"`

	// HighFalsePositives marks lists that block aggressively enough to break
	// ordinary browsing.  The panel warns before enabling one.
	HighFalsePositives bool `json:"high_false_positives"`

	// Region restricts a list's relevance, e.g. "TR".  Empty means global.
	Region string `json:"region,omitempty"`

	// Connector marks a feed maintained by dedicated code rather than by the
	// downloader — an API rather than a file.  The downloader skips these; the
	// connector writes the same cache file, so compilation is identical.
	Connector bool `json:"connector,omitempty"`
}

// Catalog is the built-in list of known feeds.
//
// The four default-on entries are chosen to be broadly safe and
// commercially usable: two from HaGeZi (ads/trackers, and threat intelligence
// aggregated from URLhaus, Phishing Army and CERT-PL), and CERT-PL's own
// warning list, which is ISP-grade and republished every five minutes.
func Catalog() []Feed {
	return []Feed{{
		ID:            "hagezi-pro",
		Name:          "HaGeZi Pro",
		Description:   "Ads, trackers and badware. The balanced default: aggressive enough to matter, curated enough not to break sites.",
		Homepage:      "https://github.com/hagezi/dns-blocklists",
		URL:           "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
		Mirrors:       []string{"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt"},
		Category:      CategoryAds,
		License:       "GPL-3.0",
		CommercialUse: true,
		DefaultOn:     true,
		PollInterval:  24 * time.Hour,
		ApproxEntries: 480_000,
	}, {
		ID:            "hagezi-tif-medium",
		Name:          "HaGeZi Threat Intelligence (medium)",
		Description:   "Malware, phishing and command-and-control domains, aggregated from URLhaus, Phishing Army, CERT-PL and others.",
		Homepage:      "https://github.com/hagezi/dns-blocklists",
		URL:           "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.medium.txt",
		Mirrors:       []string{"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.medium.txt"},
		Category:      CategoryMalware,
		License:       "GPL-3.0",
		CommercialUse: true,
		DefaultOn:     true,
		PollInterval:  12 * time.Hour,
		ApproxEntries: 250_000,
	}, {
		ID:            "cert-pl",
		Name:          "CERT-PL Warning List",
		Description:   "Poland's national CERT publishes confirmed phishing and fraud domains, republished every few minutes.",
		Homepage:      "https://cert.pl/en/warning-list/",
		URL:           "https://hole.cert.pl/domains/v2/domains.txt",
		Category:      CategoryPhishing,
		License:       "Free to use, attribution requested",
		CommercialUse: true,
		DefaultOn:     true,
		PollInterval:  time.Hour,
		ApproxEntries: 60_000,
	}, {
		ID:   "usom-sgb",
		Name: "USOM / Cyber Security Directorate (Türkiye)",
		Description: "Türkiye's national threat feed: phishing, banking fraud, malware distribution and command-and-control, " +
			"published by the state CERT. Synced through its API — the old url-list.txt was retired in 2026 and products still " +
			"pointed at it are fetching nothing.",
		Homepage:      "https://siberguvenlik.gov.tr",
		URL:           "https://siberguvenlik.gov.tr/api/address/index",
		Category:      CategoryPhishing,
		License:       "Public national feed",
		CommercialUse: true,
		DefaultOn:     false,
		PollInterval:  time.Hour,
		ApproxEntries: 465_000,
		Region:        "TR",
		Connector:     true,
	}, {
		ID:            "stevenblack",
		Name:          "StevenBlack hosts",
		Description:   "The long-standing consolidated hosts file: adware and malware, unified from several upstream sources.",
		Homepage:      "https://github.com/StevenBlack/hosts",
		URL:           "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		Category:      CategoryAds,
		License:       "MIT",
		CommercialUse: true,
		DefaultOn:     false,
		PollInterval:  24 * time.Hour,
		ApproxEntries: 130_000,
	}, {
		ID:            "oisd-big",
		Name:          "OISD Big",
		Description:   "A large aggregate list tuned to avoid breaking sites. Overlaps heavily with HaGeZi Pro.",
		Homepage:      "https://oisd.nl",
		URL:           "https://big.oisd.nl",
		Category:      CategoryAggregate,
		License:       "Free for personal and commercial use",
		CommercialUse: true,
		DefaultOn:     false,
		PollInterval:  24 * time.Hour,
		ApproxEntries: 200_000,
	}, {
		ID:            "adguard-dns",
		Name:          "AdGuard DNS filter",
		Description:   "AdGuard's own DNS-optimised list. Prefer this over raw EasyList, which is mostly cosmetic rules a resolver cannot use.",
		Homepage:      "https://adguard.com",
		URL:           "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
		Category:      CategoryAds,
		License:       "GPL-3.0",
		CommercialUse: true,
		DefaultOn:     false,
		PollInterval:  24 * time.Hour,
		ApproxEntries: 60_000,
	}, {
		ID:            "oisd-nsfw",
		Name:          "OISD NSFW",
		Description:   "Adult content. A content-policy choice, not a security one.",
		Homepage:      "https://oisd.nl",
		URL:           "https://nsfw.oisd.nl",
		Category:      CategoryNSFW,
		License:       "Free for personal and commercial use",
		CommercialUse: true,
		DefaultOn:     false,
		PollInterval:  24 * time.Hour,
		ApproxEntries: 100_000,
	}, {
		ID:                 "hagezi-nrd-30",
		Name:               "HaGeZi Newly Registered Domains (30 days)",
		Description:        "Domains registered in the last 30 days. Effective against phishing, and prone to blocking legitimate new sites.",
		Homepage:           "https://github.com/hagezi/nrd",
		URL:                "https://raw.githubusercontent.com/hagezi/nrd/main/nrds.30.txt",
		Category:           CategoryNRD,
		License:            "GPL-3.0",
		CommercialUse:      true,
		DefaultOn:          false,
		PollInterval:       24 * time.Hour,
		ApproxEntries:      1_500_000,
		HighFalsePositives: true,
	}, {
		ID:            "phishing-army",
		Name:          "Phishing Army",
		Description:   "A focused phishing list. Its licence forbids commercial use, so it is never enabled by default; most of its content already reaches you through HaGeZi TIF.",
		Homepage:      "https://phishing.army",
		URL:           "https://phishing.army/download/phishing_army_blocklist_extended.txt",
		Category:      CategoryPhishing,
		License:       "CC BY-NC 4.0",
		CommercialUse: false,
		DefaultOn:     false,
		PollInterval:  12 * time.Hour,
		ApproxEntries: 100_000,
	}}
}

// Lookup returns the catalogue entry with the given id.
func Lookup(id string) (feed Feed, found bool) {
	for _, f := range Catalog() {
		if f.ID == id {
			return f, true
		}
	}

	return Feed{}, false
}
