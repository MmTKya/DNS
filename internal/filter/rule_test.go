package filter_test

import (
	"errors"
	"testing"

	"github.com/MmTKya/DNS/internal/filter"
	"github.com/miekg/dns"
)

func TestParseLineFormats(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		line       string
		wantDomain string
		wantAction filter.Action
		wantSubs   bool
	}{{
		name:       "plain domain",
		line:       "ads.example.com",
		wantDomain: "ads.example.com",
		wantAction: filter.ActionBlock,
		wantSubs:   true,
	}, {
		name:       "hosts format",
		line:       "0.0.0.0 tracker.example.com",
		wantDomain: "tracker.example.com",
		wantAction: filter.ActionBlock,
		wantSubs:   true,
	}, {
		name:       "hosts format with tab and comment",
		line:       "0.0.0.0\ttracker.example.com # analytics",
		wantDomain: "tracker.example.com",
		wantAction: filter.ActionBlock,
		wantSubs:   true,
	}, {
		name:       "adblock block",
		line:       "||ads.example.com^",
		wantDomain: "ads.example.com",
		wantAction: filter.ActionBlock,
		wantSubs:   true,
	}, {
		name:       "adblock exception",
		line:       "@@||cdn.example.com^",
		wantDomain: "cdn.example.com",
		wantAction: filter.ActionAllow,
		wantSubs:   true,
	}, {
		name:       "leading wildcard is a suffix match",
		line:       "*.ads.example.com",
		wantDomain: "ads.example.com",
		wantAction: filter.ActionBlock,
		wantSubs:   true,
	}, {
		name:       "case and trailing dot are normalised",
		line:       "Ads.Example.COM.",
		wantDomain: "ads.example.com",
		wantAction: filter.ActionBlock,
		wantSubs:   true,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rule, ok, err := filter.ParseLine(tc.line)
			if err != nil {
				t.Fatalf("ParseLine(%q): %v", tc.line, err)
			}
			if !ok {
				t.Fatalf("ParseLine(%q) skipped the line", tc.line)
			}

			if rule.Domain != tc.wantDomain {
				t.Errorf("domain = %q, want %q", rule.Domain, tc.wantDomain)
			}
			if rule.Action != tc.wantAction {
				t.Errorf("action = %v, want %v", rule.Action, tc.wantAction)
			}
			if rule.Subdomains != tc.wantSubs {
				t.Errorf("subdomains = %t, want %t", rule.Subdomains, tc.wantSubs)
			}
		})
	}
}

func TestParseLineSkips(t *testing.T) {
	t.Parallel()

	// Cosmetic rules make up most of a raw EasyList. Treating their domain
	// part as a DNS rule would block the sites they are meant to clean up.
	skipped := []string{
		"",
		"   ",
		"# a comment",
		"! another comment",
		"[Adblock Plus 2.0]",
		"example.com##.ad-banner",
		"example.com#@#.ad-banner",
		"example.com#?#div:has(> .ad)",
		"0.0.0.0 localhost",
	}

	for _, line := range skipped {
		rule, ok, err := filter.ParseLine(line)
		if err != nil {
			t.Errorf("ParseLine(%q) returned an error: %v", line, err)
		}
		if ok {
			t.Errorf("ParseLine(%q) produced a rule %+v, want it skipped", line, rule)
		}
	}
}

func TestParseLineUnsupported(t *testing.T) {
	t.Parallel()

	// These parse as rules but cannot be honoured at the DNS layer. They must
	// be reported as unsupported, not silently reinterpreted.
	unsupported := []string{
		"||example.com/ads.js",
		"||example.com^$third-party",
		"||example.com^$dnstype=NOTAREALTYPE",
		"ads.*",
		"a*b.example.com",
	}

	for _, line := range unsupported {
		_, ok, err := filter.ParseLine(line)
		if ok {
			t.Errorf("ParseLine(%q) accepted an unsupported rule", line)

			continue
		}

		var target *filter.ErrUnsupported
		if !errors.As(err, &target) {
			t.Errorf("ParseLine(%q) error = %v, want ErrUnsupported", line, err)
		}
	}
}

func TestParseModifiers(t *testing.T) {
	t.Parallel()

	t.Run("dnstype", func(t *testing.T) {
		t.Parallel()

		rule, ok, err := filter.ParseLine("||example.com^$dnstype=AAAA|HTTPS")
		if err != nil || !ok {
			t.Fatalf("ParseLine: ok=%t err=%v", ok, err)
		}

		if !rule.MatchesQType(dns.TypeAAAA) || !rule.MatchesQType(dns.TypeHTTPS) {
			t.Error("rule should match the types it names")
		}
		if rule.MatchesQType(dns.TypeA) {
			t.Error("rule should not match a type it does not name")
		}
	})

	t.Run("dnsrewrite to an address", func(t *testing.T) {
		t.Parallel()

		rule, ok, err := filter.ParseLine("||example.com^$dnsrewrite=192.0.2.1")
		if err != nil || !ok {
			t.Fatalf("ParseLine: ok=%t err=%v", ok, err)
		}

		if rule.Action != filter.ActionRewrite {
			t.Errorf("action = %v, want rewrite", rule.Action)
		}
		if len(rule.RewriteIPs) != 1 || rule.RewriteIPs[0].String() != "192.0.2.1" {
			t.Errorf("rewrite = %v, want [192.0.2.1]", rule.RewriteIPs)
		}
	})

	t.Run("dnsrewrite long form", func(t *testing.T) {
		t.Parallel()

		rule, ok, err := filter.ParseLine("||example.com^$dnsrewrite=NOERROR;A;192.0.2.2")
		if err != nil || !ok {
			t.Fatalf("ParseLine: ok=%t err=%v", ok, err)
		}
		if len(rule.RewriteIPs) != 1 || rule.RewriteIPs[0].String() != "192.0.2.2" {
			t.Errorf("rewrite = %v, want [192.0.2.2]", rule.RewriteIPs)
		}
	})

	t.Run("dnsrewrite to NXDOMAIN", func(t *testing.T) {
		t.Parallel()

		rule, ok, err := filter.ParseLine("||example.com^$dnsrewrite=NXDOMAIN")
		if err != nil || !ok {
			t.Fatalf("ParseLine: ok=%t err=%v", ok, err)
		}
		if !rule.RewriteNXDOMAIN {
			t.Error("rule should rewrite to NXDOMAIN")
		}
	})

	t.Run("important and client", func(t *testing.T) {
		t.Parallel()

		rule, ok, err := filter.ParseLine("||example.com^$important,client='kids-tablet'")
		if err != nil || !ok {
			t.Fatalf("ParseLine: ok=%t err=%v", ok, err)
		}
		if !rule.Important {
			t.Error("rule should be important")
		}
		if rule.ClientSpec != "kids-tablet" {
			t.Errorf("client = %q, want %q", rule.ClientSpec, "kids-tablet")
		}
	})
}

func TestParseHostsRedirectIsARewrite(t *testing.T) {
	t.Parallel()

	// A hosts entry pointing at a real address is a redirection, not a block;
	// treating it as a block would break split-horizon setups.
	rule, ok, err := filter.ParseLine("192.168.1.10 nas.home.lan")
	if err != nil || !ok {
		t.Fatalf("ParseLine: ok=%t err=%v", ok, err)
	}

	if rule.Action != filter.ActionRewrite {
		t.Errorf("action = %v, want rewrite", rule.Action)
	}
	if len(rule.RewriteIPs) != 1 || rule.RewriteIPs[0].String() != "192.168.1.10" {
		t.Errorf("rewrite = %v, want [192.168.1.10]", rule.RewriteIPs)
	}
}

func TestParseRegex(t *testing.T) {
	t.Parallel()

	rule, ok, err := filter.ParseLine(`/^ad[0-9]+\.example\.com$/`)
	if err != nil || !ok {
		t.Fatalf("ParseLine: ok=%t err=%v", ok, err)
	}
	if !rule.IsRegex() {
		t.Fatal("rule should be a regex rule")
	}
	if !rule.Regex.MatchString("ad42.example.com") {
		t.Error("regex should match ad42.example.com")
	}

	if _, ok, err = filter.ParseLine(`/^(unclosed/`); err == nil && ok {
		t.Error("an invalid regex must be reported, not compiled")
	}
}
