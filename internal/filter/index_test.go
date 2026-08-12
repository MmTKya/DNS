package filter_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/MmTKya/DNS/internal/filter"
	"github.com/miekg/dns"
)

// build compiles a ruleset from newline-separated rules attributed to one
// source.
func build(t *testing.T, sourceID, rules string) *filter.Index {
	t.Helper()

	b := filter.NewBuilder()
	src := b.AddSource(sourceID, sourceID)

	stats, err := b.AddReader(src, strings.NewReader(rules))
	if err != nil {
		t.Fatalf("AddReader: %v", err)
	}
	if stats.Errors > 0 {
		t.Fatalf("fixture has %d unparseable lines", stats.Errors)
	}

	return b.Build()
}

func TestMatchBlocksDomainAndSubdomains(t *testing.T) {
	t.Parallel()

	idx := build(t, "test", "||ads.example.com^\n")

	for _, host := range []string{"ads.example.com", "a.ads.example.com", "x.y.ads.example.com"} {
		res := idx.Match(host, dns.TypeA, "")
		if !res.Matched || res.Action != filter.ActionBlock {
			t.Errorf("%s: matched=%t action=%v, want a block", host, res.Matched, res.Action)
		}
	}

	// A rule for ads.example.com must not touch its parent or a sibling.
	for _, host := range []string{"example.com", "notads.example.com", "ads.example.org"} {
		if res := idx.Match(host, dns.TypeA, ""); res.Matched {
			t.Errorf("%s: matched rule for %q, want no match", host, res.MatchedDomain)
		}
	}
}

func TestMatchReportsProvenance(t *testing.T) {
	t.Parallel()

	b := filter.NewBuilder()
	hagezi := b.AddSource("hagezi-pro", "HaGeZi Pro")
	local := b.AddSource("local", "Local rules")

	if _, err := b.AddReader(hagezi, strings.NewReader("||ads.example.com^\n")); err != nil {
		t.Fatalf("AddReader: %v", err)
	}
	if _, err := b.AddReader(local, strings.NewReader("||tracker.example.net^\n")); err != nil {
		t.Fatalf("AddReader: %v", err)
	}

	idx := b.Build()

	// "Which list blocked this" is the question that makes filtering
	// debuggable, so every match has to carry it.
	if res := idx.Match("ads.example.com", dns.TypeA, ""); res.SourceID != "hagezi-pro" {
		t.Errorf("source = %q, want %q", res.SourceID, "hagezi-pro")
	}
	if res := idx.Match("tracker.example.net", dns.TypeA, ""); res.SourceID != "local" {
		t.Errorf("source = %q, want %q", res.SourceID, "local")
	}
	if res := idx.Match("a.ads.example.com", dns.TypeA, ""); res.MatchedDomain != "ads.example.com" {
		t.Errorf("matched domain = %q, want %q", res.MatchedDomain, "ads.example.com")
	}
}

func TestAllowRuleBeatsBlock(t *testing.T) {
	t.Parallel()

	idx := build(t, "test", "||example.com^\n@@||cdn.example.com^\n")

	if res := idx.Match("example.com", dns.TypeA, ""); res.Action != filter.ActionBlock {
		t.Errorf("example.com: action = %v, want block", res.Action)
	}

	// The exception has to win at its own level and below it.
	for _, host := range []string{"cdn.example.com", "eu.cdn.example.com"} {
		res := idx.Match(host, dns.TypeA, "")
		if res.Action != filter.ActionAllow {
			t.Errorf("%s: action = %v, want allow", host, res.Action)
		}
	}
}

func TestImportantBlockBeatsAllow(t *testing.T) {
	t.Parallel()

	idx := build(t, "test", "@@||example.com^\n||tracker.example.com^$important\n")

	if res := idx.Match("tracker.example.com", dns.TypeA, ""); res.Action != filter.ActionBlock {
		t.Errorf("action = %v, want block: $important must override an exception", res.Action)
	}
	if res := idx.Match("www.example.com", dns.TypeA, ""); res.Action != filter.ActionAllow {
		t.Errorf("action = %v, want allow", res.Action)
	}
}

func TestQTypeScopedRule(t *testing.T) {
	t.Parallel()

	idx := build(t, "test", "||example.com^$dnstype=AAAA\n")

	if res := idx.Match("example.com", dns.TypeAAAA, ""); !res.Matched {
		t.Error("AAAA should be blocked")
	}
	if res := idx.Match("example.com", dns.TypeA, ""); res.Matched {
		t.Error("A should not be blocked by an AAAA-only rule")
	}
}

func TestClientScopedRule(t *testing.T) {
	t.Parallel()

	idx := build(t, "test", "||games.example.com^$client='kids-tablet'\n")

	if res := idx.Match("games.example.com", dns.TypeA, "kids-tablet"); !res.Matched {
		t.Error("the named client should be blocked")
	}
	if res := idx.Match("games.example.com", dns.TypeA, "laptop"); res.Matched {
		t.Error("other clients should not be affected")
	}
}

func TestRewriteRule(t *testing.T) {
	t.Parallel()

	idx := build(t, "test", "||nas.home.lan^$dnsrewrite=192.168.1.10\n")

	res := idx.Match("nas.home.lan", dns.TypeA, "")
	if res.Action != filter.ActionRewrite {
		t.Fatalf("action = %v, want rewrite", res.Action)
	}
	if len(res.RewriteIPs) != 1 || res.RewriteIPs[0].String() != "192.168.1.10" {
		t.Errorf("rewrite = %v, want [192.168.1.10]", res.RewriteIPs)
	}
}

func TestRegexRuleIsTheSlowPath(t *testing.T) {
	t.Parallel()

	idx := build(t, "test", "@@||ad1.example.com^\n/^ad[0-9]+\\.example\\.com$/\n")

	if res := idx.Match("ad42.example.com", dns.TypeA, ""); res.Action != filter.ActionBlock {
		t.Errorf("ad42: action = %v, want block", res.Action)
	}

	// A plain exception must still win over a regex block, which means the
	// regex pass has to run last.
	if res := idx.Match("ad1.example.com", dns.TypeA, ""); res.Action != filter.ActionAllow {
		t.Errorf("ad1: action = %v, want allow", res.Action)
	}
}

func TestDedupeAcrossSources(t *testing.T) {
	t.Parallel()

	b := filter.NewBuilder()
	first := b.AddSource("first", "First")
	second := b.AddSource("second", "Second")

	// Community lists overlap heavily; the same domain arriving from several
	// of them must cost one entry, not one per list.
	for _, src := range []uint16{first, second} {
		if _, err := b.AddReader(src, strings.NewReader("||dup.example.com^\n||other.example.com^\n")); err != nil {
			t.Fatalf("AddReader: %v", err)
		}
	}

	idx := b.Build()
	if idx.Len() != 2 {
		t.Errorf("index holds %d rules, want 2 after deduplication", idx.Len())
	}
	if res := idx.Match("dup.example.com", dns.TypeA, ""); !res.Matched {
		t.Error("the deduplicated rule should still match")
	}
}

func TestEmptyIndexMatchesNothing(t *testing.T) {
	t.Parallel()

	engine := filter.NewEngine()
	if res := engine.Match("example.com", dns.TypeA, ""); res.Matched {
		t.Error("an empty ruleset must not match anything")
	}

	var nilIndex *filter.Index
	if res := nilIndex.Match("example.com", dns.TypeA, ""); res.Matched {
		t.Error("a nil index must not match anything")
	}
}

func TestEngineReplaceIsAtomic(t *testing.T) {
	t.Parallel()

	engine := filter.NewEngine()
	engine.Replace(build(t, "v1", "||one.example.com^\n"))

	if res := engine.Match("one.example.com", dns.TypeA, ""); !res.Matched {
		t.Error("v1 rule should match")
	}

	engine.Replace(build(t, "v2", "||two.example.com^\n"))

	if res := engine.Match("one.example.com", dns.TypeA, ""); res.Matched {
		t.Error("the replaced ruleset should no longer match")
	}
	if res := engine.Match("two.example.com", dns.TypeA, ""); !res.Matched {
		t.Error("the new ruleset should match")
	}

	stats := engine.Stats()
	if stats.Rules != 1 || len(stats.Sources) != 1 || stats.Sources[0].ID != "v2" {
		t.Errorf("stats = %+v, want one rule from v2", stats)
	}
}

func TestAddReaderCountsUnparseableLinesWithoutFailing(t *testing.T) {
	t.Parallel()

	b := filter.NewBuilder()
	src := b.AddSource("mixed", "Mixed")

	const list = `# comment
||good.example.com^
||example.com^$third-party
example.com##.banner

||other.example.com^
`

	stats, err := b.AddReader(src, strings.NewReader(list))
	if err != nil {
		t.Fatalf("AddReader: %v", err)
	}

	// One bad line in a half-million-entry list must not cost the operator the
	// whole list.
	if stats.Rules != 2 {
		t.Errorf("rules = %d, want 2", stats.Rules)
	}
	if stats.Unsupported != 1 {
		t.Errorf("unsupported = %d, want 1", stats.Unsupported)
	}
	if stats.Skipped != 3 {
		t.Errorf("skipped = %d, want 3 (comment, cosmetic, blank)", stats.Skipped)
	}
}

func TestLargeRulesetMemoryBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the memory budget check in short mode")
	}
	t.Parallel()

	const count = 200_000

	var sb strings.Builder
	for i := range count {
		fmt.Fprintf(&sb, "||host%d.example.com^\n", i)
	}

	idx := build(t, "big", sb.String())

	if idx.Len() != count {
		t.Fatalf("index holds %d rules, want %d", idx.Len(), count)
	}

	// Ten bytes per domain is what makes ten million rules fit on a Pi. A
	// regression here — most likely someone reaching for a map — would be
	// invisible until a user enabled a large list and ran out of memory.
	perRule := float64(idx.ApproxBytes()) / float64(count)
	if perRule > 16 {
		t.Errorf("index costs %.1f bytes per rule, want no more than 16", perRule)
	}

	if res := idx.Match("host12345.example.com", dns.TypeA, ""); !res.Matched {
		t.Error("a rule from the middle of a large list should still match")
	}
	if res := idx.Match("absent.example.com", dns.TypeA, ""); res.Matched {
		t.Error("an absent name must not match")
	}
}

func BenchmarkMatch(b *testing.B) {
	var sb strings.Builder
	for i := range 100_000 {
		fmt.Fprintf(&sb, "||host%d.example.com^\n", i)
	}

	builder := filter.NewBuilder()
	src := builder.AddSource("bench", "Bench")
	if _, err := builder.AddReader(src, strings.NewReader(sb.String())); err != nil {
		b.Fatalf("AddReader: %v", err)
	}
	idx := builder.Build()

	b.ResetTimer()

	b.Run("hit", func(b *testing.B) {
		for range b.N {
			idx.Match("host50000.example.com", dns.TypeA, "")
		}
	})

	b.Run("miss", func(b *testing.B) {
		for range b.N {
			idx.Match("www.wikipedia.org", dns.TypeA, "")
		}
	})
}
