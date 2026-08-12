package filter

import (
	"bufio"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"net/netip"
	"sort"
	"strings"
)

// maxSourceLine bounds a single blocklist line.  Real rules are far shorter;
// anything longer is a corrupt or hostile download.
const maxSourceLine = 4 * 1024

// SourceInfo identifies where a rule came from.  Provenance is what lets an
// operator answer "why was this blocked, and which list do I turn off" — the
// question that makes filtering debuggable instead of magical.
type SourceInfo struct {
	ID   string
	Name string
}

// SourceStats reports what a source contributed.
type SourceStats struct {
	Lines       int
	Rules       int
	Blocked     int
	Allowed     int
	Rewrites    int
	Regex       int
	Skipped     int
	Unsupported int
	Errors      int
}

// Result describes a match.
type Result struct {
	// Rule is set for regex and modifier-carrying rules, which are kept in
	// full.  Plain domain rules are reduced to hashes and have no Rule.
	Rule *Rule

	// MatchedDomain is the suffix that matched, so the UI can explain that
	// "ads.example.com" was blocked by a rule for "example.com".
	MatchedDomain string

	// SourceID is the list the rule came from.
	SourceID string

	RewriteIPs []netip.Addr

	Action Action

	Matched         bool
	RewriteNXDOMAIN bool
}

// Index is an immutable compiled ruleset.
//
// Plain domain rules live in sorted hash arrays: ten bytes per domain, no
// pointers, and therefore nothing for the garbage collector to walk.  The
// trade-off is that a 64-bit hash collision would block the wrong name; at ten
// million rules the chance of any collision at all is about one in four
// hundred thousand, and the panel shows the matched rule so the mistake would
// be visible rather than silent.
type Index struct {
	seed maphash.Seed

	blockHashes []uint64
	blockSource []uint16

	allowHashes []uint64
	allowSource []uint16

	// complexByHash maps a domain hash to rules that carry modifiers, which
	// cannot be reduced to a bare hash.  There are few of these.
	complexByHash map[uint64][]int32
	complex       []*Rule
	complexSource []uint16

	regex       []*Rule
	regexSource []uint16

	sources []SourceInfo

	rules int
}

// Len returns the number of compiled rules.
func (idx *Index) Len() int {
	if idx == nil {
		return 0
	}

	return idx.rules
}

// Sources returns the lists that contributed rules.
func (idx *Index) Sources() []SourceInfo {
	if idx == nil {
		return nil
	}

	return idx.sources
}

// ApproxBytes estimates the resident size of the index, which the panel shows
// so an operator can see the cost of enabling another list.
func (idx *Index) ApproxBytes() int {
	if idx == nil {
		return 0
	}

	const (
		hashEntry    = 8 + 2 // one hash plus its source index
		complexEntry = 200   // a Rule with its strings, roughly
	)

	return (len(idx.blockHashes)+len(idx.allowHashes))*hashEntry +
		(len(idx.complex)+len(idx.regex))*complexEntry
}

// Match tests a query against the ruleset.
//
// Precedence follows AdBlock semantics, which list authors write against:
// an $important block beats everything, an exception beats a plain block, and
// a rewrite is applied only when nothing has already decided the query.
// Exceptions are honoured at any level of the name, so allowing example.com
// also allows everything under it.
func (idx *Index) Match(host string, qtype uint16, clientID string) (res Result) {
	if idx == nil {
		return Result{}
	}

	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return Result{}
	}

	var (
		allow     *Result
		block     *Result
		rewrite   *Result
		important *Result
	)

	// Walk the name from most to least specific: "a.b.example.com" then
	// "b.example.com" then "example.com" then "com".
	for suffix := host; suffix != ""; suffix = parentDomain(suffix) {
		h := maphash.String(idx.seed, suffix)

		for _, i := range idx.complexByHash[h] {
			rule := idx.complex[i]

			if !rule.MatchesQType(qtype) {
				continue
			}
			if rule.ClientSpec != "" && rule.ClientSpec != clientID {
				continue
			}
			// A rule written for an exact name must not catch subdomains.
			if !rule.Subdomains && suffix != host {
				continue
			}

			hit := &Result{
				Matched:         true,
				Action:          rule.Action,
				Rule:            rule,
				MatchedDomain:   suffix,
				SourceID:        idx.sourceID(idx.complexSource[i]),
				RewriteIPs:      rule.RewriteIPs,
				RewriteNXDOMAIN: rule.RewriteNXDOMAIN,
			}

			switch {
			case rule.Important && rule.Action == ActionBlock:
				if important == nil {
					important = hit
				}
			case rule.Action == ActionAllow:
				if allow == nil {
					allow = hit
				}
			case rule.Action == ActionRewrite:
				if rewrite == nil {
					rewrite = hit
				}
			default:
				if block == nil {
					block = hit
				}
			}
		}

		if allow == nil {
			if src, found := lookup(idx.allowHashes, idx.allowSource, h); found {
				allow = &Result{
					Matched:       true,
					Action:        ActionAllow,
					MatchedDomain: suffix,
					SourceID:      idx.sourceID(src),
				}
			}
		}

		if block == nil {
			if src, found := lookup(idx.blockHashes, idx.blockSource, h); found {
				block = &Result{
					Matched:       true,
					Action:        ActionBlock,
					MatchedDomain: suffix,
					SourceID:      idx.sourceID(src),
				}
			}
		}
	}

	switch {
	case important != nil:
		return *important
	case allow != nil:
		return *allow
	case block != nil:
		return *block
	case rewrite != nil:
		return *rewrite
	}

	// Regexes are the slow path, so they run only once the cheap lookups have
	// come up empty.
	for i, rule := range idx.regex {
		if !rule.MatchesQType(qtype) {
			continue
		}
		if rule.ClientSpec != "" && rule.ClientSpec != clientID {
			continue
		}
		if rule.Regex.MatchString(host) {
			return Result{
				Matched:         true,
				Action:          rule.Action,
				Rule:            rule,
				MatchedDomain:   host,
				SourceID:        idx.sourceID(idx.regexSource[i]),
				RewriteIPs:      rule.RewriteIPs,
				RewriteNXDOMAIN: rule.RewriteNXDOMAIN,
			}
		}
	}

	return Result{}
}

func (idx *Index) sourceID(i uint16) string {
	if int(i) < len(idx.sources) {
		return idx.sources[i].ID
	}

	return ""
}

// parentDomain drops the leftmost label, returning "" at the top.
func parentDomain(domain string) string {
	_, rest, found := strings.Cut(domain, ".")
	if !found {
		return ""
	}

	return rest
}

// lookup binary-searches the sorted hash array.
func lookup(hashes []uint64, sources []uint16, h uint64) (source uint16, found bool) {
	i := sort.Search(len(hashes), func(i int) bool { return hashes[i] >= h })
	if i < len(hashes) && hashes[i] == h {
		return sources[i], true
	}

	return 0, false
}

// Builder compiles rules into an Index.
type Builder struct {
	seed maphash.Seed

	blockHashes []uint64
	blockSource []uint16
	allowHashes []uint64
	allowSource []uint16

	complex       []*Rule
	complexSource []uint16
	regex         []*Rule
	regexSource   []uint16

	sources []SourceInfo
}

// NewBuilder returns an empty builder.
func NewBuilder() *Builder {
	return &Builder{seed: maphash.MakeSeed()}
}

// AddSource registers a list and returns the handle used to attribute its
// rules.
func (b *Builder) AddSource(id, name string) uint16 {
	b.sources = append(b.sources, SourceInfo{ID: id, Name: name})

	return uint16(len(b.sources) - 1)
}

// AddRule adds a single parsed rule.
func (b *Builder) AddRule(source uint16, rule *Rule) {
	switch {
	case rule.IsRegex():
		b.regex = append(b.regex, rule)
		b.regexSource = append(b.regexSource, source)

	case isComplex(rule):
		b.complex = append(b.complex, rule)
		b.complexSource = append(b.complexSource, source)

	case rule.Action == ActionAllow:
		b.allowHashes = append(b.allowHashes, maphash.String(b.seed, rule.Domain))
		b.allowSource = append(b.allowSource, source)

	default:
		b.blockHashes = append(b.blockHashes, maphash.String(b.seed, rule.Domain))
		b.blockSource = append(b.blockSource, source)
	}
}

// isComplex reports whether a rule carries information that a bare hash cannot
// represent.
func isComplex(rule *Rule) bool {
	return rule.Important ||
		rule.ClientSpec != "" ||
		len(rule.QTypes) > 0 ||
		len(rule.RewriteIPs) > 0 ||
		rule.RewriteNXDOMAIN ||
		!rule.Subdomains ||
		rule.Action == ActionRewrite
}

// AddReader parses every line from r and adds the rules it yields.  Parse
// failures are counted rather than returned: a single malformed line in a
// half-million-entry community list must not cost the operator the whole list.
func (b *Builder) AddReader(source uint16, r io.Reader) (stats SourceStats, err error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxSourceLine)

	for scanner.Scan() {
		stats.Lines++

		rule, ok, parseErr := ParseLine(scanner.Text())
		switch {
		case parseErr != nil:
			var unsupported *ErrUnsupported
			if errors.As(parseErr, &unsupported) {
				stats.Unsupported++
			} else {
				stats.Errors++
			}

			continue
		case !ok:
			stats.Skipped++

			continue
		}

		b.AddRule(source, rule)
		stats.Rules++

		switch {
		case rule.IsRegex():
			stats.Regex++
		case rule.Action == ActionAllow:
			stats.Allowed++
		case rule.Action == ActionRewrite:
			stats.Rewrites++
		default:
			stats.Blocked++
		}
	}

	if err = scanner.Err(); err != nil {
		return stats, fmt.Errorf("reading rules: %w", err)
	}

	return stats, nil
}

// Build sorts and deduplicates the accumulated rules into an immutable index.
// The caller should discard the builder afterwards.
func (b *Builder) Build() *Index {
	sortPairs(b.blockHashes, b.blockSource)
	sortPairs(b.allowHashes, b.allowSource)

	b.blockHashes, b.blockSource = dedupe(b.blockHashes, b.blockSource)
	b.allowHashes, b.allowSource = dedupe(b.allowHashes, b.allowSource)

	byHash := make(map[uint64][]int32, len(b.complex))
	for i, rule := range b.complex {
		h := maphash.String(b.seed, rule.Domain)
		byHash[h] = append(byHash[h], int32(i))
	}

	return &Index{
		seed:          b.seed,
		blockHashes:   b.blockHashes,
		blockSource:   b.blockSource,
		allowHashes:   b.allowHashes,
		allowSource:   b.allowSource,
		complexByHash: byHash,
		complex:       b.complex,
		complexSource: b.complexSource,
		regex:         b.regex,
		regexSource:   b.regexSource,
		sources:       b.sources,
		rules: len(b.blockHashes) + len(b.allowHashes) +
			len(b.complex) + len(b.regex),
	}
}

// hashPairs sorts two parallel arrays together, keeping them aligned without
// allocating a combined slice — which at ten million entries would cost more
// than the index itself.
type hashPairs struct {
	hashes  []uint64
	sources []uint16
}

func (p hashPairs) Len() int           { return len(p.hashes) }
func (p hashPairs) Less(i, j int) bool { return p.hashes[i] < p.hashes[j] }
func (p hashPairs) Swap(i, j int) {
	p.hashes[i], p.hashes[j] = p.hashes[j], p.hashes[i]
	p.sources[i], p.sources[j] = p.sources[j], p.sources[i]
}

func sortPairs(hashes []uint64, sources []uint16) {
	sort.Sort(hashPairs{hashes: hashes, sources: sources})
}

// dedupe collapses repeated hashes in place, keeping the first source that
// contributed each one.  Overlap between community lists is enormous, so this
// routinely removes a large fraction of the entries.
func dedupe(hashes []uint64, sources []uint16) (outHashes []uint64, outSources []uint16) {
	if len(hashes) == 0 {
		return hashes, sources
	}

	out := 0
	for i := 1; i < len(hashes); i++ {
		if hashes[i] == hashes[out] {
			continue
		}
		out++
		hashes[out] = hashes[i]
		sources[out] = sources[i]
	}

	return hashes[:out+1], sources[:out+1]
}
