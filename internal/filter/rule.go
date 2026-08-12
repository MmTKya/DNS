// Package filter compiles blocklists into a matcher the datapath can consult
// on every query.
//
// The memory budget is the design constraint.  A naive map[string]struct{}
// costs roughly 50-80 bytes per entry once Go's map overhead and the string
// headers are counted, so ten million domains would not fit on a Raspberry Pi
// at all.  Rules are therefore reduced to 64-bit hashes held in sorted arrays
// (see index.go), which brings the cost to ten bytes per domain and keeps the
// whole structure opaque to the garbage collector.
package filter

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/miekg/dns"
)

// Action is what a matching rule does to a query.
type Action uint8

const (
	// ActionBlock refuses the name.
	ActionBlock Action = iota
	// ActionAllow exempts the name, overriding any blocking rule.
	ActionAllow
	// ActionRewrite answers with a specific address instead of forwarding.
	ActionRewrite
)

// String implements fmt.Stringer.
func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionRewrite:
		return "rewrite"
	default:
		return "block"
	}
}

// Rule is one parsed blocklist entry.
type Rule struct {
	// Raw is the source line, kept for the UI so an operator can see exactly
	// what blocked a name.  It is not retained in the compiled index.
	Raw string

	// Domain is the normalised name for hash rules: lower case, no trailing
	// dot, no leading "*.".
	Domain string

	// Regex is set only for /pattern/ rules, which are matched separately
	// because they cannot be hashed.
	Regex *regexp.Regexp

	// RewriteIPs are the answers for a $dnsrewrite rule.
	RewriteIPs []netip.Addr

	// QTypes restricts the rule to specific record types ($dnstype).  Empty
	// means every type.
	QTypes []uint16

	// ClientSpec restricts the rule to one client ($client), matched against
	// the client's id, name or address by the caller.
	ClientSpec string

	Action Action

	// Subdomains is true when the rule also covers everything under Domain,
	// which is the default for blocklist entries.
	Subdomains bool

	// Important makes a blocking rule win over allow rules.
	Important bool

	// RewriteNXDOMAIN answers with NXDOMAIN rather than an address.
	RewriteNXDOMAIN bool
}

// IsRegex reports whether the rule needs the regex path.
func (r *Rule) IsRegex() bool { return r.Regex != nil }

// MatchesQType reports whether the rule applies to a query of type qtype.
func (r *Rule) MatchesQType(qtype uint16) bool {
	if len(r.QTypes) == 0 {
		return true
	}

	for _, t := range r.QTypes {
		if t == qtype {
			return true
		}
	}

	return false
}

// ErrUnsupported marks a line that parsed cleanly but uses a feature this
// engine does not implement.  Such lines are skipped rather than approximated:
// honouring half of a rule's semantics is worse than ignoring it, because it
// silently blocks or unblocks something the list author did not ask for.
type ErrUnsupported struct {
	Reason string
}

// Error implements error.
func (e *ErrUnsupported) Error() string { return "unsupported rule: " + e.Reason }

// ParseLine parses one blocklist line.
//
// It accepts, and auto-detects between, the four formats that real lists use:
//
//	example.com                    plain domain list
//	0.0.0.0 example.com            hosts file
//	||example.com^                 AdBlock DNS syntax
//	@@||example.com^               AdBlock exception (allowlist)
//	/^ad[0-9]+\.example\.com$/     regular expression
//
// ok is false for blank lines, comments and cosmetic rules.  A non-nil error
// means the line looked like a rule but could not be used.
func ParseLine(line string) (rule *Rule, ok bool, err error) {
	line = strings.TrimSpace(line)

	if line == "" || isComment(line) {
		return nil, false, nil
	}

	// Cosmetic and scriptlet rules belong to browser extensions and make up
	// most of a raw EasyList.  A DNS filter cannot act on them, and treating
	// their domain part as a blocking rule would break every site they touch.
	if isCosmetic(line) {
		return nil, false, nil
	}

	if strings.HasPrefix(line, "/") && strings.HasSuffix(line, "/") && len(line) > 2 {
		return parseRegex(line)
	}

	if isHostsLine(line) {
		return parseHosts(line)
	}

	if strings.HasPrefix(line, "||") || strings.HasPrefix(line, "@@") {
		return parseAdblock(line)
	}

	return parsePlainDomain(line)
}

func isComment(line string) bool {
	switch line[0] {
	case '#', '!', ';':
		return true
	case '[':
		// List headers such as "[Adblock Plus 2.0]".
		return true
	default:
		return false
	}
}

func isCosmetic(line string) bool {
	return strings.Contains(line, "##") ||
		strings.Contains(line, "#@#") ||
		strings.Contains(line, "#?#") ||
		strings.Contains(line, "#$#") ||
		strings.Contains(line, "#%#")
}

// isHostsLine reports whether the line starts with an IP address, which is how
// a hosts-format list is told apart from a plain domain list.  Fields are used
// rather than a cut on the first space because real lists separate the address
// from the name with either spaces or tabs, in any combination.
func isHostsLine(line string) bool {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}

	_, err := netip.ParseAddr(fields[0])

	return err == nil
}

func parseHosts(line string) (rule *Rule, ok bool, err error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil, false, nil
	}

	addr, addrErr := netip.ParseAddr(fields[0])
	if addrErr != nil {
		return nil, false, fmt.Errorf("parsing hosts address %q: %w", fields[0], addrErr)
	}

	domain, normErr := normaliseDomain(stripComment(fields[1]))
	if normErr != nil {
		return nil, false, normErr
	}
	if domain == "" || domain == "localhost" {
		return nil, false, nil
	}

	// An unspecified address is the list author saying "block this"; anything
	// else is a real redirection, which is a rewrite.
	if addr.IsUnspecified() || addr.IsLoopback() {
		return &Rule{
			Raw:        line,
			Domain:     domain,
			Action:     ActionBlock,
			Subdomains: true,
		}, true, nil
	}

	return &Rule{
		Raw:        line,
		Domain:     domain,
		Action:     ActionRewrite,
		RewriteIPs: []netip.Addr{addr},
		Subdomains: true,
	}, true, nil
}

func parsePlainDomain(line string) (rule *Rule, ok bool, err error) {
	field := stripComment(line)
	if field == "" {
		return nil, false, nil
	}

	// A plain list must not contain spaces; anything else is a format this
	// parser does not recognise.
	if strings.ContainsAny(field, " \t") {
		return nil, false, &ErrUnsupported{Reason: "unrecognised line format"}
	}

	domain, err := normaliseDomain(field)
	if err != nil {
		return nil, false, err
	}
	if domain == "" {
		return nil, false, nil
	}

	return &Rule{
		Raw:        line,
		Domain:     domain,
		Action:     ActionBlock,
		Subdomains: true,
	}, true, nil
}

func parseAdblock(line string) (rule *Rule, ok bool, err error) {
	rule = &Rule{Raw: line, Action: ActionBlock, Subdomains: true}

	body := line
	if strings.HasPrefix(body, "@@") {
		rule.Action = ActionAllow
		body = body[2:]
	}

	if !strings.HasPrefix(body, "||") {
		// Rules anchored to a URL path or scheme are browser-level, not
		// name-level: a resolver cannot see the path.
		return nil, false, &ErrUnsupported{Reason: "not a DNS-level rule"}
	}
	body = body[2:]

	// Modifiers follow the first unescaped "$".
	if idx := strings.IndexByte(body, '$'); idx >= 0 {
		if err = parseModifiers(rule, body[idx+1:]); err != nil {
			return nil, false, err
		}
		body = body[:idx]
	}

	// "^" is the AdBlock separator; at the end of a DNS rule it simply
	// terminates the name.
	body = strings.TrimSuffix(body, "^")
	body = strings.TrimSuffix(body, "|")

	if strings.ContainsAny(body, "/?=&") {
		return nil, false, &ErrUnsupported{Reason: "rule targets a URL, not a name"}
	}

	domain, err := normaliseDomain(body)
	if err != nil {
		return nil, false, err
	}
	if domain == "" {
		return nil, false, nil
	}

	rule.Domain = domain

	return rule, true, nil
}

func parseRegex(line string) (rule *Rule, ok bool, err error) {
	pattern := line[1 : len(line)-1]

	// Blocklists are downloaded from third parties, so a pathological pattern
	// is an availability risk.  Go's RE2 has no backtracking, which removes
	// the catastrophic case, but a very long pattern is still a smell.
	if len(pattern) > 512 {
		return nil, false, &ErrUnsupported{Reason: "regex is too long"}
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, false, fmt.Errorf("compiling regex %q: %w", pattern, err)
	}

	return &Rule{
		Raw:    line,
		Regex:  re,
		Action: ActionBlock,
	}, true, nil
}

func parseModifiers(rule *Rule, mods string) error {
	for _, mod := range strings.Split(mods, ",") {
		mod = strings.TrimSpace(mod)
		if mod == "" {
			continue
		}

		key, value, hasValue := strings.Cut(mod, "=")

		switch key {
		case "important":
			rule.Important = true

		case "dnstype":
			for _, name := range strings.Split(value, "|") {
				qtype, known := dns.StringToType[strings.ToUpper(strings.TrimSpace(name))]
				if !known {
					return &ErrUnsupported{Reason: "unknown record type in $dnstype: " + name}
				}
				rule.QTypes = append(rule.QTypes, qtype)
			}

		case "dnsrewrite":
			if !hasValue {
				return &ErrUnsupported{Reason: "$dnsrewrite without a value"}
			}
			if err := parseRewrite(rule, value); err != nil {
				return err
			}

		case "client":
			rule.ClientSpec = strings.Trim(value, "'\"")

		default:
			// Modifiers this engine does not implement change what the rule
			// means, so the rule is dropped instead of being applied without
			// them.
			return &ErrUnsupported{Reason: "unknown modifier $" + key}
		}
	}

	return nil
}

// parseRewrite handles both the short form ($dnsrewrite=1.2.3.4) and the long
// form ($dnsrewrite=NOERROR;A;1.2.3.4).
func parseRewrite(rule *Rule, value string) error {
	parts := strings.Split(value, ";")
	target := parts[len(parts)-1]

	switch strings.ToUpper(target) {
	case "NXDOMAIN":
		rule.Action = ActionRewrite
		rule.RewriteNXDOMAIN = true

		return nil
	case "REFUSED", "NODATA":
		return &ErrUnsupported{Reason: "$dnsrewrite response code " + target}
	}

	addr, err := netip.ParseAddr(target)
	if err != nil {
		return &ErrUnsupported{Reason: "$dnsrewrite target is not an address: " + target}
	}

	rule.Action = ActionRewrite
	rule.RewriteIPs = append(rule.RewriteIPs, addr)

	return nil
}

// stripComment removes a trailing comment from a domain or hosts line.
func stripComment(field string) string {
	if idx := strings.IndexAny(field, "#!"); idx >= 0 {
		field = field[:idx]
	}

	return strings.TrimSpace(field)
}

// normaliseDomain lowercases a name and strips the decorations lists use, so
// that "*.Example.COM." and "example.com" hash to the same value.
func normaliseDomain(domain string) (string, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimSuffix(domain, ".")
	domain = strings.TrimPrefix(domain, "*.")

	if domain == "" {
		return "", nil
	}

	// A wildcard anywhere else ("ads.*", "a*b.com") cannot be expressed as a
	// suffix match, and pretending otherwise would over-block.
	if strings.Contains(domain, "*") {
		return "", &ErrUnsupported{Reason: "wildcard is not a domain suffix"}
	}

	if len(domain) > 253 {
		return "", fmt.Errorf("domain %q is longer than 253 characters", domain)
	}

	for _, r := range domain {
		switch {
		case r >= 'a' && r <= 'z',
			r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
		default:
			// Internationalised names must arrive already punycoded; a raw
			// unicode name would never match a query, which arrives encoded.
			return "", &ErrUnsupported{Reason: "name contains characters outside the DNS presentation format"}
		}
	}

	return domain, nil
}
