package intel

import (
	_ "embed"
	"strings"
	"sync"
)

// Some names are too widely used to block on an intelligence report.
//
// The sources this node consults are built for throwaway domains: a name
// registered last week, used by one piece of malware, then abandoned. Against
// those they are excellent. Against a name half the internet depends on they
// are actively dangerous, for two reasons that both showed up in the field.
//
// The first is dead drops. Some malware does not carry its command address —
// it fetches a page on a popular site where the real address is hidden in a
// comment or a video description. The analyst records what the sample
// contacted, which is the popular site, and submits it as the command
// address. The report is true about the sample and useless as a blocking rule:
// acting on it takes the site away from everyone in the house to inconvenience
// no attacker at all.
//
// The second is bulk community reports. A shared list of "indicators" is often
// a whole connection log pasted in, and every popular name a machine talked to
// while it was infected ends up in it. Being named in fifty of those measures
// how popular a name is at least as much as how dangerous.
//
// So a report against one of these names is kept and shown — the household may
// still want to know — but it never reaches the score that blocks something on
// its own.

//go:embed reputable.txt
var reputableList string

var (
	reputableOnce sync.Once
	reputable     map[string]bool
)

// Reputable reports whether a name is well enough known that an intelligence
// report about it should be shown rather than acted on.
//
// Subdomains count: a report against a name under a well-known domain is the
// same situation, since that is exactly where a dead drop lives.
func Reputable(domain string) bool {
	reputableOnce.Do(func() {
		reputable = make(map[string]bool, 512)
		for line := range strings.Lines(reputableList) {
			if name := strings.TrimSpace(line); name != "" && !strings.HasPrefix(name, "#") {
				reputable[strings.ToLower(name)] = true
			}
		}
	})

	name := strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	if name == "" {
		return false
	}

	// Walk up the labels: www.youtube.com, youtube.com, com.
	for {
		if reputable[name] {
			return true
		}

		_, rest, found := strings.Cut(name, ".")
		if !found {
			return false
		}

		name = rest
	}
}

// reputableNote is what the panel says instead of a verdict, so the operator
// knows the report was seen and why it was not acted on.
const reputableNote = "a widely used name — kept for you to look at, not blocked on a report alone, " +
	"because malware routinely uses popular sites to hide its real address and the report names the site"
