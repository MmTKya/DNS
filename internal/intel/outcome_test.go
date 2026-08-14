package intel

import "testing"

// An empty findings list means two opposite things: every source looked and
// found nothing, or no source was ever asked. Only one of them says the name
// is probably fine, and the screen cannot tell them apart without this.
func TestOutcomesDistinguishAskedFromNotAsked(t *testing.T) {
	t.Parallel()

	a := Assessment{
		Domain: "example.com",
		Consulted: []SourceOutcome{
			{Name: "Safe Browsing", Status: OutcomeClean},
			{Name: "ThreatFox", Status: OutcomeUnconfigured},
			{Name: "OTX", Status: OutcomeFailed, Error: "the configured key was rejected"},
			{Name: "URLhaus", Status: OutcomeReported},
		},
	}

	counts := map[string]int{}
	for _, o := range a.Consulted {
		counts[o.Status]++
	}

	for _, status := range []string{OutcomeClean, OutcomeUnconfigured, OutcomeFailed, OutcomeReported} {
		if counts[status] != 1 {
			t.Errorf("%s appears %d times, want 1", status, counts[status])
		}
	}

	// A failure has to carry its reason, or the screen can only say that
	// something went wrong.
	for _, o := range a.Consulted {
		if o.Status == OutcomeFailed && o.Error == "" {
			t.Error("a failed source did not say why")
		}
	}
}
