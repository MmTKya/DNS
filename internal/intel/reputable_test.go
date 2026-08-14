package intel

import "testing"

func TestWellKnownNamesAreRecognisedIncludingTheirSubdomains(t *testing.T) {
	// A dead drop lives on a subdomain of a popular site as often as on the
	// site itself, so the check has to walk up the labels.
	for _, name := range []string{
		"youtube.com",
		"www.youtube.com",
		"m.youtube.com",
		"rr3---sn-4g5e6nz7.googlevideo.com",
		"gib.gov.tr",
		"internetsube.isbank.com.tr",
		"api.github.com",
		"YOUTUBE.COM",
		"youtube.com.",
	} {
		if !Reputable(name) {
			t.Errorf("%q was not recognised as widely used", name)
		}
	}
}

func TestAThrowawayDomainIsNotProtected(t *testing.T) {
	// The whole point is that the protection is narrow. A name nobody has
	// heard of gets the full weight of whatever the sources say.
	for _, name := range []string{
		"nodemetrics3379.com",
		"youtube.com.evil.example",
		"notyoutube.com",
		"youtube.co",
		"",
	} {
		if Reputable(name) {
			t.Errorf("%q was treated as widely used", name)
		}
	}
}

func TestATopLevelDomainDoesNotProtectEverythingUnderIt(t *testing.T) {
	// Walking up the labels ends at a name in the list, and "com" must never
	// be one — that would switch the sources off entirely.
	if Reputable("com") || Reputable("net") || Reputable("tr") {
		t.Fatal("a bare suffix is protecting everything under it")
	}
}

func TestAWidelyUsedNameIsNeverActedOnAutomatically(t *testing.T) {
	// The case this was written for: threat intelligence reported YouTube as
	// a command-and-control address, because a loader used it to hide the
	// real one. Blocking it takes YouTube away from the whole house and
	// inconveniences no attacker at all.
	assessment := temper(Assessment{
		Domain:  "www.youtube.com",
		Score:   90,
		Verdict: VerdictMalicious,
		Findings: []Finding{
			{Source: "threatfox", Detail: "botnet_cc (Unknown Loader)", Score: 60, Malicious: true},
			{Source: "otx", Detail: "named in 50 community threat reports", Score: 45, Malicious: true},
		},
	})

	if assessment.Malicious() {
		t.Fatal("a widely used name would have been blocked without being asked")
	}
	if !assessment.Reputable || assessment.Note == "" {
		t.Fatal("nothing explains why the verdict was held back")
	}
	if assessment.Verdict != VerdictSuspect {
		t.Fatalf("verdict = %q, want %q", assessment.Verdict, VerdictSuspect)
	}

	// Still worth showing. Holding back the block is not the same as
	// pretending the sources said nothing.
	if !assessment.Suspect() {
		t.Fatal("the report was discarded rather than shown")
	}
	if assessment.Score != 90 {
		t.Fatalf("score = %d, want the sources' own figure kept", assessment.Score)
	}
	if len(assessment.Findings) != 2 {
		t.Fatal("the findings were dropped")
	}
}

func TestAThrowawayDomainIsStillBlockedAutomatically(t *testing.T) {
	assessment := temper(Assessment{
		Domain:   "nodemetrics3379.com",
		Score:    90,
		Verdict:  VerdictMalicious,
		Findings: []Finding{{Source: "threatfox", Score: 90, Malicious: true}},
	})

	if !assessment.Malicious() {
		t.Fatal("the guard is catching names it was not meant to")
	}
	if assessment.Note != "" {
		t.Fatalf("note = %q, want none", assessment.Note)
	}
}

func TestAWidelyUsedNameNothingWasSaidAboutIsUntouched(t *testing.T) {
	// No findings means no accusation to explain, and a clean verdict should
	// not carry a note about why it was not blocked.
	assessment := temper(Assessment{Domain: "youtube.com", Verdict: VerdictClean})

	if assessment.Reputable || assessment.Note != "" {
		t.Fatal("a clean name was annotated")
	}
}
