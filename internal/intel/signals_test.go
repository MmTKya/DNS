package intel

import (
	"path/filepath"
	"testing"

	"github.com/MmTKya/DNS/internal/store"
)

func ptr[T any](v T) *T { return &v }

func openTestDB(t *testing.T) *store.DB {
	t.Helper()

	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "seddns.db"))
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	return db
}

func TestAValidCertificateOnAnEstablishedDomainIsNeverMalicious(t *testing.T) {
	t.Parallel()

	a := Assessment{
		Domain:        "definitely-fine.example",
		Score:         100,
		Verdict:       VerdictMalicious,
		HasValidTLS:   ptr(true),
		DomainAgeDays: ptr(365 * 5),
	}
	a = temper(a)

	if !a.Protected {
		t.Error("a valid, old-enough certificate should have earned Protected")
	}
	if a.Malicious() {
		t.Error("a Protected domain must never be Malicious, however high the score")
	}
}

func TestAnUnknownTLSCheckIsNotTreatedAsInvalid(t *testing.T) {
	t.Parallel()

	a := Assessment{Domain: "unchecked.example", Score: 100, Verdict: VerdictMalicious}
	a = temper(a)

	if a.Protected {
		t.Error("an unchecked TLS state must never grant Protected")
	}
	if a.HighRisk {
		t.Error("an unchecked TLS state must never trigger HighRisk")
	}
	if !a.Malicious() {
		t.Error("nothing here should have suppressed Malicious")
	}
}

func TestAnUnknownAgeStillCountsAsProtectedGivenValidTLS(t *testing.T) {
	t.Parallel()

	a := Assessment{
		Domain:      "unknown-age.example",
		Score:       100,
		Verdict:     VerdictMalicious,
		HasValidTLS: ptr(true),
		// DomainAgeDays intentionally nil: unknown age must count in the
		// domain's favour, not against it.
	}
	a = temper(a)

	if !a.Protected {
		t.Error("valid TLS with an unknown age should still be Protected")
	}
}

func TestANewlyRegisteredDomainWithNoValidTLSIsFlaggedHighRiskNotScored(t *testing.T) {
	t.Parallel()

	a := Assessment{
		Domain:        "brand-new.example",
		Score:         0,
		Verdict:       VerdictClean,
		HasValidTLS:   ptr(false),
		DomainAgeDays: ptr(3),
	}
	a = temper(a)

	if !a.HighRisk {
		t.Error("a newly registered domain with no valid TLS should be HighRisk")
	}
	if a.Score != 0 {
		t.Errorf("Score = %d, want 0 — HighRisk must not inflate the score", a.Score)
	}
}

func TestAKnownOldDomainWithNoTLSIsNotHighRisk(t *testing.T) {
	t.Parallel()

	a := Assessment{
		Domain:        "old-no-website.example",
		HasValidTLS:   ptr(false),
		DomainAgeDays: ptr(365 * 10),
	}
	a = temper(a)

	if a.HighRisk {
		t.Error("age alone should not trigger HighRisk")
	}
}

func TestAFailedRDAPLookupNeverCountsAsNew(t *testing.T) {
	t.Parallel()

	db := openTestDB(t)
	ctx := t.Context()

	// No cache entry and a lookup that cannot reach the network (the real
	// rdap.org call is not exercised in unit tests) must resolve to unknown,
	// not to "new".
	got := cachedAgeDays(ctx, db, "never-looked-up.example")
	if got != nil {
		t.Errorf("cachedAgeDays = %v, want nil for a domain never cached", got)
	}
}

func TestANoResponseIsDistinctFromAnInvalidCertificate(t *testing.T) {
	t.Parallel()

	// Nothing listens on 127.0.0.1:443 in the test environment, so this must
	// report TLSNoResponse — never TLSCertInvalid, which would wrongly imply
	// a certificate was actually seen and rejected.
	valid, reason := checkTLS(t.Context(), "127.0.0.1")
	if valid {
		t.Fatal("expected the dial to fail with nothing listening")
	}
	if reason != TLSNoResponse {
		t.Errorf("reason = %q, want %q for an unreachable host", reason, TLSNoResponse)
	}
}
