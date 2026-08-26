package intel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/MmTKya/DNS/internal/store"
)

// Verdicts.
const (
	VerdictUnknown   = "unknown"
	VerdictClean     = "clean"
	VerdictSuspect   = "suspect"
	VerdictMalicious = "malicious"
)

// Cache lifetimes.
//
// A clean answer expires sooner than a malicious one on purpose: a domain that
// is fine today can be compromised tomorrow, while a domain a national CERT
// has listed is not going to become respectable overnight.
const (
	cleanTTL     = 24 * time.Hour
	suspectTTL   = 3 * 24 * time.Hour
	maliciousTTL = 7 * 24 * time.Hour
)

// Score thresholds.
const (
	// suspectScore is where a name becomes worth telling the operator about.
	suspectScore = 40

	// maliciousScore is where the evidence is strong enough that automatic
	// blocking is defensible, if the operator has switched it on.
	maliciousScore = 70
)

// newbyThresholdDays is how young a domain has to be to count as newly
// registered.
//
// A judgment call, not a measurement: long enough that a legitimate small
// site — which takes weeks to get a cert, get indexed, get real traffic —
// is not branded suspicious forever, short enough to still catch the
// overwhelming majority of throwaway phishing infrastructure, which is
// typically used within days of registration and abandoned within weeks.
const newbyThresholdDays = 90

// Settings keys for the API credentials, kept in the database rather than the
// config file because they are entered in the panel.
const (
	SettingAbuseChKey      = "intel.abusech_key"
	SettingSafeBrowsingKey = "intel.safebrowsing_key"
	SettingOTXKey          = "intel.otx_key"

	// SettingEnforcementMode records how the node is allowed to act on strong
	// findings. Kept in the settings table, not the config file, for the same
	// reason SettingPanelPort is: a mode chosen through the panel has to be
	// readable back through the same door it was set through.
	SettingEnforcementMode = "intel.enforcement_mode"
)

// Enforcement modes.
const (
	// ModeTransparent only watches and logs. Nothing is ever blocked without
	// a person choosing to.
	ModeTransparent = "transparent"

	// ModeDefense investigates and tells the operator, and blocks findings
	// strong enough to act on — but Assessment.Malicious already excludes a
	// widely used or well-evidenced name, so this mode can never auto-block
	// one of those regardless of score.
	ModeDefense = "defense"
)

// Assessment is what the enricher concluded about a domain.
type Assessment struct {
	Domain    string    `json:"domain"`
	Verdict   string    `json:"verdict"`
	Findings  []Finding `json:"findings"`
	CheckedAt time.Time `json:"checked_at"`
	Score     int       `json:"score"`
	Cached    bool      `json:"cached"`

	// Reputable marks a name too widely used to act on a report about. The
	// findings are kept and shown; they simply do not reach the score that
	// blocks something without being asked.
	Reputable bool `json:"reputable,omitempty"`

	// HasValidTLS is nil until checked — never checked must not be mistaken
	// for checked-and-failed, which is exactly the mix-up that put claude.ai
	// in front of the operator as something to block.
	HasValidTLS *bool `json:"has_valid_tls,omitempty"`

	// TLSNote explains an invalid result: no response, an untrusted chain, or
	// a hostname mismatch. Set only when HasValidTLS is non-nil and false.
	TLSNote string `json:"tls_note,omitempty"`

	// DomainAgeDays is nil when unknown — RDAP had nothing, or was never
	// asked. Never treated as "new" on a nil value.
	DomainAgeDays *int `json:"domain_age_days,omitempty"`

	// Protected marks a name with a certificate a trusted root vouches for,
	// on a domain that has existed long enough not to be throwaway phishing
	// infrastructure. Earned on evidence rather than reputation, and treated
	// the same way Reputable is: kept and shown, never blocked on its own.
	Protected bool `json:"protected,omitempty"`

	// HighRisk marks the combination the operator asked to be warned about
	// loudly: newly registered and no certificate a browser would trust. It
	// is shown, not scored — on its own it is what every legitimate new site
	// looks like on day one, so folding it into Score would punish domains no
	// threat source has flagged at all.
	HighRisk     bool   `json:"high_risk,omitempty"`
	HighRiskNote string `json:"high_risk_note,omitempty"`

	// Note explains a verdict that is not what the score alone would give.
	Note string `json:"note,omitempty"`

	// Consulted records what each source did, which is the difference
	// between "three sources looked and found nothing" and "three sources
	// were never asked". Both produce an empty Findings list, and only one of
	// them means the name is probably fine.
	Consulted []SourceOutcome `json:"consulted,omitempty"`
}

// SourceOutcome is one source's part in a lookup.
type SourceOutcome struct {
	Name string `json:"name"`

	// Status is one of: reported, clean, unconfigured, failed.
	Status string `json:"status"`

	// Error is why it failed, when it did.
	Error string `json:"error,omitempty"`
}

// Outcomes a source can have.
const (
	OutcomeReported     = "reported"
	OutcomeClean        = "clean"
	OutcomeUnconfigured = "unconfigured"
	OutcomeFailed       = "failed"
)

// Malicious reports whether the evidence is strong enough to act on
// automatically.
//
// Never for a widely used name, and never for a name with a certificate a
// trusted root vouches for on a domain old enough not to be throwaway
// infrastructure. Blocking either on an unverified report takes a working
// service away from the whole household, which is a larger and far more
// certain harm than whatever the report describes — this is the single
// choke point that makes that structurally impossible, not a convention
// enforcement mode has to remember to respect.
func (a Assessment) Malicious() bool {
	return a.Score >= maliciousScore && !a.Reputable && !a.Protected
}

// Suspect reports whether the name is worth asking the operator about.
func (a Assessment) Suspect() bool { return a.Score >= suspectScore }

// HasOfficialFinding reports whether a state CERT's own investigation is
// among the findings, as opposed to only community heuristics.
func (a Assessment) HasOfficialFinding() bool {
	for _, f := range a.Findings {
		if f.Official {
			return true
		}
	}

	return false
}

// Enricher asks the configured sources about a domain and caches the answer.
type Enricher struct {
	db     *store.DB
	logger *slog.Logger

	mu      sync.RWMutex
	sources []Source

	// tlsCheck and ageCheck are swappable so tests can drive EnrichSignals
	// without a real network — the same reason panelport's listen is a field
	// rather than a direct net.Listen call.
	tlsCheck func(ctx context.Context, domain string) (bool, string)
	ageCheck func(ctx context.Context, db *store.DB, domain string) *int
}

// New creates an enricher with the local sources only.  Call Configure to add
// the remote ones once their credentials are known.
func New(db *store.DB, logger *slog.Logger) *Enricher {
	if logger == nil {
		logger = slog.Default()
	}

	e := &Enricher{
		db:       db,
		logger:   logger.With("component", "intel"),
		tlsCheck: checkTLS,
		ageCheck: domainAge,
	}
	e.sources = []Source{&SGBSource{DB: db}}

	return e
}

// Configure reloads the remote sources from the stored credentials.
func (e *Enricher) Configure(ctx context.Context) error {
	abusech, _, err := e.db.GetSetting(ctx, SettingAbuseChKey)
	if err != nil {
		return err
	}
	safeBrowsing, _, err := e.db.GetSetting(ctx, SettingSafeBrowsingKey)
	if err != nil {
		return err
	}
	otx, _, err := e.db.GetSetting(ctx, SettingOTXKey)
	if err != nil {
		return err
	}

	sources := []Source{
		&SGBSource{DB: e.db},
		&SafeBrowsingSource{APIKey: safeBrowsing},
		&URLhausSource{AuthKey: abusech},
		&ThreatFoxSource{AuthKey: abusech},
		&OTXSource{APIKey: otx},
	}

	e.mu.Lock()
	e.sources = sources
	e.mu.Unlock()

	return nil
}

// SourceStatus describes one source for the panel.
type SourceStatus struct {
	Name       string `json:"name"`
	Configured bool   `json:"configured"`
}

// Sources reports which sources are usable, so the panel can show what is
// missing a key rather than silently doing less than the operator expects.
func (e *Enricher) Sources() []SourceStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	statuses := make([]SourceStatus, 0, len(e.sources))
	for _, s := range e.sources {
		statuses = append(statuses, SourceStatus{Name: s.Name(), Configured: s.Configured()})
	}

	return statuses
}

// Assess returns what is known about a domain, consulting the cache first.
func (e *Enricher) Assess(ctx context.Context, domain string) (assessment Assessment, err error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return Assessment{}, errors.New("a domain is required")
	}

	if cached, found, cacheErr := e.cached(ctx, domain); cacheErr == nil && found {
		return temper(cached), nil
	}

	assessment = Assessment{Domain: domain, CheckedAt: time.Now()}

	e.mu.RLock()
	sources := make([]Source, len(e.sources))
	copy(sources, e.sources)
	e.mu.RUnlock()

	for _, source := range sources {
		if !source.Configured() {
			assessment.Consulted = append(assessment.Consulted, SourceOutcome{
				Name: source.Name(), Status: OutcomeUnconfigured,
			})

			continue
		}

		finding, lookupErr := source.Lookup(ctx, domain)
		if lookupErr != nil {
			// One source being down must not deny the others their say — but
			// it must not be mistaken for one that looked and found nothing
			// either, which is what happened while this only went to the log.
			e.logger.DebugContext(ctx, "threat source lookup failed",
				"source", source.Name(), "domain", domain, "err", lookupErr)

			assessment.Consulted = append(assessment.Consulted, SourceOutcome{
				Name: source.Name(), Status: OutcomeFailed, Error: lookupErr.Error(),
			})

			continue
		}
		if finding == nil {
			// Asked, answered, nothing on file. The most common outcome, and
			// the one worth being able to distinguish from the others.
			assessment.Consulted = append(assessment.Consulted, SourceOutcome{
				Name: source.Name(), Status: OutcomeClean,
			})

			continue
		}

		assessment.Consulted = append(assessment.Consulted, SourceOutcome{
			Name: source.Name(), Status: OutcomeReported,
		})
		assessment.Findings = append(assessment.Findings, *finding)
	}

	assessment.Score, assessment.Verdict = score(assessment.Findings)
	assessment = temper(assessment)

	if err = e.store(ctx, assessment); err != nil {
		e.logger.ErrorContext(ctx, "caching verdict", "domain", domain, "err", err)
	}

	return assessment, nil
}

// score combines findings into a single number and a verdict.
//
// Sources are not simply added up: agreement between independent sources is
// worth more than one source shouting. The strongest finding sets the floor,
// and each additional agreeing source adds a diminishing amount.
func score(findings []Finding) (total int, verdict string) {
	if len(findings) == 0 {
		return 0, VerdictClean
	}

	highest := 0
	for _, f := range findings {
		if f.Score > highest {
			highest = f.Score
		}
	}

	total = highest
	for range len(findings) - 1 {
		total += 10
	}

	if total > 100 {
		total = 100
	}

	switch {
	case total >= maliciousScore:
		return total, VerdictMalicious
	case total >= suspectScore:
		return total, VerdictSuspect
	default:
		return total, VerdictClean
	}
}

// temper holds back the verdict on a name too widely used, or too well
// evidenced, to act on.
//
// Applied after scoring rather than inside it, and safe to apply more than
// once — from the cache read, and again once the TLS/RDAP signals arrive —
// so that a name added to the list later, or a signal that only just
// finished checking, is covered by an answer scored before it was.
func temper(assessment Assessment) Assessment {
	if len(assessment.Findings) > 0 && Reputable(assessment.Domain) {
		assessment.Reputable = true
		assessment.Note = reputableNote

		// The score is left alone: it is what the sources said, and rewriting
		// it would hide the disagreement rather than explain it.
		if assessment.Verdict == VerdictMalicious {
			assessment.Verdict = VerdictSuspect
		}
	}

	if protected(assessment) {
		assessment.Protected = true
		if assessment.Note == "" {
			assessment.Note = protectedNote
		}
		if assessment.Verdict == VerdictMalicious {
			assessment.Verdict = VerdictSuspect
		}
	}

	if highRisk(assessment) {
		assessment.HighRisk = true
		assessment.HighRiskNote = highRiskNote
	}

	return assessment
}

// protected reports whether a name has earned the same restraint a
// well-known name gets, on evidence rather than reputation: a certificate a
// trusted root vouches for, on a domain that has existed long enough not to
// be throwaway phishing infrastructure.
//
// Unknown age counts in its favour, not against it — a lookup that could not
// tell is not evidence of anything, and an unchecked TLS state never counts
// as protection.
func protected(a Assessment) bool {
	if a.HasValidTLS == nil || !*a.HasValidTLS {
		return false
	}

	return a.DomainAgeDays == nil || *a.DomainAgeDays >= newbyThresholdDays
}

// highRisk reports the combination the operator asked to be warned about
// loudly. Both signals must be known — an unknown age or an unchecked TLS
// state must never trigger it, the same fail-open rule protected relies on.
func highRisk(a Assessment) bool {
	return a.DomainAgeDays != nil && *a.DomainAgeDays < newbyThresholdDays &&
		a.HasValidTLS != nil && !*a.HasValidTLS
}

// protectedNote is what the panel says instead of a verdict when the
// protection came from evidence rather than a hand-kept list.
const protectedNote = "a valid certificate from a trusted authority, on a domain old enough not to be " +
	"throwaway infrastructure — kept for you to look at, not blocked on a report alone"

// highRiskNote is the warning shown for a newly registered, unverified name.
const highRiskNote = "yeni kaydedilmiş ve tarayıcıların güvendiği bir sertifikası yok — " +
	"atılmış phishing altyapısının tipik görünümü, ama her yeni meşru site de ilk günlerinde böyle görünür"

// EnrichSignals attaches the TLS and domain-age signals to an assessment and
// re-applies temper now that they are known.
//
// Deliberately separate from Assess: these need a real network round trip —
// up to several seconds for TLS, more for a cold RDAP lookup — which is fine
// for the background suggestion queue but would make every fast cached
// lookup slow. Callers that already have a person waiting (the manual
// "ask about a name" lookup) may call this too; callers on a hot path never
// should.
func (e *Enricher) EnrichSignals(ctx context.Context, assessment Assessment) Assessment {
	valid, reason := e.tlsCheck(ctx, assessment.Domain)
	assessment.HasValidTLS = &valid
	if !valid {
		assessment.TLSNote = reason
	}

	assessment.DomainAgeDays = e.ageCheck(ctx, e.db, assessment.Domain)

	if err := e.recordSignals(ctx, assessment); err != nil {
		e.logger.ErrorContext(ctx, "caching TLS signal", "domain", assessment.Domain, "err", err)
	}

	return temper(assessment)
}

// recordSignals patches the TLS result onto the cached verdict row.
//
// An UPDATE, not an upsert: EnrichSignals only ever runs after Assess, which
// always leaves a row behind, so there is always something here to patch.
func (e *Enricher) recordSignals(ctx context.Context, assessment Assessment) error {
	if assessment.HasValidTLS == nil {
		return nil
	}

	if _, err := e.db.Writer().ExecContext(ctx, `
		UPDATE intel_verdicts SET tls_valid = ?, tls_checked_at = ? WHERE domain = ?
	`, *assessment.HasValidTLS, time.Now().Unix(), assessment.Domain); err != nil {
		return fmt.Errorf("storing tls signal: %w", err)
	}

	return nil
}

func (e *Enricher) cached(ctx context.Context, domain string) (assessment Assessment, found bool, err error) {
	var (
		findings     string
		checkedAt    int64
		expiresAt    int64
		tlsValid     sql.NullInt64
		tlsCheckedAt int64
	)

	row := e.db.Reader().QueryRowContext(ctx, `
		SELECT score, verdict, findings, checked_at, expires_at, tls_valid, tls_checked_at
		FROM intel_verdicts WHERE domain = ?
	`, domain)

	err = row.Scan(&assessment.Score, &assessment.Verdict, &findings, &checkedAt, &expiresAt,
		&tlsValid, &tlsCheckedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Assessment{}, false, nil
	case err != nil:
		return Assessment{}, false, fmt.Errorf("reading cached verdict: %w", err)
	}

	if time.Now().Unix() > expiresAt {
		return Assessment{}, false, nil
	}

	assessment.Domain = domain
	assessment.CheckedAt = time.Unix(checkedAt, 0)
	assessment.Cached = true

	if err = json.Unmarshal([]byte(findings), &assessment.Findings); err != nil {
		assessment.Findings = nil
	}

	// tls_checked_at is 0 for a row nobody has ever run a TLS check against —
	// distinct from a check that ran and found nothing wrong, which is the
	// mix-up this whole signal exists to avoid repeating.
	if tlsCheckedAt > 0 && tlsValid.Valid {
		valid := tlsValid.Int64 != 0
		assessment.HasValidTLS = &valid
	}

	assessment.DomainAgeDays = cachedAgeDays(ctx, e.db, domain)

	return assessment, true, nil
}

func (e *Enricher) store(ctx context.Context, assessment Assessment) error {
	findings, err := json.Marshal(assessment.Findings)
	if err != nil {
		return fmt.Errorf("encoding findings: %w", err)
	}

	ttl := cleanTTL
	switch assessment.Verdict {
	case VerdictMalicious:
		ttl = maliciousTTL
	case VerdictSuspect:
		ttl = suspectTTL
	}

	now := time.Now()
	if _, err = e.db.Writer().ExecContext(ctx, `
		INSERT INTO intel_verdicts (domain, score, verdict, findings, checked_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET
			score = excluded.score, verdict = excluded.verdict,
			findings = excluded.findings, checked_at = excluded.checked_at,
			expires_at = excluded.expires_at
	`, assessment.Domain, assessment.Score, assessment.Verdict, string(findings),
		now.Unix(), now.Add(ttl).Unix(),
	); err != nil {
		return fmt.Errorf("storing verdict: %w", err)
	}

	return nil
}

// PurgeExpired removes stale cached verdicts.
func (e *Enricher) PurgeExpired(ctx context.Context) error {
	if _, err := e.db.Writer().ExecContext(ctx,
		`DELETE FROM intel_verdicts WHERE expires_at < ?`, time.Now().Unix()); err != nil {
		return fmt.Errorf("purging verdicts: %w", err)
	}

	return nil
}
