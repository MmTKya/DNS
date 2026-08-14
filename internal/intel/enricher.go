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

// Settings keys for the API credentials, kept in the database rather than the
// config file because they are entered in the panel.
const (
	SettingAbuseChKey      = "intel.abusech_key"
	SettingSafeBrowsingKey = "intel.safebrowsing_key"
	SettingOTXKey          = "intel.otx_key"

	// SettingAutoBlock records whether the operator has allowed the node to
	// block strong findings without asking.
	SettingAutoBlock = "intel.auto_block"
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
// Never for a widely used name. Blocking one of those on an unverified report
// takes a working service away from the whole household, which is a larger and
// far more certain harm than whatever the report describes.
func (a Assessment) Malicious() bool { return a.Score >= maliciousScore && !a.Reputable }

// Suspect reports whether the name is worth asking the operator about.
func (a Assessment) Suspect() bool { return a.Score >= suspectScore }

// Enricher asks the configured sources about a domain and caches the answer.
type Enricher struct {
	db     *store.DB
	logger *slog.Logger

	mu      sync.RWMutex
	sources []Source
}

// New creates an enricher with the local sources only.  Call Configure to add
// the remote ones once their credentials are known.
func New(db *store.DB, logger *slog.Logger) *Enricher {
	if logger == nil {
		logger = slog.Default()
	}

	e := &Enricher{
		db:     db,
		logger: logger.With("component", "intel"),
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

// temper holds back the verdict on a name too widely used to act on.
//
// Applied after scoring rather than inside it, and applied again when a
// verdict is read back from the cache, so that a name added to the list later
// is covered by an answer stored before it was.
func temper(assessment Assessment) Assessment {
	if len(assessment.Findings) == 0 || !Reputable(assessment.Domain) {
		return assessment
	}

	assessment.Reputable = true
	assessment.Note = reputableNote

	// The score is left alone: it is what the sources said, and rewriting it
	// would hide the disagreement rather than explain it.
	if assessment.Verdict == VerdictMalicious {
		assessment.Verdict = VerdictSuspect
	}

	return assessment
}

func (e *Enricher) cached(ctx context.Context, domain string) (assessment Assessment, found bool, err error) {
	var (
		findings  string
		checkedAt int64
		expiresAt int64
	)

	row := e.db.Reader().QueryRowContext(ctx, `
		SELECT score, verdict, findings, checked_at, expires_at
		FROM intel_verdicts WHERE domain = ?
	`, domain)

	err = row.Scan(&assessment.Score, &assessment.Verdict, &findings, &checkedAt, &expiresAt)
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
