package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/MmTKya/DNS/internal/feeds"
	"github.com/MmTKya/DNS/internal/filter"
	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
)

// handleListFeeds returns every feed with its state, so the panel can show the
// whole catalogue rather than only what is switched on.
func (s *Server) handleListFeeds(w http.ResponseWriter, r *http.Request) {
	if s.deps.Store == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "storage is not configured")

		return
	}

	records, err := feeds.List(r.Context(), s.deps.Store)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	// The catalogue metadata — licence, cadence, whether a list is known for
	// false positives — is what makes enabling one an informed decision, so it
	// travels with the state.
	type feedView struct {
		feeds.Record
		Catalog *feeds.Feed `json:"catalog,omitempty"`
	}

	views := make([]feedView, 0, len(records))
	for _, record := range records {
		view := feedView{Record: record}
		if meta, ok := feeds.Lookup(record.ID); ok {
			view.Catalog = &meta
		}
		views = append(views, view)
	}

	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"feeds":   views,
		"compile": s.compileSummary(),
	})
}

func (s *Server) compileSummary() any {
	if s.deps.Feeds == nil {
		return nil
	}

	return s.deps.Feeds.LastCompile()
}

// handleFeedCatalog returns the built-in catalogue on its own.
func (s *Server) handleFeedCatalog(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, r, http.StatusOK, map[string]any{"feeds": feeds.Catalog()})
}

type feedEnabledRequest struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) handleSetFeedEnabled(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req feedEnabledRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}

	if err := feeds.SetEnabled(r.Context(), s.deps.Store, id, req.Enabled); err != nil {
		s.writeError(w, r, http.StatusBadRequest, err.Error())

		return
	}

	// Enabling a feed that has never been downloaded should take effect now,
	// not at the next scheduled refresh.
	s.refreshFeedsInBackground(req.Enabled)

	w.WriteHeader(http.StatusNoContent)
}

type addFeedRequest struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

func (s *Server) handleAddFeed(w http.ResponseWriter, r *http.Request) {
	var req addFeedRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}

	if err := feeds.AddCustom(r.Context(), s.deps.Store, req.ID, req.Name, req.URL); err != nil {
		s.writeError(w, r, http.StatusBadRequest, err.Error())

		return
	}

	s.refreshFeedsInBackground(true)
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleDeleteFeed(w http.ResponseWriter, r *http.Request) {
	if err := feeds.Delete(r.Context(), s.deps.Store, chi.URLParam(r, "id")); err != nil {
		s.writeError(w, r, http.StatusBadRequest, err.Error())

		return
	}

	s.recompileInBackground()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRefreshFeeds(w http.ResponseWriter, r *http.Request) {
	if s.deps.Feeds == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "feeds are not configured")

		return
	}

	// Downloading several hundred thousand rules takes longer than a request
	// should, so this is accepted and run in the background; the panel watches
	// the feed list for the result.
	s.refreshFeedsInBackground(true)
	s.writeJSON(w, r, http.StatusAccepted, map[string]string{"status": "refreshing"})
}

// refreshFeedsInBackground runs a refresh detached from the request, with its
// own timeout so a hung download cannot leak a goroutine forever.
func (s *Server) refreshFeedsInBackground(fetch bool) {
	if s.deps.Feeds == nil {
		return
	}

	go func() {
		ctx, cancel := contextWithTimeout(10 * time.Minute)
		defer cancel()

		var err error
		if fetch {
			err = s.deps.Feeds.Refresh(ctx, true)
		} else {
			err = s.deps.Feeds.Compile(ctx)
		}

		if err != nil {
			s.deps.Logger.ErrorContext(ctx, "refreshing feeds", "err", err)
		}
	}()
}

func (s *Server) recompileInBackground() { s.refreshFeedsInBackground(false) }

// handleListRules returns the operator's own rules and the compiled ruleset's
// statistics.
func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	rules, err := feeds.ListUserRules(r.Context(), s.deps.Store)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	var stats filter.Stats
	if s.deps.Filter != nil {
		stats = s.deps.Filter.Stats()
	}

	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"rules": describeRules(rules),
		"stats": stats,
	})
}

// describedRule is a stored rule with what the engine will actually do to it.
//
// Parsed here with the real parser rather than re-implemented in the panel: a
// second implementation of this syntax would drift, and the screen would end
// up describing a rule differently from the resolver that enforces it.
type describedRule struct {
	feeds.UserRule

	Action    string `json:"action"`
	Domain    string `json:"domain,omitempty"`
	Rewrite   string `json:"rewrite,omitempty"`
	QTypes    string `json:"qtypes,omitempty"`
	Client    string `json:"client,omitempty"`
	Subdomain bool   `json:"subdomains"`
	Important bool   `json:"important"`
}

func describeRules(rules []feeds.UserRule) []describedRule {
	described := make([]describedRule, 0, len(rules))

	for _, rule := range rules {
		row := describedRule{UserRule: rule, Action: "block"}

		parsed, ok, err := filter.ParseLine(rule.Rule)
		if err == nil && ok && parsed != nil {
			row.Action = parsed.Action.String()
			row.Domain = parsed.Domain
			row.Subdomain = parsed.Subdomains
			row.Important = parsed.Important
			row.Client = parsed.ClientSpec

			switch {
			case parsed.RewriteNXDOMAIN:
				row.Rewrite = "NXDOMAIN"
			case len(parsed.RewriteIPs) > 0:
				addrs := make([]string, 0, len(parsed.RewriteIPs))
				for _, ip := range parsed.RewriteIPs {
					addrs = append(addrs, ip.String())
				}
				row.Rewrite = strings.Join(addrs, ", ")
			}

			if len(parsed.QTypes) > 0 {
				names := make([]string, 0, len(parsed.QTypes))
				for _, qtype := range parsed.QTypes {
					names = append(names, dns.TypeToString[qtype])
				}
				row.QTypes = strings.Join(names, ", ")
			}

			if parsed.IsRegex() {
				row.Domain = parsed.Regex.String()
			}
		}

		described = append(described, row)
	}

	return described
}

type addRuleRequest struct {
	Rule    string `json:"rule"`
	Comment string `json:"comment,omitempty"`
}

func (s *Server) handleAddRule(w http.ResponseWriter, r *http.Request) {
	var req addRuleRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}

	// Rejecting a rule the engine cannot honour at write time is far kinder
	// than silently dropping it at compile time and leaving the operator
	// wondering why a name is still resolving.
	parsed, ok, err := filter.ParseLine(req.Rule)
	switch {
	case err != nil:
		s.writeError(w, r, http.StatusBadRequest, "rule is not usable: "+err.Error())

		return
	case !ok || parsed == nil:
		s.writeError(w, r, http.StatusBadRequest, "that line is a comment or has no effect at the DNS layer")

		return
	}

	id, err := feeds.AddUserRule(r.Context(), s.deps.Store, req.Rule, req.Comment)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	s.recompileInBackground()
	s.writeJSON(w, r, http.StatusCreated, map[string]any{"id": id})
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid rule id")

		return
	}

	found, err := feeds.DeleteUserRule(r.Context(), s.deps.Store, id)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}
	if !found {
		s.writeError(w, r, http.StatusNotFound, "no such rule")

		return
	}

	s.recompileInBackground()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetRuleEnabled(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid rule id")

		return
	}

	var req feedEnabledRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}

	found, err := feeds.SetUserRuleEnabled(r.Context(), s.deps.Store, id, req.Enabled)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}
	if !found {
		s.writeError(w, r, http.StatusNotFound, "no such rule")

		return
	}

	s.recompileInBackground()
	w.WriteHeader(http.StatusNoContent)
}
