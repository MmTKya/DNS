package api

import (
	"net/http"
	"strings"

	"github.com/MmTKya/DNS/internal/feeds"
	"github.com/MmTKya/DNS/internal/intel"
	"github.com/go-chi/chi/v5"
)

// handleSuggestions returns what the node thinks is worth blocking.
func (s *Server) handleSuggestions(w http.ResponseWriter, r *http.Request) {
	if s.deps.Store == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "storage is not configured")

		return
	}

	status := r.URL.Query().Get("status")
	if status == "" {
		status = intel.StatusPending
	}
	if status == "all" {
		status = ""
	}

	suggestions, err := intel.ListSuggestions(r.Context(), s.deps.Store, status, 200)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	pending, err := intel.PendingCount(r.Context(), s.deps.Store)
	if err != nil {
		s.deps.Logger.ErrorContext(r.Context(), "counting suggestions", "err", err)
	}

	var sources []intel.SourceStatus
	if s.deps.Intel != nil {
		sources = s.deps.Intel.Sources()
	}

	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"suggestions": suggestions,
		"pending":     pending,
		"sources":     sources,
	})
}

type decisionRequest struct {
	Decision string `json:"decision"`
}

// handleDecideSuggestion records the operator's answer and, for a block or an
// allow, writes the rule that carries it out.
//
// Recording the decision without acting on it would be the worst of both
// worlds: the question stops being asked and nothing changes.
func (s *Server) handleDecideSuggestion(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "domain")))
	if domain == "" {
		s.writeError(w, r, http.StatusBadRequest, "a domain is required")

		return
	}

	var req decisionRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}

	switch req.Decision {
	case intel.StatusBlocked:
		if _, err := feeds.AddUserRule(r.Context(), s.deps.Store,
			"||"+domain+"^", "blocked from a threat-intelligence suggestion"); err != nil {
			s.writeError(w, r, http.StatusInternalServerError, err.Error())

			return
		}

	case intel.StatusAllowed:
		if _, err := feeds.AddUserRule(r.Context(), s.deps.Store,
			"@@||"+domain+"^", "allowed from a threat-intelligence suggestion"); err != nil {
			s.writeError(w, r, http.StatusInternalServerError, err.Error())

			return
		}

	case intel.StatusIgnored:
		// Nothing to enforce: the operator has simply seen it and moved on.

	default:
		s.writeError(w, r, http.StatusBadRequest, "decision must be blocked, allowed or ignored")

		return
	}

	found, err := intel.Decide(r.Context(), s.deps.Store, domain, req.Decision)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}
	if !found {
		s.writeError(w, r, http.StatusNotFound, "no suggestion for that name")

		return
	}

	if req.Decision != intel.StatusIgnored {
		s.recompileInBackground()
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleIntelLookup asks the sources about one name on demand, which is what
// the panel's "why was this blocked" and "is this safe" buttons call.
func (s *Server) handleIntelLookup(w http.ResponseWriter, r *http.Request) {
	if s.deps.Intel == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "threat intelligence is not configured")

		return
	}

	domain := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "domain")))
	if domain == "" {
		s.writeError(w, r, http.StatusBadRequest, "a domain is required")

		return
	}

	assessment, err := s.deps.Intel.Assess(r.Context(), domain)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, err.Error())

		return
	}

	s.writeJSON(w, r, http.StatusOK, assessment)
}

type intelKeysRequest struct {
	AbuseCh      *string `json:"abusech_key,omitempty"`
	SafeBrowsing *string `json:"safebrowsing_key,omitempty"`
	OTX          *string `json:"otx_key,omitempty"`
	AutoBlock    *bool   `json:"auto_block,omitempty"`
}

// handleIntelSources reports which threat sources are usable.
//
// Whether a key is set, never the key itself: the point of writing them
// through a write-only endpoint is lost if another one hands them back.
func (s *Server) handleIntelSources(w http.ResponseWriter, r *http.Request) {
	if s.deps.Intel == nil {
		s.writeJSON(w, r, http.StatusOK, map[string]any{"sources": []any{}})

		return
	}

	s.writeJSON(w, r, http.StatusOK, map[string]any{"sources": s.deps.Intel.Sources()})
}

// handleIntelSettings stores the API credentials.
//
// Keys are write-only through this endpoint: they are never read back, so a
// borrowed session cannot walk off with the operator's credentials.
func (s *Server) handleIntelSettings(w http.ResponseWriter, r *http.Request) {
	if s.deps.Intel == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "threat intelligence is not configured")

		return
	}

	var req intelKeysRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}

	settings := map[string]*string{
		intel.SettingAbuseChKey:      req.AbuseCh,
		intel.SettingSafeBrowsingKey: req.SafeBrowsing,
		intel.SettingOTXKey:          req.OTX,
	}

	for key, value := range settings {
		if value == nil {
			continue
		}
		if err := s.deps.Store.SetSetting(r.Context(), key, strings.TrimSpace(*value)); err != nil {
			s.writeError(w, r, http.StatusInternalServerError, err.Error())

			return
		}
	}

	if req.AutoBlock != nil && s.deps.Suggestions != nil {
		s.deps.Suggestions.SetAutoBlock(*req.AutoBlock)

		value := "false"
		if *req.AutoBlock {
			value = "true"
		}
		if err := s.deps.Store.SetSetting(r.Context(), intel.SettingAutoBlock, value); err != nil {
			s.writeError(w, r, http.StatusInternalServerError, err.Error())

			return
		}
	}

	if err := s.deps.Intel.Configure(r.Context()); err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	s.writeJSON(w, r, http.StatusOK, map[string]any{"sources": s.deps.Intel.Sources()})
}
