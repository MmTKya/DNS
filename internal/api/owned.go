package api

import (
	"net/http"
	"strings"

	"github.com/MmTKya/DNS/internal/intel"
	"github.com/go-chi/chi/v5"
)

// handleListOwnedDomains returns the domains the operator has declared as
// their own.
func (s *Server) handleListOwnedDomains(w http.ResponseWriter, r *http.Request) {
	domains, err := intel.ListOwnedDomains(r.Context(), s.deps.Store)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	s.writeJSON(w, r, http.StatusOK, map[string]any{"domains": domains})
}

type addOwnedDomainRequest struct {
	Domain string `json:"domain"`
	Label  string `json:"label"`
}

// handleAddOwnedDomain records a domain as the operator's own, so the
// suggestion queue stops treating it as an unknown third-party name.
func (s *Server) handleAddOwnedDomain(w http.ResponseWriter, r *http.Request) {
	var req addOwnedDomainRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}

	if err := intel.AddOwnedDomain(r.Context(), s.deps.Store, req.Domain, req.Label); err != nil {
		s.writeError(w, r, http.StatusBadRequest, err.Error())

		return
	}

	s.reloadOwnedDomains(r)
	s.audit(r, "intel.owned.add", req.Domain, req.Label, true)
	w.WriteHeader(http.StatusCreated)
}

// handleDeleteOwnedDomain forgets a domain the operator no longer wants
// excluded from review.
func (s *Server) handleDeleteOwnedDomain(w http.ResponseWriter, r *http.Request) {
	domain := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "domain")))

	found, err := intel.RemoveOwnedDomain(r.Context(), s.deps.Store, domain)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}
	if !found {
		s.writeError(w, r, http.StatusNotFound, "no such owned domain")

		return
	}

	s.reloadOwnedDomains(r)
	s.audit(r, "intel.owned.remove", domain, "", true)
	w.WriteHeader(http.StatusNoContent)
}

// reloadOwnedDomains refreshes the in-memory set the queue's hot path
// consults, so an add or a removal takes effect immediately rather than at
// the next restart.
func (s *Server) reloadOwnedDomains(r *http.Request) {
	if s.deps.Suggestions == nil {
		return
	}

	if err := s.deps.Suggestions.LoadOwned(r.Context()); err != nil {
		s.deps.Logger.ErrorContext(r.Context(), "reloading owned domains", "err", err)
	}
}
