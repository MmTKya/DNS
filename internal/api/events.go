package api

import (
	"net/http"
	"strconv"

	"github.com/MmTKya/DNS/internal/events"
)

// handleEvents returns what the node has noticed.
//
// Not behind the admin gate, for the same reason the resolver health card is
// not: this is where someone looks when a page will not open, and needing
// administrator rights to read why would make the screen useless at the one
// moment it matters.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if s.deps.Store == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "storage is not configured")

		return
	}

	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))

	list, err := events.List(r.Context(), s.deps.Store, events.Filter{
		Kind:     q.Get("kind"),
		Severity: q.Get("severity"),
		Limit:    limit,
	})
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	// The counts drive which filters the panel offers, so it shows the ones
	// that would return something rather than a row of empty buttons.
	counts, err := events.Counts(r.Context(), s.deps.Store)
	if err != nil {
		s.deps.Logger.WarnContext(r.Context(), "counting events", "err", err)
	}

	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"events": list,
		"counts": counts,
	})
}
