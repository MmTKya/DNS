package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/MmTKya/DNS/internal/upstreams"
	"github.com/go-chi/chi/v5"
)

// benchmarkTimeout bounds the whole measurement. Five candidates against four
// names, run in parallel, with room for the slow ones to time out honestly
// rather than being cut off and reported as broken.
const benchmarkTimeout = 45 * time.Second

// handleListUpstreams returns the resolvers this node forwards to.
//
// The defaults are reported alongside, and flagged as defaults, so the screen
// can say which resolvers are actually in use rather than showing an empty
// list on a node that is resolving perfectly well.
func (s *Server) handleListUpstreams(w http.ResponseWriter, r *http.Request) {
	list, err := upstreams.List(r.Context(), s.deps.Store)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	primary, fallback, err := upstreams.Effective(r.Context(), s.deps.Store)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	usingDefaults := primary == nil
	if usingDefaults {
		primary = s.deps.Config.DNS.Upstreams
		fallback = s.deps.Config.DNS.Fallbacks
	}

	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"upstreams":      list,
		"in_use":         primary,
		"fallbacks_used": fallback,
		"using_defaults": usingDefaults,
		"defaults":       s.deps.Config.DNS.Upstreams,
	})
}

type addUpstreamRequest struct {
	Address string `json:"address"`
	Role    string `json:"role"`
	Note    string `json:"note,omitempty"`
}

func (s *Server) handleAddUpstream(w http.ResponseWriter, r *http.Request) {
	var req addUpstreamRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}

	id, err := upstreams.Add(r.Context(), s.deps.Store, req.Address, req.Role, req.Note)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, err.Error())

		return
	}

	s.audit(r, "dns.upstream.add", req.Address, req.Role, true)
	s.reloadDatapath()
	s.writeJSON(w, r, http.StatusCreated, map[string]any{"id": id})
}

type upstreamPatch struct {
	Role    *string `json:"role,omitempty"`
	Enabled *bool   `json:"enabled,omitempty"`
}

func (s *Server) handleUpdateUpstream(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid upstream id")

		return
	}

	var patch upstreamPatch
	if !s.decodeJSON(w, r, &patch) {
		return
	}

	if patch.Role != nil {
		if err = upstreams.SetRole(r.Context(), s.deps.Store, id, *patch.Role); err != nil {
			s.writeError(w, r, http.StatusInternalServerError, err.Error())

			return
		}
	}
	if patch.Enabled != nil {
		if err = upstreams.SetEnabled(r.Context(), s.deps.Store, id, *patch.Enabled); err != nil {
			s.writeError(w, r, http.StatusInternalServerError, err.Error())

			return
		}
	}

	s.audit(r, "dns.upstream.update", chi.URLParam(r, "id"), "", true)
	s.reloadDatapath()
	w.WriteHeader(http.StatusNoContent)
}

// handleDeleteUpstream removes one, which is also how someone goes back to the
// resolvers that shipped: with none left, the defaults apply again.
func (s *Server) handleDeleteUpstream(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid upstream id")

		return
	}

	if err = upstreams.Delete(r.Context(), s.deps.Store, id); err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	s.audit(r, "dns.upstream.delete", chi.URLParam(r, "id"), "", true)
	s.reloadDatapath()
	w.WriteHeader(http.StatusNoContent)
}

// reloadDatapath rebuilds the resolver so a change takes effect now.
//
// Without it the panel would report a resolver the node is not using until
// something restarted it, which is the kind of gap that gets diagnosed as
// "the setting does not work".
func (s *Server) reloadDatapath() {
	if s.deps.ReloadDatapath != nil {
		s.deps.ReloadDatapath()
	}
}

// handleBenchmarkUpstreams measures candidate resolvers from this node.
//
// From this node, not from the panel's browser: what matters is the path the
// resolver will actually take, and a laptop on the same wifi is a different
// path with different latency.
func (s *Server) handleBenchmarkUpstreams(w http.ResponseWriter, r *http.Request) {
	adopt := r.URL.Query().Get("adopt") == "true"

	ctx, cancel := context.WithTimeout(r.Context(), benchmarkTimeout)
	defer cancel()

	results, err := upstreams.Benchmark(ctx, nil, 2*time.Second)
	if err != nil {
		s.writeError(w, r, http.StatusGatewayTimeout, err.Error())

		return
	}

	payload := map[string]any{"results": results}

	if adopt {
		adopted, adoptErr := upstreams.Adopt(ctx, s.deps.Store, results)
		if adoptErr != nil {
			s.audit(r, "dns.upstream.benchmark", "", adoptErr.Error(), false)
			s.writeError(w, r, http.StatusConflict, adoptErr.Error())

			return
		}

		s.audit(r, "dns.upstream.benchmark", strings.Join(adopted, ", "), "adopted", true)
		s.reloadDatapath()
		payload["adopted"] = adopted
	}

	s.writeJSON(w, r, http.StatusOK, payload)
}

// handleUpstreamHealth reports how the resolvers in use are behaving.
//
// Not behind the admin gate: this is the first thing anyone looks at when a
// page will not load, and making them an administrator to find out whether the
// internet is broken would be the wrong shape of answer.
func (s *Server) handleUpstreamHealth(w http.ResponseWriter, r *http.Request) {
	if s.deps.UpstreamHealth == nil {
		s.writeJSON(w, r, http.StatusOK, map[string]any{"available": false})

		return
	}

	results, rescues := s.deps.UpstreamHealth()

	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"available": true,
		"upstreams": results,
		"rescues":   rescues,
	})
}
