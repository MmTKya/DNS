package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/MmTKya/DNS/internal/clients"
	"github.com/MmTKya/DNS/internal/config"
	"github.com/MmTKya/DNS/internal/querylog"
	"github.com/go-chi/chi/v5"
)

// contextWithTimeout is a small indirection so background work started from a
// request does not inherit the request's cancellation.
func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// handleStats returns the dashboard's headline numbers.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"mode": s.deps.Config.Mode,
	}

	if s.deps.QueryLog != nil {
		resp["queries"] = s.deps.QueryLog.Stats()
	}
	if s.deps.Filter != nil {
		resp["filter"] = s.deps.Filter.Stats()
	}
	if s.deps.Feeds != nil {
		resp["compile"] = s.deps.Feeds.LastCompile()
	}

	// Anything the current deployment mode cannot honestly measure is named
	// here, so the panel can disable those widgets rather than showing an
	// invented number.
	resp["capabilities"] = capabilities(s.deps.Config.Mode)

	s.writeJSON(w, r, http.StatusOK, resp)
}

// capabilities states what this deployment can actually measure.
func capabilities(mode config.DeploymentMode) map[string]bool {
	gateway := mode == config.ModeGateway

	return map[string]bool{
		// Available in both modes: a resolver sees every name asked for.
		"query_visibility": true,
		"dns_filtering":    true,
		"per_client_rules": true,

		// Only a node that all traffic passes through can count bytes, time
		// real sessions, or actually cut a device off.
		"bandwidth":         gateway,
		"live_connections":  gateway,
		"real_dwell_time":   gateway,
		"enforced_blocking": gateway,
	}
}

// handleQueryLog returns recent queries: the live ring by default, the
// database when a filter or an older window is asked for.
func (s *Server) handleQueryLog(w http.ResponseWriter, r *http.Request) {
	if s.deps.QueryLog == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "the query log is not configured")

		return
	}

	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	search := querylog.Search{
		Host:    q.Get("host"),
		Client:  q.Get("client"),
		Verdict: q.Get("verdict"),
		Limit:   limit,
	}

	// The ring buffer answers the common case with no disk access at all.
	if search.Host == "" && search.Client == "" && search.Verdict == "" && q.Get("stored") == "" {
		s.writeJSON(w, r, http.StatusOK, map[string]any{
			"entries": s.deps.QueryLog.Recent(limit),
			"source":  "live",
		})

		return
	}

	if since := q.Get("since"); since != "" {
		if ts, err := time.Parse(time.RFC3339, since); err == nil {
			search.Since = ts
		}
	}

	entries, err := s.deps.QueryLog.Query(r.Context(), search)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"entries": entries,
		"source":  "stored",
	})
}

// streamFlushInterval batches live events before writing them out.
//
// A busy network makes thousands of queries a second; one server-sent event
// per query would spend more time in write syscalls than in resolving, and the
// browser would spend the rest of its day in layout.  Batching turns that into
// a few frames a second carrying the same information.
const streamFlushInterval = 200 * time.Millisecond

// handleStream is the live telemetry feed.
//
// Server-sent events, not WebSockets: the traffic is one-way, it is plain
// HTTP so it passes through any reverse proxy, and browsers reconnect on their
// own.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	if s.deps.QueryLog == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "the query log is not configured")

		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		s.writeError(w, r, http.StatusInternalServerError, "streaming is not supported by this server")

		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Nginx buffers proxied responses by default, which would hold the whole
	// stream until the connection closed.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	entries, cancel := s.deps.QueryLog.Subscribe(1024)
	defer cancel()

	ticker := time.NewTicker(streamFlushInterval)
	defer ticker.Stop()

	// A heartbeat keeps intermediaries from closing an idle stream on a quiet
	// network, and lets the panel notice a dead connection.
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()

	batch := make([]querylog.Entry, 0, 256)

	writeBatch := func() bool {
		if len(batch) == 0 {
			return true
		}

		payload, err := json.Marshal(map[string]any{
			"entries": batch,
			"stats":   s.deps.QueryLog.Stats(),
		})
		batch = batch[:0]

		if err != nil {
			s.deps.Logger.ErrorContext(r.Context(), "encoding stream batch", "err", err)

			return true
		}

		if _, err = fmt.Fprintf(w, "event: queries\ndata: %s\n\n", payload); err != nil {
			return false
		}
		flusher.Flush()

		return true
	}

	for {
		select {
		case <-r.Context().Done():
			return

		case entry, open := <-entries:
			if !open {
				return
			}

			batch = append(batch, entry)
			// Cap the batch so a burst cannot grow it without limit between
			// ticks.
			if len(batch) >= 256 && !writeBatch() {
				return
			}

		case <-ticker.C:
			if !writeBatch() {
				return
			}

		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": keep-alive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// handleListClients returns every device the resolver has seen.
func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	if s.deps.Clients == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "client tracking is not configured")

		return
	}

	list, err := s.deps.Clients.List(r.Context())
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"clients": list,
		"mode":    s.deps.Config.Mode,
		// What "pause" actually does depends on the deployment mode, and the
		// panel must not imply a kill switch it cannot deliver.
		"pause_is_enforced": s.deps.Config.Mode == config.ModeGateway,
	})
}

// handleStaleClients lists devices not seen for a while: expired leases and
// retired hardware.
func (s *Server) handleStaleClients(w http.ResponseWriter, r *http.Request) {
	if s.deps.Clients == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "client tracking is not configured")

		return
	}

	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 {
		days = 30
	}

	list, err := s.deps.Clients.Stale(r.Context(), time.Duration(days)*24*time.Hour)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	s.writeJSON(w, r, http.StatusOK, map[string]any{"clients": list, "days": days})
}

type updateClientRequest struct {
	Name             *string `json:"name,omitempty"`
	Tags             *string `json:"tags,omitempty"`
	FilteringEnabled *bool   `json:"filtering_enabled,omitempty"`
	Paused           *bool   `json:"paused,omitempty"`
}

func (s *Server) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	if s.deps.Clients == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "client tracking is not configured")

		return
	}

	var req updateClientRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}

	client, err := s.deps.Clients.Update(r.Context(), chi.URLParam(r, "key"), clients.Update{
		Name:             req.Name,
		Tags:             req.Tags,
		FilteringEnabled: req.FilteringEnabled,
		Paused:           req.Paused,
	})
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, err.Error())

		return
	}

	s.writeJSON(w, r, http.StatusOK, client)
}

func (s *Server) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	if s.deps.Clients == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "client tracking is not configured")

		return
	}

	if err := s.deps.Clients.Delete(r.Context(), chi.URLParam(r, "key")); err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	w.WriteHeader(http.StatusNoContent)
}
