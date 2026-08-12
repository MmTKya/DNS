package api

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/MmTKya/DNS/internal/audit"
	"github.com/MmTKya/DNS/internal/notify"
	"github.com/go-chi/chi/v5"
)

// --- notifications ---

func (s *Server) handleListChannels(w http.ResponseWriter, r *http.Request) {
	// Redacted: a borrowed panel session should not walk away with the
	// household's mail password.
	channels, err := notify.ListChannelsForDisplay(r.Context(), s.deps.Store)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	history, err := notify.RecentAlerts(r.Context(), s.deps.Store, 50)
	if err != nil {
		s.deps.Logger.ErrorContext(r.Context(), "reading alert history", "err", err)
	}

	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"channels": channels,
		"history":  history,
	})
}

type addChannelRequest struct {
	Kind        string         `json:"kind"`
	Name        string         `json:"name"`
	MinSeverity string         `json:"min_severity"`
	Config      map[string]any `json:"config"`
}

func (s *Server) handleAddChannel(w http.ResponseWriter, r *http.Request) {
	var req addChannelRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}

	id, err := notify.AddChannel(r.Context(), s.deps.Store, req.Kind, req.Name, req.MinSeverity, req.Config)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, err.Error())

		return
	}

	s.audit(r, "notify.channel.add", req.Name, req.Kind, true)
	s.writeJSON(w, r, http.StatusCreated, map[string]any{"id": id})
}

// updateTimeout bounds a self-update. Generous on purpose: a Raspberry Pi on
// a slow line still has to fetch a ten-megabyte archive.
const updateTimeout = 15 * time.Minute

// restartGrace is how long the node waits after answering before it exits, so
// the panel is told what happened rather than seeing a dropped connection.
const restartGrace = 750 * time.Millisecond

func (s *Server) handleTestChannel(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid channel id")

		return
	}

	if s.deps.Notify == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "notifications are not configured")

		return
	}

	if err = s.deps.Notify.Test(r.Context(), id); err != nil {
		// The failure is the useful part of a test button, so it is returned
		// rather than logged and hidden behind a generic error.
		s.audit(r, "notify.channel.test", chi.URLParam(r, "id"), err.Error(), false)
		s.writeError(w, r, http.StatusBadGateway, err.Error())

		return
	}

	s.audit(r, "notify.channel.test", chi.URLParam(r, "id"), "", true)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetChannelEnabled(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid channel id")

		return
	}

	var req feedEnabledRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}

	found, err := notify.SetChannelEnabled(r.Context(), s.deps.Store, id, req.Enabled)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}
	if !found {
		s.writeError(w, r, http.StatusNotFound, "no such channel")

		return
	}

	s.audit(r, "notify.channel.enabled", chi.URLParam(r, "id"), strconv.FormatBool(req.Enabled), true)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteChannel(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid channel id")

		return
	}

	found, err := notify.DeleteChannel(r.Context(), s.deps.Store, id)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}
	if !found {
		s.writeError(w, r, http.StatusNotFound, "no such channel")

		return
	}

	s.audit(r, "notify.channel.delete", chi.URLParam(r, "id"), "", true)
	w.WriteHeader(http.StatusNoContent)
}

// --- audit trail ---

func (s *Server) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	if s.deps.Audit == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "the audit log is not configured")

		return
	}

	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))

	query := audit.Query{
		Username: q.Get("username"),
		Action:   q.Get("action"),
		Limit:    limit,
	}
	if days, _ := strconv.Atoi(q.Get("days")); days > 0 {
		query.Since = time.Now().AddDate(0, 0, -days)
	}

	entries, err := s.deps.Audit.List(r.Context(), query)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	s.writeJSON(w, r, http.StatusOK, map[string]any{"entries": entries})
}

// audit records an administrative action.
//
// Only state changes are recorded. A trail that logs every dashboard refresh
// buries the twelve entries that matter under a hundred thousand that do not.
func (s *Server) audit(r *http.Request, action, target, detail string, success bool) {
	if s.deps.Audit == nil {
		return
	}

	username := ""
	if user, ok := userFrom(r.Context()); ok {
		username = user.Username
	}

	s.deps.Audit.Record(r.Context(), audit.Entry{
		Username: username,
		IP:       clientIP(r),
		Action:   action,
		Target:   target,
		Detail:   detail,
		Success:  success,
	})
}

// --- updates ---

func (s *Server) handleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if s.deps.Update == nil {
		s.writeJSON(w, r, http.StatusOK, map[string]any{
			"current": s.deps.Version,
			"managed": false,
			"error":   "updates are not configured for this build",
		})

		return
	}

	status, err := s.deps.Update.Check(r.Context())
	if err != nil {
		// The status carries the error; the request itself succeeded in
		// finding out that the check failed.
		s.writeJSON(w, r, http.StatusOK, status)

		return
	}

	s.writeJSON(w, r, http.StatusOK, status)
}

// handleApplyUpdate downloads, verifies and installs a release.
//
// The response is sent before the process hands over, because the browser will
// never get an answer from a node that has already exited. What it says is
// deliberately narrow: the update is installed and verified, and the service is
// coming back. Whether it came back is the panel's next health check to find
// out, not something this handler can honestly claim.
func (s *Server) handleApplyUpdate(w http.ResponseWriter, r *http.Request) {
	if s.deps.Update == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "updates are not configured for this build")

		return
	}

	status, err := s.deps.Update.Check(r.Context())
	if err != nil {
		s.writeError(w, r, http.StatusBadGateway, "could not reach the release server: "+err.Error())

		return
	}
	if !status.UpdateAvailable {
		s.writeError(w, r, http.StatusConflict, "this node is already running the latest release")

		return
	}

	// Not r.Context(): that is cancelled the moment the response is written,
	// and a download interrupted halfway is exactly what must not happen here.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), updateTimeout)
	defer cancel()

	if err = s.deps.Update.Apply(ctx, status.Latest, s.deps.ConfigPath); err != nil {
		s.audit(r, "update.apply", status.Latest, err.Error(), false)
		s.writeError(w, r, http.StatusBadGateway, err.Error())

		return
	}

	s.audit(r, "update.apply", status.Latest, "", true)
	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"installed":  status.Latest,
		"previous":   s.deps.Version,
		"restarting": true,
	})

	if s.deps.Restart == nil {
		s.deps.Logger.WarnContext(ctx, "update installed but this node cannot restart itself; restart it by hand",
			"version", status.Latest)

		return
	}

	// Let the response reach the browser before the listener goes away.
	go func() {
		time.Sleep(restartGrace)
		s.deps.Restart()
	}()
}
