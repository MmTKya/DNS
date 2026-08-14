package api

import (
	"net/http"

	"github.com/MmTKya/DNS/internal/config"
	"github.com/MmTKya/DNS/internal/shaper"
	"github.com/go-chi/chi/v5"
)

// handleListLimits returns the speed limits and whether they are being
// enforced.
//
// The two are separate on purpose. A limit set in DNS-only mode is a decision
// recorded, not a rule in force, and a screen that showed the number without
// the distinction would be claiming something untrue about the network.
func (s *Server) handleListLimits(w http.ResponseWriter, r *http.Request) {
	limits, err := shaper.List(r.Context(), s.deps.Store)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	enforced := s.deps.Config.Mode == config.ModeGateway && s.deps.Shaper != nil && s.deps.Shaper.Available()

	explanation := ""
	if !enforced {
		explanation = "Saved, but not in force. Limits are applied by holding packets back, which " +
			"only something on the path between your devices and the internet can do — this node " +
			"answers questions about names. They take effect if it is switched to gateway mode."
	}

	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"limits":      limits,
		"enforced":    enforced,
		"mode":        string(s.deps.Config.Mode),
		"explanation": explanation,
	})
}

type limitRequest struct {
	DownloadKbps int `json:"download_kbps"`
	UploadKbps   int `json:"upload_kbps"`
}

func (s *Server) handleSetLimit(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")

	var req limitRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}

	if err := shaper.Set(r.Context(), s.deps.Store, key, req.DownloadKbps, req.UploadKbps); err != nil {
		s.writeError(w, r, http.StatusBadRequest, err.Error())

		return
	}

	s.audit(r, "limit.set", key, "", true)
	s.applyLimits(r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteLimit(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")

	if err := shaper.Remove(r.Context(), s.deps.Store, key); err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	s.audit(r, "limit.remove", key, "", true)
	s.applyLimits(r)
	w.WriteHeader(http.StatusNoContent)
}

// applyLimits pushes the stored limits at the kernel, when there is a kernel
// path to push them down.
//
// Failures are logged rather than returned: the limit is stored either way,
// and a save that reports failure because the node cannot enforce it yet would
// stop someone deciding what the limits should be before the machine is ready.
func (s *Server) applyLimits(r *http.Request) {
	if s.deps.Shaper == nil || s.deps.Config.Mode != config.ModeGateway {
		return
	}

	plan, err := shaper.PlanFrom(r.Context(), s.deps.Store,
		s.deps.LANInterface, s.deps.WANInterface)
	if err != nil {
		s.deps.Logger.ErrorContext(r.Context(), "building the limit plan", "err", err)

		return
	}

	if err = s.deps.Shaper.Apply(r.Context(), plan); err != nil {
		s.deps.Logger.ErrorContext(r.Context(), "applying limits", "err", err)
	}
}
