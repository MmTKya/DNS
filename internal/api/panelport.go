package api

import (
	"errors"
	"net"
	"net/http"
	"strconv"

	"github.com/MmTKya/DNS/internal/panelport"
)

// SettingPanelPort is where a confirmed port is kept.
//
// In the database rather than the configuration file, because the node runs
// unprivileged and cannot write its own configuration — the same reason
// updates are staged for a privileged helper rather than applied in place.
const SettingPanelPort = "http.panel_port"

// handlePanelPort reports where the panel is and whether a move is waiting.
func (s *Server) handlePanelPort(w http.ResponseWriter, r *http.Request) {
	current := portOf(s.deps.Config.HTTP.Listen)
	if stored, found, _ := s.deps.Store.GetSetting(r.Context(), SettingPanelPort); found {
		if parsed, err := strconv.Atoi(stored); err == nil {
			current = parsed
		}
	}

	response := map[string]any{"port": current}

	if s.deps.PanelPort != nil {
		if port, deadline, waiting := s.deps.PanelPort.Pending(); waiting {
			response["pending_port"] = port
			response["confirm_by"] = deadline
			response["confirm_url"] = panelURL(r, port)
		}
	}

	s.writeJSON(w, r, http.StatusOK, response)
}

type panelPortRequest struct {
	Port int `json:"port"`
}

// handleMovePanelPort opens the new port without giving up the old one.
//
// Nothing is stored here. The panel is the thing being reconfigured, and a
// setting that can make its own editor unreachable has to be provable before
// it is permanent — so the node opens the port, keeps the current one, and
// waits to be told from the other side that it worked.
func (s *Server) handleMovePanelPort(w http.ResponseWriter, r *http.Request) {
	if s.deps.PanelPort == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "this node cannot move its own panel")

		return
	}

	var req panelPortRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}

	if req.Port == portOf(s.deps.Config.HTTP.Listen) {
		s.writeError(w, r, http.StatusBadRequest, "the panel is already on that port")

		return
	}

	deadline, err := s.deps.PanelPort.Begin(req.Port)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, panelport.ErrInUse) || errors.Is(err, panelport.ErrPending) {
			status = http.StatusConflict
		}

		s.writeError(w, r, status, err.Error())

		return
	}

	s.audit(r, "panel.port.begin", strconv.Itoa(req.Port), "opened, awaiting confirmation on the new port", true)

	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"pending_port": req.Port,
		"confirm_by":   deadline,
		"confirm_url":  panelURL(r, req.Port),
	})
}

// handleConfirmPanelPort makes the move permanent.
//
// It only works when the request arrived on the new port, which is the point:
// a browser that got here proves the port is reachable from where the person
// actually is. Nothing the node could check about itself would establish that.
func (s *Server) handleConfirmPanelPort(w http.ResponseWriter, r *http.Request) {
	if s.deps.PanelPort == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "this node cannot move its own panel")

		return
	}

	arrivedOn := 0
	if local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && local != nil {
		if _, port, err := net.SplitHostPort(local.String()); err == nil {
			arrivedOn, _ = strconv.Atoi(port)
		}
	}

	if err := s.deps.PanelPort.Confirm(arrivedOn); err != nil {
		status := http.StatusConflict
		if errors.Is(err, panelport.ErrWrongPort) {
			status = http.StatusBadRequest
		}

		s.writeError(w, r, status, err.Error())

		return
	}

	s.audit(r, "panel.port.confirm", strconv.Itoa(arrivedOn), "confirmed from the new port", true)

	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"port": arrivedOn,
		"note": "the panel will use this port from now on, including after a restart",
	})
}

// handleCancelPanelPort gives up on a move.
func (s *Server) handleCancelPanelPort(w http.ResponseWriter, r *http.Request) {
	if s.deps.PanelPort == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "this node cannot move its own panel")

		return
	}

	if err := s.deps.PanelPort.Cancel(); err != nil {
		s.writeError(w, r, http.StatusConflict, err.Error())

		return
	}

	s.audit(r, "panel.port.cancel", "", "the move was abandoned", true)
	s.writeJSON(w, r, http.StatusOK, map[string]any{"cancelled": true})
}

// panelURL is the address to try the new port on.
//
// Built from the Host header, so it is whatever the person actually typed to
// get here — a node that answered with its own idea of its address would send
// them somewhere they may have no route to.
func panelURL(r *http.Request, port int) string {
	host := r.Host
	if stripped, _, err := net.SplitHostPort(host); err == nil {
		host = stripped
	}

	return "http://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/"
}

// portOf pulls the port out of a listen address.
func portOf(listen string) int {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return 0
	}

	parsed, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}

	return parsed
}
