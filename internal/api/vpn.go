package api

import (
	"net/http"
	"net/netip"
	"strconv"

	"github.com/MmTKya/DNS/internal/tunnel"
	"github.com/MmTKya/DNS/internal/vpn"
	"github.com/go-chi/chi/v5"
)

// serverConfig builds the tunnel description from the node's configuration.
func (s *Server) serverConfig() (cfg vpn.ServerConfig, err error) {
	subnet, err := netip.ParsePrefix(s.deps.Config.VPN.Subnet)
	if err != nil {
		return vpn.ServerConfig{}, err
	}

	addr, err := netip.ParseAddr(s.deps.Config.VPN.Address)
	if err != nil {
		return vpn.ServerConfig{}, err
	}

	return vpn.ServerConfig{
		Subnet:    subnet,
		Address:   addr,
		Endpoint:  s.deps.Config.VPN.Endpoint,
		PublicKey: s.deps.VPNPublicKey,
		KeepAlive: s.deps.Config.VPN.KeepAlive,
		MTU:       s.deps.Config.VPN.MTU,
	}, nil
}

// handleListPeers returns the tunnel's devices.
func (s *Server) handleListPeers(w http.ResponseWriter, r *http.Request) {
	peers, err := vpn.List(r.Context(), s.deps.Store)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}
	vpn.SortPeers(peers)

	available := s.deps.VPN != nil && s.deps.VPN.Available()

	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"peers":   peers,
		"enabled": s.deps.Config.VPN.Enabled,
		// Availability is reported honestly: a node without the kernel module
		// should say so rather than showing a peer list that never connects.
		"available":  available,
		"endpoint":   s.deps.Config.VPN.Endpoint,
		"public_key": s.deps.VPNPublicKey,
		"exposures":  tunnel.Exposures(available),
	})
}

type addPeerRequest struct {
	Name string `json:"name"`

	// FullTunnel routes everything through the house rather than DNS alone.
	FullTunnel bool `json:"full_tunnel"`
}

// handleAddPeer creates a device and returns its configuration.
//
// The private key is in this response and nowhere else: it is generated per
// device, handed over once, and never stored, so the panel has to show it
// immediately or the operator has to create the peer again.
func (s *Server) handleAddPeer(w http.ResponseWriter, r *http.Request) {
	if !s.deps.Config.VPN.Enabled {
		s.writeError(w, r, http.StatusConflict,
			"the tunnel is not enabled; set vpn.enabled and an endpoint in the configuration first")

		return
	}

	var req addPeerRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}

	server, err := s.serverConfig()
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	cfg, err := vpn.AddPeer(r.Context(), s.deps.Store, server, req.Name, req.FullTunnel)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, err.Error())

		return
	}

	s.syncTunnel(r)

	s.writeJSON(w, r, http.StatusCreated, cfg)
}

func (s *Server) handleSetPeerEnabled(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid peer id")

		return
	}

	var req feedEnabledRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}

	found, err := vpn.SetEnabled(r.Context(), s.deps.Store, id, req.Enabled)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}
	if !found {
		s.writeError(w, r, http.StatusNotFound, "no such peer")

		return
	}

	s.syncTunnel(r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeletePeer(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid peer id")

		return
	}

	found, err := vpn.DeletePeer(r.Context(), s.deps.Store, id)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}
	if !found {
		s.writeError(w, r, http.StatusNotFound, "no such peer")

		return
	}

	s.syncTunnel(r)
	w.WriteHeader(http.StatusNoContent)
}

// syncTunnel pushes the stored peers onto the interface.
//
// Revoking a device has to take effect now, not at the next restart, so this
// runs on every change rather than on a timer.
func (s *Server) syncTunnel(r *http.Request) {
	if s.deps.VPN == nil || !s.deps.VPN.Available() {
		return
	}

	if err := s.deps.VPN.Sync(r.Context()); err != nil {
		s.deps.Logger.ErrorContext(r.Context(), "syncing the tunnel", "err", err)
	}
}
