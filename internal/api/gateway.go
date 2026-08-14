package api

import (
	"net/http"

	"github.com/MmTKya/DNS/internal/gateway"
)

// Settings for gateway mode. Stored, not applied: nothing here switches the
// mode on, and the screen says why.
const (
	settingGWWAN      = "gateway.wan_interface"
	settingGWLAN      = "gateway.lan_interface"
	settingGWPPPoEOn  = "gateway.pppoe_enabled"
	settingGWPPPoEURL = "gateway.pppoe_username"
	settingGWPPPoEPwd = "gateway.pppoe_password"
	settingGWDHCPFrom = "gateway.dhcp_from"
	settingGWDHCPTo   = "gateway.dhcp_to"
)

// handleGatewayStatus reports what gateway mode would need from this machine.
//
// The checks run against the machine rather than describing requirements in
// the abstract, because the useful answer is not "a gateway needs two ports"
// but "this one has one, and here is what to do about it".
func (s *Server) handleGatewayStatus(w http.ResponseWriter, r *http.Request) {
	readiness := gateway.Inspect(r.Context())
	routeIface, routeGW := gateway.ScanRoutes()

	get := func(key string) string {
		value, _, _ := s.deps.Store.GetSetting(r.Context(), key)

		return value
	}

	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"mode":      string(s.deps.Config.Mode),
		"readiness": readiness,
		"current_route": map[string]string{
			"interface": routeIface,
			"gateway":   routeGW,
		},
		"settings": map[string]any{
			"wan_interface": get(settingGWWAN),
			"lan_interface": get(settingGWLAN),
			"pppoe_enabled": get(settingGWPPPoEOn) == "true",
			// The username comes back so the form is not blank on a revisit;
			// the password never does.
			"pppoe_username": get(settingGWPPPoEURL),
			"dhcp_from":      get(settingGWDHCPFrom),
			"dhcp_to":        get(settingGWDHCPTo),
		},
	})
}

type gatewaySettingsRequest struct {
	WANInterface  string  `json:"wan_interface"`
	LANInterface  string  `json:"lan_interface"`
	PPPoEEnabled  bool    `json:"pppoe_enabled"`
	PPPoEUsername string  `json:"pppoe_username"`
	PPPoEPassword *string `json:"pppoe_password,omitempty"`
	DHCPFrom      string  `json:"dhcp_from"`
	DHCPTo        string  `json:"dhcp_to"`
}

// handleSaveGateway stores the settings without applying them.
//
// Deliberately inert. Gateway mode has never run on real hardware, and a save
// button that reconfigured the network on the strength of that would be the
// most expensive bug in this project — the failure takes the household off the
// internet, not off DNS.
func (s *Server) handleSaveGateway(w http.ResponseWriter, r *http.Request) {
	var req gatewaySettingsRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}

	if req.WANInterface != "" && req.WANInterface == req.LANInterface {
		s.writeError(w, r, http.StatusBadRequest,
			"the two ports must be different: one faces the modem, one faces the house")

		return
	}

	values := map[string]string{
		settingGWWAN:      req.WANInterface,
		settingGWLAN:      req.LANInterface,
		settingGWPPPoEOn:  boolText(req.PPPoEEnabled),
		settingGWPPPoEURL: req.PPPoEUsername,
		settingGWDHCPFrom: req.DHCPFrom,
		settingGWDHCPTo:   req.DHCPTo,
	}

	// Written only when supplied, so saving the form again does not blank a
	// password the field could not show in the first place.
	if req.PPPoEPassword != nil && *req.PPPoEPassword != "" {
		values[settingGWPPPoEPwd] = *req.PPPoEPassword
	}

	for key, value := range values {
		if err := s.deps.Store.SetSetting(r.Context(), key, value); err != nil {
			s.writeError(w, r, http.StatusInternalServerError, err.Error())

			return
		}
	}

	s.audit(r, "gateway.settings", req.WANInterface+" → "+req.LANInterface, "saved, not applied", true)
	w.WriteHeader(http.StatusNoContent)
}

func boolText(b bool) string {
	if b {
		return "true"
	}

	return "false"
}
