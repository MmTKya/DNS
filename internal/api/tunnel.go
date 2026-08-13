package api

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/MmTKya/DNS/internal/tunnel"
)

// Settings keys for the Cloudflare tunnel.
const (
	settingCFTunnelID    = "tunnel.cloudflare.tunnel_id"
	settingCFCredentials = "tunnel.cloudflare.credentials_file"
	settingCFHostname    = "tunnel.cloudflare.hostname"
)

// handleTunnelStatus reports how the panel can be reached from outside and
// what is already set up.
//
// The tradeoffs come with it rather than living in documentation: choosing how
// to expose a box that can redirect every name in the house is not a decision
// to make from a list of names.
func (s *Server) handleTunnelStatus(w http.ResponseWriter, r *http.Request) {
	cf := s.cloudflareConfig(r)

	version := ""
	installed := tunnel.CloudflaredAvailable()
	if installed {
		version, _ = tunnel.CloudflaredVersion(r.Context())
	}

	rendered := ""
	if cf.Validate() == nil {
		rendered, _ = tunnel.RenderCloudflareConfig(cf)
	}

	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"exposures": tunnel.Exposures(s.deps.VPN != nil),
		"cloudflare": map[string]any{
			"installed":        installed,
			"version":          version,
			"tunnel_id":        cf.TunnelID,
			"credentials_file": cf.CredentialsFile,
			"hostname":         cf.Hostname,
			"service":          cf.Service,
			"config":           rendered,
			"config_path":      s.cloudflareConfigPath(),
		},
	})
}

type cloudflareRequest struct {
	TunnelID        string `json:"tunnel_id"`
	CredentialsFile string `json:"credentials_file"`
	Hostname        string `json:"hostname"`
}

// handleSaveCloudflare stores the settings and writes the configuration file.
//
// The node cannot install cloudflared or manage its service — it runs
// unprivileged, and a resolver that could install system software would be a
// worse trade than the convenience is worth. What it can do is the part that
// is actually fiddly: producing a correct configuration file, including the
// catch-all rule cloudflared refuses to start without.
func (s *Server) handleSaveCloudflare(w http.ResponseWriter, r *http.Request) {
	var req cloudflareRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}

	cfg := tunnel.CloudflareConfig{
		TunnelID:        req.TunnelID,
		CredentialsFile: req.CredentialsFile,
		Hostname:        req.Hostname,
		Service:         "http://" + s.deps.Config.HTTP.Listen,
	}
	if cfg.Service == "http://0.0.0.0:8080" {
		cfg.Service = "http://127.0.0.1:8080"
	}

	if err := cfg.Validate(); err != nil {
		s.writeError(w, r, http.StatusBadRequest, err.Error())

		return
	}

	rendered, err := tunnel.RenderCloudflareConfig(cfg)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, err.Error())

		return
	}

	for key, value := range map[string]string{
		settingCFTunnelID:    cfg.TunnelID,
		settingCFCredentials: cfg.CredentialsFile,
		settingCFHostname:    cfg.Hostname,
	} {
		if err = s.deps.Store.SetSetting(r.Context(), key, value); err != nil {
			s.writeError(w, r, http.StatusInternalServerError, err.Error())

			return
		}
	}

	path := s.cloudflareConfigPath()
	if writeErr := os.WriteFile(path, []byte(rendered), 0o640); writeErr != nil {
		// Saved but not written: the settings survive and the panel can still
		// show the file to copy by hand.
		s.audit(r, "tunnel.cloudflare.save", cfg.Hostname, writeErr.Error(), false)
		s.writeJSON(w, r, http.StatusOK, map[string]any{
			"config":      rendered,
			"config_path": path,
			"write_error": writeErr.Error(),
		})

		return
	}

	s.audit(r, "tunnel.cloudflare.save", cfg.Hostname, "", true)
	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"config":      rendered,
		"config_path": path,
	})
}

func (s *Server) cloudflareConfig(r *http.Request) tunnel.CloudflareConfig {
	get := func(key string) string {
		value, _, _ := s.deps.Store.GetSetting(r.Context(), key)

		return value
	}

	service := "http://" + s.deps.Config.HTTP.Listen
	if service == "http://0.0.0.0:8080" {
		service = "http://127.0.0.1:8080"
	}

	return tunnel.CloudflareConfig{
		TunnelID:        get(settingCFTunnelID),
		CredentialsFile: get(settingCFCredentials),
		Hostname:        get(settingCFHostname),
		Service:         service,
	}
}

// cloudflareConfigPath keeps the file beside the database, which is the one
// directory this node is allowed to write.
func (s *Server) cloudflareConfigPath() string {
	if s.deps.Config == nil || s.deps.Config.Store.Path == "" {
		return "/var/lib/seddns/cloudflared.yml"
	}

	return filepath.Join(filepath.Dir(s.deps.Config.Store.Path), "cloudflared.yml")
}
