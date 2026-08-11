package api

import (
	"net/http"
	"time"

	"github.com/MmTKya/DNS/internal/config"
	"github.com/MmTKya/DNS/internal/version"
	"github.com/MmTKya/DNS/internal/web"
)

// Health status values.  They are deliberately coarse: the panel shows a dot,
// and the post-update health gate in phase 6 needs a single yes/no.
const (
	statusOK       = "ok"
	statusDegraded = "degraded"
)

type healthResponse struct {
	Status string `json:"status"`

	// Mode tells the panel which capabilities are honestly available.  Every
	// widget that needs gateway mode reads this.
	Mode config.DeploymentMode `json:"mode"`

	Version       string  `json:"version"`
	UptimeSeconds float64 `json:"uptime_seconds"`

	Resolver resolverHealth `json:"resolver"`
	Database databaseHealth `json:"database"`

	// PanelEmbedded is false for API-only builds, which is worth surfacing
	// because it looks like a broken deployment otherwise.
	PanelEmbedded bool `json:"panel_embedded"`
}

type resolverHealth struct {
	Status string   `json:"status"`
	Listen []string `json:"listen,omitempty"`
	Error  string   `json:"error,omitempty"`
}

type databaseHealth struct {
	Status        string `json:"status"`
	SchemaVersion int    `json:"schema_version"`
	Error         string `json:"error,omitempty"`
}

// handleHealth reports whether the node is actually working, not merely
// whether the process is alive.  It probes the database and asks the resolver
// for its bound sockets, so a wedged datapath shows up as degraded here and,
// from phase 4, trips the systemd watchdog and VRRP failover.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	resp := healthResponse{
		Status:        statusOK,
		Mode:          s.deps.Config.Mode,
		Version:       version.Get().Version,
		UptimeSeconds: time.Since(s.deps.Started).Seconds(),
		PanelEmbedded: web.HasPanel(),
	}

	switch {
	case s.deps.Resolver == nil:
		resp.Resolver = resolverHealth{Status: statusDegraded, Error: "resolver not configured"}
	case !s.deps.Resolver.Running():
		resp.Resolver = resolverHealth{Status: statusDegraded, Error: "resolver is not running"}
	default:
		resp.Resolver = resolverHealth{Status: statusOK, Listen: s.deps.Resolver.Addrs()}
	}

	if s.deps.Store == nil {
		resp.Database = databaseHealth{Status: statusDegraded, Error: "database not configured"}
	} else if err := s.deps.Store.Ping(ctx); err != nil {
		resp.Database = databaseHealth{Status: statusDegraded, Error: err.Error()}
	} else {
		resp.Database = databaseHealth{Status: statusOK}
		if schema, err := s.deps.Store.SchemaVersion(ctx); err != nil {
			resp.Database.Status = statusDegraded
			resp.Database.Error = err.Error()
		} else {
			resp.Database.SchemaVersion = schema
		}
	}

	status := http.StatusOK
	if resp.Resolver.Status != statusOK || resp.Database.Status != statusOK {
		resp.Status = statusDegraded
		// A non-2xx status is what lets `curl -f`, load balancer probes and
		// the update health gate detect trouble without parsing the body.
		status = http.StatusServiceUnavailable
	}

	s.writeJSON(w, r, status, resp)
}

// handleVersion reports build identity.  The panel shows it, and the phase 6
// updater compares it against the release channel.
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, r, http.StatusOK, version.Get())
}
