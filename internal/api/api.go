// Package api is the control plane's HTTP surface: the REST API the panel
// talks to, plus the embedded panel itself.
//
// Everything under /api goes through one group, so authentication is attached
// in exactly one place and a new endpoint cannot be added unprotected by
// accident.  The live telemetry stream is the one exception to the request
// timeout, for the obvious reason.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/MmTKya/DNS/internal/audit"
	"github.com/MmTKya/DNS/internal/auth"
	"github.com/MmTKya/DNS/internal/clients"
	"github.com/MmTKya/DNS/internal/cluster"
	"github.com/MmTKya/DNS/internal/config"
	"github.com/MmTKya/DNS/internal/enforce"
	"github.com/MmTKya/DNS/internal/feeds"
	"github.com/MmTKya/DNS/internal/filter"
	"github.com/MmTKya/DNS/internal/intel"
	"github.com/MmTKya/DNS/internal/notify"
	"github.com/MmTKya/DNS/internal/querylog"
	"github.com/MmTKya/DNS/internal/resolver"
	"github.com/MmTKya/DNS/internal/store"
	"github.com/MmTKya/DNS/internal/update"
	"github.com/MmTKya/DNS/internal/vpn"
	"github.com/MmTKya/DNS/internal/web"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Deps are the collaborators the API reports on and drives.
type Deps struct {
	Config   *config.Config
	Store    *store.DB
	Resolver *resolver.Resolver
	Auth     *auth.Manager
	Feeds    *feeds.Manager
	Filter   *filter.Engine
	Clients  *clients.Registry
	QueryLog *querylog.Log

	// Intel and Suggestions power the "should I block this?" flow.
	Intel       *intel.Enricher
	Suggestions *intel.Queue

	// Enforce turns a paused device into a firewall rule, in gateway mode.
	Enforce *enforce.Enforcer

	// Cluster is nil on a standalone node.
	Cluster *cluster.Node

	// ConfigPath and Version travel in backups and snapshots.
	ConfigPath string
	Version    string

	// VPN is nil when the tunnel is not configured.
	VPN          *vpn.Manager
	VPNPublicKey string

	Notify *notify.Notifier
	Audit  *audit.Recorder
	Update *update.Checker

	// ReloadDatapath rebuilds the resolver from the current configuration and
	// the resolvers stored in the database.
	ReloadDatapath func()

	// UpdateStaging is where a verified update is left for the privileged
	// installer to pick up. Empty when this node has no such directory, in
	// which case updates are reported but not offered.
	UpdateStaging string

	// Metrics is the Prometheus handler, nil when metrics are disabled.
	Metrics http.Handler

	Logger *slog.Logger

	// Started is when the process came up, used for uptime.
	Started time.Time
}

// Server bundles the router with its dependencies.
type Server struct {
	deps    Deps
	router  chi.Router
	limiter *loginLimiter
}

// New builds the HTTP handler.
func New(deps Deps) *Server {
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	if deps.Started.IsZero() {
		deps.Started = time.Now()
	}
	// The health handler reports the deployment mode on every request, so a
	// missing config would panic on the one endpoint that exists to tell you
	// whether the node is healthy.
	if deps.Config == nil {
		deps.Config = config.Default()
	}

	s := &Server{deps: deps, limiter: newLoginLimiter()}
	s.router = s.routes()

	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) routes() chi.Router {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(requestLogger(s.deps.Logger))
	r.Use(middleware.Recoverer)

	r.Route("/api", func(api chi.Router) {
		// Health and version stay open: a monitoring probe should not need a
		// session, and the panel has to know whether setup is needed before
		// anyone can log in.
		api.Group(func(open chi.Router) {
			open.Use(middleware.Timeout(30 * time.Second))

			open.Get("/health", s.handleHealth)
			open.Get("/version", s.handleVersion)
			open.Get("/auth/status", s.handleAuthStatus)
			// Both verify a password, which is expensive on purpose. Left
			// unbounded that cost is a way to starve the resolver.
			open.With(s.throttle).Post("/auth/setup", s.handleSetup)
			open.With(s.throttle).Post("/auth/login", s.handleLogin)
			open.Post("/auth/logout", s.handleLogout)

			// Peer replication authenticates with the shared cluster token
			// rather than a panel session: the other node is a machine, and it
			// has no business holding someone's login.
			open.Get("/cluster/state", s.handleClusterState)
			open.Get("/cluster/snapshot", s.handleClusterSnapshot)
		})

		// Metrics are scraped by a machine that has no session. Binding the
		// panel to the LAN is what keeps this from being public; exposing the
		// node to the internet means putting something in front of it.
		if s.deps.Metrics != nil {
			api.Handle("/metrics", s.deps.Metrics)
		}

		// The live stream is exempt from the request timeout: it is meant to
		// stay open.
		api.Group(func(stream chi.Router) {
			stream.Use(s.requireSession)

			stream.Get("/stream", s.handleStream)
		})

		api.Group(func(protected chi.Router) {
			protected.Use(middleware.Timeout(30 * time.Second))
			protected.Use(s.requireSession)

			protected.Get("/auth/me", s.handleMe)
			protected.Post("/auth/password", s.handleChangePassword)
			protected.Post("/auth/totp/begin", s.handleTOTPBegin)
			protected.Post("/auth/totp/confirm", s.handleTOTPConfirm)
			protected.Post("/auth/totp/disable", s.handleTOTPDisable)

			protected.Get("/stats", s.handleStats)
			protected.Get("/querylog", s.handleQueryLog)

			protected.Get("/feeds", s.handleListFeeds)
			protected.Get("/feeds/catalog", s.handleFeedCatalog)
			protected.Get("/filters/rules", s.handleListRules)
			protected.Get("/dns/upstreams", s.handleListUpstreams)
			protected.Get("/clients", s.handleListClients)
			protected.Get("/clients/stale", s.handleStaleClients)
			protected.Get("/clients/{key}/activity", s.handleClientActivity)

			protected.Get("/cluster/status", s.handleClusterStatus)
			protected.Get("/vpn/peers", s.handleListPeers)
			protected.Get("/notify/channels", s.handleListChannels)
			protected.Get("/audit", s.handleAuditLog)
			protected.Get("/update", s.handleUpdateStatus)
			protected.Get("/backup", s.handleBackupExport)

			protected.Get("/intel/suggestions", s.handleSuggestions)
			protected.Get("/intel/lookup/{domain}", s.handleIntelLookup)

			// Anything that changes state needs an administrator; a read-only
			// user can watch the dashboard but not unblock anything.
			protected.Group(func(admin chi.Router) {
				admin.Use(s.requireAdmin)

				admin.Post("/feeds/{id}/enabled", s.handleSetFeedEnabled)
				admin.Post("/feeds/refresh", s.handleRefreshFeeds)
				admin.Post("/feeds", s.handleAddFeed)
				admin.Delete("/feeds/{id}", s.handleDeleteFeed)

				admin.Post("/filters/rules", s.handleAddRule)
				admin.Delete("/filters/rules/{id}", s.handleDeleteRule)
				admin.Post("/filters/rules/{id}/enabled", s.handleSetRuleEnabled)

				admin.Patch("/clients/{key}", s.handleUpdateClient)
				admin.Delete("/clients/{key}", s.handleDeleteClient)

				admin.Post("/intel/suggestions/{domain}", s.handleDecideSuggestion)
				admin.Post("/intel/settings", s.handleIntelSettings)

				admin.Post("/dns/upstreams", s.handleAddUpstream)
				admin.Post("/dns/upstreams/benchmark", s.handleBenchmarkUpstreams)
				admin.Patch("/dns/upstreams/{id}", s.handleUpdateUpstream)
				admin.Delete("/dns/upstreams/{id}", s.handleDeleteUpstream)

				admin.Post("/backup/restore", s.handleBackupImport)
				admin.Post("/cluster/demote", s.handleClusterDemote)
				admin.Post("/update/apply", s.handleApplyUpdate)

				admin.Post("/vpn/peers", s.handleAddPeer)
				admin.Post("/vpn/peers/{id}/enabled", s.handleSetPeerEnabled)
				admin.Delete("/vpn/peers/{id}", s.handleDeletePeer)

				admin.Post("/notify/channels", s.handleAddChannel)
				admin.Post("/notify/channels/{id}/test", s.handleTestChannel)
				admin.Post("/notify/channels/{id}/enabled", s.handleSetChannelEnabled)
				admin.Delete("/notify/channels/{id}", s.handleDeleteChannel)
			})
		})

		api.NotFound(notFoundJSON)
		api.MethodNotAllowed(methodNotAllowedJSON)
	})

	// Anything that is not /api is the panel, including client-side routes.
	r.NotFound(web.Handler().ServeHTTP)

	return r
}

// writeJSON renders v with the given status.  Encoding errors are logged
// rather than returned, because the status line has already been written.
func (s *Server) writeJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.deps.Logger.ErrorContext(r.Context(), "writing json response",
			"path", r.URL.Path,
			"err", err,
		)
	}
}

// writeError renders a problem in the shape the panel expects.
func (s *Server) writeError(w http.ResponseWriter, r *http.Request, status int, message string) {
	s.writeJSON(w, r, status, errorResponse{Error: message})
}

// decodeJSON reads a request body, bounded so a malformed or hostile request
// cannot make the node allocate without limit.
func (s *Server) decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()

	if err := dec.Decode(v); err != nil {
		s.writeError(w, r, http.StatusBadRequest, "invalid request body: "+err.Error())

		return false
	}

	return true
}

type errorResponse struct {
	Error string `json:"error"`
}

func notFoundJSON(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: "not found"})
}

func methodNotAllowedJSON(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusMethodNotAllowed)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: "method not allowed"})
}

// requestLogger logs one line per request at debug level.  Info level would
// drown the journal on a busy node, and the panel polls.
func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !logger.Enabled(r.Context(), slog.LevelDebug) {
				next.ServeHTTP(w, r)

				return
			}

			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			start := time.Now()

			defer func() {
				logger.DebugContext(r.Context(), "http request",
					"method", r.Method,
					"path", r.URL.Path,
					"status", ww.Status(),
					"bytes", ww.BytesWritten(),
					"duration", time.Since(start),
					"request_id", middleware.GetReqID(r.Context()),
				)
			}()

			next.ServeHTTP(ww, r)
		})
	}
}
