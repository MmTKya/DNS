// Package api is the control plane's HTTP surface: the REST API the panel
// talks to, plus the embedded panel itself.
//
// Phase 0 exposes only health and version.  The middleware chain and the /api
// grouping are laid out now so that phase 1 can attach authentication in one
// place, and later phases can add /api/filters, /api/clients, /api/cluster and
// the SSE stream without restructuring anything.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/MmTKya/DNS/internal/config"
	"github.com/MmTKya/DNS/internal/resolver"
	"github.com/MmTKya/DNS/internal/store"
	"github.com/MmTKya/DNS/internal/web"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Deps are the collaborators the API reports on and, later, drives.
type Deps struct {
	Config   *config.Config
	Store    *store.DB
	Resolver *resolver.Resolver
	Logger   *slog.Logger

	// Started is when the process came up, used for uptime.
	Started time.Time
}

// Server bundles the router with its dependencies.
type Server struct {
	deps   Deps
	router chi.Router
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

	s := &Server{deps: deps}
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
	// The panel is served from the same origin and the admin API must never
	// hang on a wedged client, but the SSE stream added in phase 1 needs an
	// exemption, so the timeout lives on the /api group rather than globally.

	r.Route("/api", func(api chi.Router) {
		api.Use(middleware.Timeout(30 * time.Second))
		// Authentication attaches here in phase 1.  Everything under /api
		// must go through this group so nothing can be added unprotected.

		api.Get("/health", s.handleHealth)
		api.Get("/version", s.handleVersion)

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
