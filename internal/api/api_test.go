package api_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MmTKya/DNS/internal/api"
	"github.com/MmTKya/DNS/internal/config"
	"github.com/MmTKya/DNS/internal/resolver"
	"github.com/MmTKya/DNS/internal/store"
)

func newServer(t *testing.T, withStore, withResolver bool) *api.Server {
	t.Helper()

	cfg := config.Default()
	cfg.DNS.Listen = []string{"127.0.0.1:0"}
	cfg.HTTP.Listen = "127.0.0.1:0"

	deps := api.Deps{
		Config:  cfg,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Started: time.Now().Add(-90 * time.Second),
	}

	if withStore {
		db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "aegisdns.db"))
		if err != nil {
			t.Fatalf("opening store: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })
		deps.Store = db
	}

	if withResolver {
		r := resolver.New(cfg, deps.Logger)
		if err := r.Start(t.Context()); err != nil {
			t.Fatalf("starting resolver: %v", err)
		}
		t.Cleanup(func() { _ = r.Shutdown(t.Context()) })
		deps.Resolver = r
	}

	return api.New(deps)
}

func do(t *testing.T, srv *api.Server, method, target string) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(method, target, nil))

	return rec
}

func TestHealthWhenEverythingIsUp(t *testing.T) {
	t.Parallel()

	rec := do(t, newServer(t, true, true), http.MethodGet, "/api/health")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body %s", rec.Code, rec.Body)
	}

	var body struct {
		Status        string  `json:"status"`
		Mode          string  `json:"mode"`
		UptimeSeconds float64 `json:"uptime_seconds"`
		Resolver      struct {
			Status string   `json:"status"`
			Listen []string `json:"listen"`
		} `json:"resolver"`
		Database struct {
			Status        string `json:"status"`
			SchemaVersion int    `json:"schema_version"`
		} `json:"database"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}

	if body.Status != "ok" {
		t.Errorf("status = %q, want %q", body.Status, "ok")
	}
	if body.Mode != string(config.ModeDNSOnly) {
		t.Errorf("mode = %q, want %q: the panel gates widgets on this field", body.Mode, config.ModeDNSOnly)
	}
	if body.UptimeSeconds < 89 {
		t.Errorf("uptime_seconds = %v, want at least 89", body.UptimeSeconds)
	}
	if body.Resolver.Status != "ok" || len(body.Resolver.Listen) == 0 {
		t.Errorf("resolver health = %+v, want ok with bound addresses", body.Resolver)
	}
	if body.Database.Status != "ok" || body.Database.SchemaVersion < 1 {
		t.Errorf("database health = %+v, want ok with a schema version", body.Database)
	}
}

func TestHealthIsUnavailableWhenResolverIsDown(t *testing.T) {
	t.Parallel()

	rec := do(t, newServer(t, true, false), http.MethodGet, "/api/health")

	// The status code has to carry the verdict: the phase 6 update health gate
	// and external probes rely on it without parsing the body.
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "degraded") {
		t.Errorf("body should report a degraded component, got %s", rec.Body)
	}
}

func TestVersionEndpoint(t *testing.T) {
	t.Parallel()

	rec := do(t, newServer(t, true, true), http.MethodGet, "/api/version")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var body struct {
		Version   string `json:"version"`
		GoVersion string `json:"go_version"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if body.Version == "" {
		t.Error("version must not be empty")
	}
}

func TestUnknownAPIPathReturnsJSON404(t *testing.T) {
	t.Parallel()

	rec := do(t, newServer(t, true, true), http.MethodGet, "/api/nope")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type = %q, want json: /api must never fall through to the SPA", ct)
	}
}

func TestUnknownMethodOnAPIPath(t *testing.T) {
	t.Parallel()

	rec := do(t, newServer(t, true, true), http.MethodPost, "/api/health")

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestSPARoutesFallThroughToPanel(t *testing.T) {
	t.Parallel()

	srv := newServer(t, true, true)

	// A client-side route must not 404 on reload.  Without a built panel this
	// serves the placeholder page, which is still HTML with a 200.
	rec := do(t, srv, http.MethodGet, "/clients/42")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a client-side route", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q, want text/html", ct)
	}
}
