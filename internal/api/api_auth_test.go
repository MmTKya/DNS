package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MmTKya/DNS/internal/api"
	"github.com/MmTKya/DNS/internal/auth"
	"github.com/MmTKya/DNS/internal/clients"
	"github.com/MmTKya/DNS/internal/config"
	"github.com/MmTKya/DNS/internal/feeds"
	"github.com/MmTKya/DNS/internal/filter"
	"github.com/MmTKya/DNS/internal/querylog"
	"github.com/MmTKya/DNS/internal/store"
)

const apiTestPassword = "correct-horse-battery-staple"

// harness is a server with the full phase-1 dependency set.
type harness struct {
	srv    *api.Server
	auth   *auth.Manager
	db     *store.DB
	cookie *http.Cookie
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "aegisdns.db"))
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.Default()
	cfg.DNS.Listen = []string{"127.0.0.1:0"}
	cfg.HTTP.Listen = "127.0.0.1:0"

	registry, err := clients.New(t.Context(), db, logger)
	if err != nil {
		t.Fatalf("creating client registry: %v", err)
	}

	authManager := auth.New(db, time.Hour, logger)

	return &harness{
		db:   db,
		auth: authManager,
		srv: api.New(api.Deps{
			Config:   cfg,
			Store:    db,
			Auth:     authManager,
			Filter:   filter.NewEngine(),
			Clients:  registry,
			QueryLog: querylog.New(db, cfg, logger),
			Logger:   logger,
		}),
	}
}

func (h *harness) do(t *testing.T, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encoding body: %v", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req := httptest.NewRequest(method, target, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if h.cookie != nil {
		req.AddCookie(h.cookie)
	}

	rec := httptest.NewRecorder()
	h.srv.ServeHTTP(rec, req)

	// Carry the session forward once login sets it.
	for _, c := range rec.Result().Cookies() {
		if strings.Contains(c.Name, "aegis_session") && c.Value != "" {
			h.cookie = c
		}
	}

	return rec
}

// setup runs the first-run flow and leaves the harness logged in.
func (h *harness) setup(t *testing.T) {
	t.Helper()

	rec := h.do(t, http.MethodPost, "/api/auth/setup", map[string]string{
		"username": "admin",
		"password": apiTestPassword,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("setup: status %d, body %s", rec.Code, rec.Body)
	}
}

func TestAuthStatusDrivesFirstRun(t *testing.T) {
	t.Parallel()

	h := newHarness(t)

	rec := h.do(t, http.MethodGet, "/api/auth/status", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	var status struct {
		NeedsSetup bool `json:"needs_setup"`
		SignedIn   bool `json:"signed_in"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	// The panel needs to tell "set up" from "log in" before anyone has a
	// session, so this endpoint stays open.
	if !status.NeedsSetup || status.SignedIn {
		t.Errorf("status = %+v, want needs_setup on a fresh node", status)
	}

	h.setup(t)

	rec = h.do(t, http.MethodGet, "/api/auth/status", nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if status.NeedsSetup || !status.SignedIn {
		t.Errorf("status after setup = %+v, want signed in", status)
	}
}

func TestSetupRefusesOnceClaimed(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.setup(t)

	// Otherwise anyone who reached the panel later could mint themselves an
	// administrator.
	rec := h.do(t, http.MethodPost, "/api/auth/setup", map[string]string{
		"username": "intruder",
		"password": apiTestPassword,
	})
	if rec.Code != http.StatusConflict {
		t.Errorf("second setup: status = %d, want 409", rec.Code)
	}
}

func TestProtectedEndpointsRequireASession(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.setup(t)

	protected := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/stats"},
		{http.MethodGet, "/api/querylog"},
		{http.MethodGet, "/api/feeds"},
		{http.MethodGet, "/api/clients"},
		{http.MethodGet, "/api/filters/rules"},
		{http.MethodGet, "/api/auth/me"},
		{http.MethodGet, "/api/stream"},
	}

	// Drop the session and confirm every one of them closes.
	h.cookie = nil

	for _, tc := range protected {
		rec := h.do(t, tc.method, tc.path, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: status = %d, want 401", tc.method, tc.path, rec.Code)
		}
	}
}

func TestReadOnlyUserCannotChangeThings(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.setup(t)

	if _, err := h.auth.CreateUser(t.Context(), "watcher", apiTestPassword, auth.RoleReadOnly); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	h.cookie = nil
	rec := h.do(t, http.MethodPost, "/api/auth/login", map[string]string{
		"username": "watcher",
		"password": apiTestPassword,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: status %d, body %s", rec.Code, rec.Body)
	}

	// A read-only user is for watching the dashboard, so reads work...
	if got := h.do(t, http.MethodGet, "/api/stats", nil); got.Code != http.StatusOK {
		t.Errorf("read-only GET /api/stats = %d, want 200", got.Code)
	}

	// ...and anything that changes state does not.
	rec = h.do(t, http.MethodPost, "/api/filters/rules", map[string]string{"rule": "||ads.example.com^"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("read-only rule creation = %d, want 403", rec.Code)
	}
}

func TestLoginThenLogout(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.setup(t)

	if rec := h.do(t, http.MethodPost, "/api/auth/logout", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("logout: status %d", rec.Code)
	}

	h.cookie = nil
	if rec := h.do(t, http.MethodGet, "/api/auth/me", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("after logout: status = %d, want 401", rec.Code)
	}

	rec := h.do(t, http.MethodPost, "/api/auth/login", map[string]string{
		"username": "admin",
		"password": apiTestPassword,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: status %d, body %s", rec.Code, rec.Body)
	}
	if rec := h.do(t, http.MethodGet, "/api/auth/me", nil); rec.Code != http.StatusOK {
		t.Errorf("after login: status = %d, want 200", rec.Code)
	}
}

func TestSessionCookieIsHttpOnly(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.setup(t)

	if h.cookie == nil {
		t.Fatal("setup did not set a session cookie")
	}
	// Script access to the session cookie would turn any XSS into a permanent
	// takeover of the node.
	if !h.cookie.HttpOnly {
		t.Error("the session cookie must be HttpOnly")
	}
	if h.cookie.SameSite != http.SameSiteLaxMode && h.cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want Lax or Strict", h.cookie.SameSite)
	}
}

func TestUserRuleLifecycle(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.setup(t)

	rec := h.do(t, http.MethodPost, "/api/filters/rules", map[string]string{
		"rule":    "||ads.example.com^",
		"comment": "noisy",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("adding a rule: status %d, body %s", rec.Code, rec.Body)
	}

	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	rec = h.do(t, http.MethodGet, "/api/filters/rules", nil)
	if !strings.Contains(rec.Body.String(), "ads.example.com") {
		t.Errorf("the rule list should contain the new rule, got %s", rec.Body)
	}

	rec = h.do(t, http.MethodDelete, "/api/filters/rules/"+strconv.FormatInt(created.ID, 10), nil)
	if rec.Code != http.StatusNoContent {
		t.Errorf("deleting a rule: status %d, body %s", rec.Code, rec.Body)
	}
}

func TestUnusableRuleIsRejectedAtWriteTime(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.setup(t)

	// Silently dropping these at compile time would leave the operator
	// wondering why the name still resolves.
	for _, rule := range []string{
		"||example.com^$third-party",
		"example.com##.banner",
		"# just a comment",
	} {
		rec := h.do(t, http.MethodPost, "/api/filters/rules", map[string]string{"rule": rule})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("rule %q: status = %d, want 400", rule, rec.Code)
		}
	}
}

func TestClientUpdateAndModeHonesty(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.setup(t)

	name := "Kids tablet"
	paused := true
	rec := h.do(t, http.MethodPatch, "/api/clients/192.168.1.50", map[string]any{
		"name":   name,
		"paused": paused,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("updating a client: status %d, body %s", rec.Code, rec.Body)
	}

	rec = h.do(t, http.MethodGet, "/api/clients", nil)

	var list struct {
		Clients []struct {
			Key    string `json:"key"`
			Name   string `json:"name"`
			Paused bool   `json:"paused"`
		} `json:"clients"`
		Mode            string `json:"mode"`
		PauseIsEnforced bool   `json:"pause_is_enforced"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	var found bool
	for _, c := range list.Clients {
		if c.Key == "192.168.1.50" && c.Name == name && c.Paused {
			found = true
		}
	}
	if !found {
		t.Errorf("clients = %+v, want the updated one", list.Clients)
	}

	// In DNS-only mode a pause is content filtering, not a kill switch, and
	// the API has to say so rather than let the panel imply otherwise.
	if list.PauseIsEnforced {
		t.Error("pause_is_enforced must be false in dns-only mode")
	}
}

func TestStatsReportModeCapabilities(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.setup(t)

	rec := h.do(t, http.MethodGet, "/api/stats", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	var stats struct {
		Capabilities map[string]bool `json:"capabilities"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	// A DNS server sees names, not bytes. Claiming otherwise is the one thing
	// the product must never do.
	if stats.Capabilities["bandwidth"] {
		t.Error("bandwidth must not be advertised in dns-only mode")
	}
	if !stats.Capabilities["dns_filtering"] {
		t.Error("dns filtering should be advertised in every mode")
	}
}

func TestFeedListIncludesCatalogueMetadata(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.setup(t)

	if err := feeds.Seed(t.Context(), h.db); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	rec := h.do(t, http.MethodGet, "/api/feeds", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}

	// The licence and the false-positive warning are what make enabling a
	// list an informed decision.
	body := rec.Body.String()
	for _, want := range []string{"commercial_use", "license", "high_false_positives"} {
		if !strings.Contains(body, want) {
			t.Errorf("feed list is missing %q", want)
		}
	}
}
