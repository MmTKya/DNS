package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/MmTKya/DNS/internal/auth"
)

// sessionCookie is the panel's login cookie.
//
// The __Host- prefix is a browser-enforced guarantee: the cookie must be
// Secure, path "/", and carry no Domain, which means a compromised sibling
// host cannot set or overwrite it.  Plain HTTP over a LAN cannot satisfy that,
// so the prefix is only used when the request arrived over TLS.
const (
	sessionCookie       = "aegis_session"
	sessionCookieSecure = "__Host-aegis_session"
)

type contextKey int

const userContextKey contextKey = iota

// requireSession rejects requests without a valid login.
func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.deps.Auth == nil {
			s.writeError(w, r, http.StatusServiceUnavailable, "authentication is not configured")

			return
		}

		token := sessionToken(r)

		user, err := s.deps.Auth.Authenticate(r.Context(), token)
		if err != nil {
			// A node with no administrator yet answers 401 too; the panel uses
			// /api/auth/status to tell "log in" from "set up".
			s.writeError(w, r, http.StatusUnauthorized, "not authenticated")

			return
		}

		s.deps.Auth.Touch(r.Context(), token)

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userContextKey, user)))
	})
}

// requireAdmin rejects a read-only user from anything that changes state.
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := userFrom(r.Context())
		if !ok || !user.IsAdmin() {
			s.writeError(w, r, http.StatusForbidden, "this action requires an administrator")

			return
		}

		next.ServeHTTP(w, r)
	})
}

func userFrom(ctx context.Context) (user auth.User, ok bool) {
	user, ok = ctx.Value(userContextKey).(auth.User)

	return user, ok
}

func sessionToken(r *http.Request) string {
	for _, name := range []string{sessionCookieSecure, sessionCookie} {
		if c, err := r.Cookie(name); err == nil && c.Value != "" {
			return c.Value
		}
	}

	return ""
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	name := sessionCookie
	secure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	if secure {
		name = sessionCookieSecure
	}

	http.SetCookie(w, &http.Cookie{
		Name:  name,
		Value: token,
		Path:  "/",
		// The panel is same-origin, so the cookie never needs to travel with a
		// cross-site request; Lax still allows a normal link into the panel.
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   secure,
		MaxAge:   int(s.deps.Config.HTTP.SessionTTL.Duration().Seconds()),
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	for _, name := range []string{sessionCookie, sessionCookieSecure} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			MaxAge:   -1,
		})
	}
}

type authStatusResponse struct {
	User        *auth.User `json:"user,omitempty"`
	NeedsSetup  bool       `json:"needs_setup"`
	SignedIn    bool       `json:"signed_in"`
	TOTPEnabled bool       `json:"totp_enabled"`
}

// handleAuthStatus tells the panel which screen to show: setup, login, or the
// dashboard.
func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	if s.deps.Auth == nil {
		s.writeJSON(w, r, http.StatusOK, authStatusResponse{})

		return
	}

	needsSetup, err := s.deps.Auth.NeedsSetup(r.Context())
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	resp := authStatusResponse{NeedsSetup: needsSetup}

	if user, authErr := s.deps.Auth.Authenticate(r.Context(), sessionToken(r)); authErr == nil {
		resp.SignedIn = true
		resp.User = &user
		resp.TOTPEnabled = user.TOTPEnabled
	}

	s.writeJSON(w, r, http.StatusOK, resp)
}

type setupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// handleSetup creates the first administrator.
//
// It is open by necessity — there is nobody to authenticate as yet — so it
// refuses once any user exists.  That leaves a race on a brand-new node
// reachable from an untrusted network, which is why the installer tells you to
// finish setup immediately.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if s.deps.Auth == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "authentication is not configured")

		return
	}

	needsSetup, err := s.deps.Auth.NeedsSetup(r.Context())
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}
	if !needsSetup {
		s.writeError(w, r, http.StatusConflict, "this node already has an administrator")

		return
	}

	var req setupRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}

	user, err := s.deps.Auth.CreateUser(r.Context(), req.Username, req.Password, auth.RoleAdmin)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, err.Error())

		return
	}

	token, _, err := s.deps.Auth.Login(r.Context(), req.Username, req.Password, "", clientIP(r), r.UserAgent())
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	s.setSessionCookie(w, r, token)
	s.writeJSON(w, r, http.StatusCreated, user)
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Code     string `json:"code,omitempty"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.deps.Auth == nil {
		s.writeError(w, r, http.StatusServiceUnavailable, "authentication is not configured")

		return
	}

	var req loginRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}

	token, user, err := s.deps.Auth.Login(r.Context(), req.Username, req.Password, req.Code, clientIP(r), r.UserAgent())
	switch {
	case errors.Is(err, auth.ErrTOTPRequired):
		// A distinct status so the panel can ask for the code without making
		// the user type their password again.
		s.writeJSON(w, r, http.StatusAccepted, map[string]bool{"totp_required": true})

		return

	case errors.Is(err, auth.ErrLockedOut):
		s.writeError(w, r, http.StatusTooManyRequests, err.Error())

		return

	case err != nil:
		s.writeError(w, r, http.StatusUnauthorized, "invalid credentials")

		return
	}

	s.setSessionCookie(w, r, token)
	s.writeJSON(w, r, http.StatusOK, user)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if s.deps.Auth != nil {
		if err := s.deps.Auth.Logout(r.Context(), sessionToken(r)); err != nil {
			s.deps.Logger.ErrorContext(r.Context(), "logging out", "err", err)
		}
	}

	s.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())

	left, err := s.deps.Auth.RecoveryCodesLeft(r.Context(), user.ID)
	if err != nil {
		s.deps.Logger.ErrorContext(r.Context(), "counting recovery codes", "err", err)
	}

	s.writeJSON(w, r, http.StatusOK, struct {
		auth.User
		RecoveryCodesLeft int `json:"recovery_codes_left"`
	}{User: user, RecoveryCodesLeft: left})
}

type changePasswordRequest struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())

	var req changePasswordRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}

	if err := s.deps.Auth.ChangePassword(r.Context(), user.ID, req.Current, req.New); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, auth.ErrInvalidCredentials) {
			status = http.StatusUnauthorized
		}
		s.writeError(w, r, status, err.Error())

		return
	}

	// Every session was revoked, including this one.
	s.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleTOTPBegin(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())

	enrollment, err := s.deps.Auth.BeginTOTP(r.Context(), user.ID, user.Username)
	if err != nil {
		s.writeError(w, r, http.StatusInternalServerError, err.Error())

		return
	}

	s.writeJSON(w, r, http.StatusOK, enrollment)
}

type totpConfirmRequest struct {
	Code string `json:"code"`
}

func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())

	var req totpConfirmRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}

	codes, err := s.deps.Auth.ConfirmTOTP(r.Context(), user.ID, req.Code)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, err.Error())

		return
	}

	// Shown once, here. They are stored only as hashes.
	s.writeJSON(w, r, http.StatusOK, map[string]any{"recovery_codes": codes})
}

type totpDisableRequest struct {
	Password string `json:"password"`
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	user, _ := userFrom(r.Context())

	var req totpDisableRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}

	if err := s.deps.Auth.DisableTOTP(r.Context(), user.ID, req.Password); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, auth.ErrInvalidCredentials) {
			status = http.StatusUnauthorized
		}
		s.writeError(w, r, status, err.Error())

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// clientIP is used for login throttling.  chi's RealIP middleware has already
// applied any proxy headers.
func clientIP(r *http.Request) string {
	host, _, found := strings.Cut(r.RemoteAddr, ":")
	if !found {
		return r.RemoteAddr
	}

	return host
}
