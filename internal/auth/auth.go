package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/MmTKya/DNS/internal/store"
	"github.com/pquerna/otp/totp"
)

// Roles.  Read-only exists so a household member can watch the dashboard
// without being able to unblock anything.
const (
	RoleAdmin    = "admin"
	RoleReadOnly = "readonly"
)

// Errors callers are expected to distinguish.
var (
	// ErrInvalidCredentials is returned for a wrong username, a wrong
	// password and a wrong second factor alike.  Telling them apart would let
	// an attacker enumerate usernames.
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrTOTPRequired means the password was right but a code is still needed.
	ErrTOTPRequired = errors.New("a two-factor code is required")

	// ErrLockedOut means too many failed attempts.
	ErrLockedOut = errors.New("too many failed attempts, try again later")

	// ErrNoSession means the session is absent, expired or revoked.
	ErrNoSession = errors.New("no valid session")
)

// Login throttling.  Slow enough to make guessing pointless, forgiving enough
// that a typo does not lock a household out of its own router.
const (
	maxAttempts   = 8
	lockoutWindow = 15 * time.Minute
)

// User is an administrator of the node.
type User struct {
	CreatedAt   time.Time `json:"created_at"`
	LastLoginAt time.Time `json:"last_login_at,omitzero"`
	Username    string    `json:"username"`
	Role        string    `json:"role"`
	ID          int64     `json:"id"`
	TOTPEnabled bool      `json:"totp_enabled"`
}

// IsAdmin reports whether the user may change things.
func (u User) IsAdmin() bool { return u.Role == RoleAdmin }

// Session is a logged-in browser.
type Session struct {
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	LastUsed  time.Time `json:"last_used,omitzero"`
	UserAgent string    `json:"user_agent,omitempty"`
	IP        string    `json:"ip,omitempty"`
	UserID    int64     `json:"user_id"`
}

// Manager owns users and sessions.
type Manager struct {
	db     *store.DB
	logger *slog.Logger

	sessionTTL time.Duration

	// attempts throttles logins in memory rather than in the database: the
	// counter is worthless after a restart anyway, and it must not cost a
	// write per failed guess.
	mu       sync.Mutex
	attempts map[string]*attemptRecord
}

type attemptRecord struct {
	first time.Time
	count int
}

// New creates a manager.
func New(db *store.DB, sessionTTL time.Duration, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	if sessionTTL <= 0 {
		sessionTTL = 7 * 24 * time.Hour
	}

	return &Manager{
		db:         db,
		logger:     logger.With("component", "auth"),
		sessionTTL: sessionTTL,
		attempts:   map[string]*attemptRecord{},
	}
}

// NeedsSetup reports whether the node has no administrator yet, which is what
// puts the panel into its first-run flow.
func (m *Manager) NeedsSetup(ctx context.Context) (needs bool, err error) {
	var count int
	if err = m.db.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return false, fmt.Errorf("counting users: %w", err)
	}

	return count == 0, nil
}

// CreateUser adds an administrator.
func (m *Manager) CreateUser(ctx context.Context, username, password, role string) (user User, err error) {
	username = strings.TrimSpace(strings.ToLower(username))
	if username == "" {
		return User{}, errors.New("a username is required")
	}
	if err = ValidatePassword(password); err != nil {
		return User{}, err
	}
	if role != RoleAdmin && role != RoleReadOnly {
		return User{}, fmt.Errorf("unknown role %q", role)
	}

	hash, err := HashPassword(password)
	if err != nil {
		return User{}, err
	}

	now := time.Now()
	res, err := m.db.Writer().ExecContext(ctx, `
		INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)
	`, username, hash, role, now.Unix())
	if err != nil {
		return User{}, fmt.Errorf("creating user %s: %w", username, err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return User{}, fmt.Errorf("reading new user id: %w", err)
	}

	return User{ID: id, Username: username, Role: role, CreatedAt: now}, nil
}

// ValidatePassword enforces a floor on password strength.
//
// Length is the only requirement.  Composition rules ("one capital, one
// symbol") push people towards predictable substitutions and are not worth the
// friction on a device its owner logs into from their sofa.
func ValidatePassword(password string) error {
	if len(password) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	if len(password) > 256 {
		return errors.New("password must be at most 256 characters")
	}

	return nil
}

// Login verifies credentials and returns a session token.
//
// The token is returned once, here, and only its hash is stored.
func (m *Manager) Login(ctx context.Context, username, password, code, ip, userAgent string) (token string, user User, err error) {
	username = strings.TrimSpace(strings.ToLower(username))

	if m.lockedOut(username) || m.lockedOut(ip) {
		return "", User{}, ErrLockedOut
	}

	row := m.db.Reader().QueryRowContext(ctx, `
		SELECT id, username, password_hash, role, totp_secret, totp_enabled, created_at
		FROM users WHERE username = ?
	`, username)

	var (
		hash        string
		totpSecret  string
		totpEnabled int
		createdAt   int64
	)
	err = row.Scan(&user.ID, &user.Username, &hash, &user.Role, &totpSecret, &totpEnabled, &createdAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// Hash a dummy password anyway, so that a missing user and a wrong
		// password take the same time and cannot be told apart.
		_, _ = HashPassword(password)
		m.recordFailure(username, ip)

		return "", User{}, ErrInvalidCredentials

	case err != nil:
		return "", User{}, fmt.Errorf("reading user: %w", err)
	}

	user.CreatedAt = time.Unix(createdAt, 0)
	user.TOTPEnabled = totpEnabled != 0

	ok, err := VerifyPassword(password, hash)
	if err != nil {
		return "", User{}, fmt.Errorf("verifying password: %w", err)
	}
	if !ok {
		m.recordFailure(username, ip)

		return "", User{}, ErrInvalidCredentials
	}

	if user.TOTPEnabled {
		if code == "" {
			return "", User{}, ErrTOTPRequired
		}

		valid, totpErr := m.checkSecondFactor(ctx, user.ID, totpSecret, code)
		if totpErr != nil {
			return "", User{}, totpErr
		}
		if !valid {
			m.recordFailure(username, ip)

			return "", User{}, ErrInvalidCredentials
		}
	}

	m.clearFailures(username, ip)

	token, err = m.createSession(ctx, user.ID, ip, userAgent)
	if err != nil {
		return "", User{}, err
	}

	if _, err = m.db.Writer().ExecContext(ctx,
		`UPDATE users SET last_login_at = ? WHERE id = ?`, time.Now().Unix(), user.ID); err != nil {
		m.logger.WarnContext(ctx, "recording last login", "user", username, "err", err)
	}

	return token, user, nil
}

// checkSecondFactor accepts either a TOTP code or an unused recovery code.
func (m *Manager) checkSecondFactor(ctx context.Context, userID int64, secret, code string) (valid bool, err error) {
	code = strings.TrimSpace(strings.ReplaceAll(code, " ", ""))

	if totp.Validate(code, secret) {
		return true, nil
	}

	return m.consumeRecoveryCode(ctx, userID, code)
}

// createSession stores a hashed token and returns the plaintext one.
func (m *Manager) createSession(ctx context.Context, userID int64, ip, userAgent string) (token string, err error) {
	// 32 bytes of entropy: not guessable, and short enough for a cookie.
	if token, err = randomToken(32); err != nil {
		return "", err
	}

	now := time.Now()
	if _, err = m.db.Writer().ExecContext(ctx, `
		INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_used, user_agent, ip)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, hashToken(token), userID, now.Unix(), now.Add(m.sessionTTL).Unix(), now.Unix(),
		truncate(userAgent, 200), ip,
	); err != nil {
		return "", fmt.Errorf("creating session: %w", err)
	}

	return token, nil
}

// Authenticate resolves a session token to its user.
func (m *Manager) Authenticate(ctx context.Context, token string) (user User, err error) {
	if token == "" {
		return User{}, ErrNoSession
	}

	row := m.db.Reader().QueryRowContext(ctx, `
		SELECT u.id, u.username, u.role, u.totp_enabled, u.created_at, s.expires_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ?
	`, hashToken(token))

	var (
		totpEnabled int
		createdAt   int64
		expiresAt   int64
	)
	err = row.Scan(&user.ID, &user.Username, &user.Role, &totpEnabled, &createdAt, &expiresAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return User{}, ErrNoSession
	case err != nil:
		return User{}, fmt.Errorf("reading session: %w", err)
	}

	if time.Now().Unix() > expiresAt {
		// Clean up as we go, so expired rows do not accumulate on a node
		// nobody is administering.
		_ = m.Logout(ctx, token)

		return User{}, ErrNoSession
	}

	user.TOTPEnabled = totpEnabled != 0
	user.CreatedAt = time.Unix(createdAt, 0)

	return user, nil
}

// Touch records that a session was used, at most once a minute so that
// browsing the panel does not turn into a write per request.
func (m *Manager) Touch(ctx context.Context, token string) {
	if _, err := m.db.Writer().ExecContext(ctx, `
		UPDATE sessions SET last_used = ? WHERE token_hash = ? AND last_used < ?
	`, time.Now().Unix(), hashToken(token), time.Now().Add(-time.Minute).Unix()); err != nil {
		m.logger.DebugContext(ctx, "touching session", "err", err)
	}
}

// Logout revokes one session.
func (m *Manager) Logout(ctx context.Context, token string) error {
	if _, err := m.db.Writer().ExecContext(ctx,
		`DELETE FROM sessions WHERE token_hash = ?`, hashToken(token)); err != nil {
		return fmt.Errorf("deleting session: %w", err)
	}

	return nil
}

// LogoutAll revokes every session for a user, which is what a password change
// or a lost laptop calls for.
func (m *Manager) LogoutAll(ctx context.Context, userID int64) error {
	if _, err := m.db.Writer().ExecContext(ctx,
		`DELETE FROM sessions WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("deleting sessions: %w", err)
	}

	return nil
}

// ChangePassword updates a password and revokes existing sessions.
func (m *Manager) ChangePassword(ctx context.Context, userID int64, current, next string) error {
	var hash string
	if err := m.db.Reader().QueryRowContext(ctx,
		`SELECT password_hash FROM users WHERE id = ?`, userID).Scan(&hash); err != nil {
		return fmt.Errorf("reading user: %w", err)
	}

	ok, err := VerifyPassword(current, hash)
	if err != nil {
		return fmt.Errorf("verifying password: %w", err)
	}
	if !ok {
		return ErrInvalidCredentials
	}

	if err = ValidatePassword(next); err != nil {
		return err
	}

	newHash, err := HashPassword(next)
	if err != nil {
		return err
	}

	if _, err = m.db.Writer().ExecContext(ctx,
		`UPDATE users SET password_hash = ? WHERE id = ?`, newHash, userID); err != nil {
		return fmt.Errorf("updating password: %w", err)
	}

	// Anyone holding a session from before the change should be pushed out;
	// that is usually the reason for changing it.
	return m.LogoutAll(ctx, userID)
}

// Purge deletes expired sessions.
func (m *Manager) Purge(ctx context.Context) error {
	if _, err := m.db.Writer().ExecContext(ctx,
		`DELETE FROM sessions WHERE expires_at < ?`, time.Now().Unix()); err != nil {
		return fmt.Errorf("purging sessions: %w", err)
	}

	return nil
}

// Run purges expired sessions until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.Purge(ctx); err != nil {
				m.logger.ErrorContext(ctx, "purging sessions", "err", err)
			}
		}
	}
}

// ListUsers returns every administrator.
func (m *Manager) ListUsers(ctx context.Context) (users []User, err error) {
	rows, err := m.db.Reader().QueryContext(ctx, `
		SELECT id, username, role, totp_enabled, created_at, last_login_at FROM users ORDER BY id
	`)
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			u                    User
			totpEnabled          int
			createdAt, lastLogin int64
		)
		if err = rows.Scan(&u.ID, &u.Username, &u.Role, &totpEnabled, &createdAt, &lastLogin); err != nil {
			return nil, fmt.Errorf("scanning user: %w", err)
		}

		u.TOTPEnabled = totpEnabled != 0
		u.CreatedAt = time.Unix(createdAt, 0)
		if lastLogin > 0 {
			u.LastLoginAt = time.Unix(lastLogin, 0)
		}

		users = append(users, u)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating users: %w", err)
	}

	return users, nil
}

// --- throttling ---

func (m *Manager) lockedOut(key string) bool {
	if key == "" {
		return false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	rec, ok := m.attempts[key]
	if !ok {
		return false
	}

	if time.Since(rec.first) > lockoutWindow {
		delete(m.attempts, key)

		return false
	}

	return rec.count >= maxAttempts
}

func (m *Manager) recordFailure(keys ...string) {
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, key := range keys {
		if key == "" {
			continue
		}

		rec, ok := m.attempts[key]
		if !ok || now.Sub(rec.first) > lockoutWindow {
			m.attempts[key] = &attemptRecord{first: now, count: 1}

			continue
		}

		rec.count++
	}
}

func (m *Manager) clearFailures(keys ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, key := range keys {
		delete(m.attempts, key)
	}
}

// --- helpers ---

// hashToken hashes a session token for storage.  SHA-256 is right here rather
// than argon2: the token is 32 random bytes, so there is nothing to guess and
// no reason to make every request pay a slow hash.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))

	return hex.EncodeToString(sum[:])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}

	return s[:n]
}

// Issuer is the label shown in an authenticator app.
const Issuer = "SedDNS"
