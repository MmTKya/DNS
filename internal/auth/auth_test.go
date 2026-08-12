package auth_test

import (
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MmTKya/DNS/internal/auth"
	"github.com/MmTKya/DNS/internal/store"
	"github.com/pquerna/otp/totp"
)

const testPassword = "correct-horse-battery-staple"

func newManager(t *testing.T) (*auth.Manager, *store.DB) {
	t.Helper()

	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "aegisdns.db"))
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	return auth.New(db, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil))), db
}

func TestPasswordHashing(t *testing.T) {
	t.Parallel()

	hash, err := auth.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	// The hash must not contain the password, and must carry its parameters so
	// the cost can be raised later without invalidating existing passwords.
	if strings.Contains(hash, testPassword) {
		t.Fatal("the hash contains the password")
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("hash = %q, want an argon2id encoding", hash)
	}

	ok, err := auth.VerifyPassword(testPassword, hash)
	if err != nil || !ok {
		t.Errorf("VerifyPassword(correct) = %t, %v; want true, nil", ok, err)
	}

	ok, err = auth.VerifyPassword("wrong-password-entirely", hash)
	if err != nil || ok {
		t.Errorf("VerifyPassword(wrong) = %t, %v; want false, nil", ok, err)
	}

	// Two hashes of the same password must differ: the salt is what stops one
	// leaked hash from revealing that two accounts share a password.
	second, err := auth.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == second {
		t.Error("hashes of the same password are identical; the salt is not random")
	}
}

func TestVerifyRejectsMalformedHash(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{"", "plaintext", "$argon2id$broken", "$bcrypt$v=19$m=1,t=1,p=1$aaaa$bbbb"} {
		if _, err := auth.VerifyPassword("x", bad); err == nil {
			t.Errorf("VerifyPassword with hash %q returned no error", bad)
		}
	}
}

func TestNeedsSetupAndFirstUser(t *testing.T) {
	t.Parallel()

	mgr, _ := newManager(t)
	ctx := t.Context()

	needs, err := mgr.NeedsSetup(ctx)
	if err != nil {
		t.Fatalf("NeedsSetup: %v", err)
	}
	if !needs {
		t.Error("a fresh node must report that it needs setup")
	}

	if _, err = mgr.CreateUser(ctx, "Admin", testPassword, auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if needs, err = mgr.NeedsSetup(ctx); err != nil || needs {
		t.Errorf("NeedsSetup after creating a user = %t, %v; want false, nil", needs, err)
	}
}

func TestLoginAndSession(t *testing.T) {
	t.Parallel()

	mgr, _ := newManager(t)
	ctx := t.Context()

	if _, err := mgr.CreateUser(ctx, "admin", testPassword, auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	token, user, err := mgr.Login(ctx, "admin", testPassword, "", "192.168.1.5", "test-agent")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if token == "" {
		t.Fatal("Login returned an empty token")
	}
	if user.Username != "admin" {
		t.Errorf("username = %q, want %q", user.Username, "admin")
	}

	got, err := mgr.Authenticate(ctx, token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.ID != user.ID {
		t.Errorf("authenticated user id = %d, want %d", got.ID, user.ID)
	}

	if err = mgr.Logout(ctx, token); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err = mgr.Authenticate(ctx, token); !errors.Is(err, auth.ErrNoSession) {
		t.Errorf("Authenticate after logout = %v, want ErrNoSession", err)
	}
}

func TestSessionTokenIsStoredHashed(t *testing.T) {
	t.Parallel()

	mgr, db := newManager(t)
	ctx := t.Context()

	if _, err := mgr.CreateUser(ctx, "admin", testPassword, auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	token, _, err := mgr.Login(ctx, "admin", testPassword, "", "", "")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	var stored string
	if err = db.Reader().QueryRowContext(ctx, `SELECT token_hash FROM sessions`).Scan(&stored); err != nil {
		t.Fatalf("reading session: %v", err)
	}

	// A copy of the database must not hand over live logins.
	if stored == token {
		t.Error("the session token is stored in plaintext")
	}
	if strings.Contains(stored, token) {
		t.Error("the stored value contains the token")
	}
}

func TestWrongCredentialsAreIndistinguishable(t *testing.T) {
	t.Parallel()

	mgr, _ := newManager(t)
	ctx := t.Context()

	if _, err := mgr.CreateUser(ctx, "admin", testPassword, auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	_, _, wrongUser := mgr.Login(ctx, "nobody", testPassword, "", "", "")
	_, _, wrongPass := mgr.Login(ctx, "admin", "not-the-password", "", "", "")

	// Distinguishable errors would let an attacker enumerate usernames.
	if !errors.Is(wrongUser, auth.ErrInvalidCredentials) || !errors.Is(wrongPass, auth.ErrInvalidCredentials) {
		t.Errorf("unknown user = %v, wrong password = %v; both should be ErrInvalidCredentials", wrongUser, wrongPass)
	}
}

func TestLockoutAfterRepeatedFailures(t *testing.T) {
	t.Parallel()

	mgr, _ := newManager(t)
	ctx := t.Context()

	if _, err := mgr.CreateUser(ctx, "admin", testPassword, auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	var lockedOut bool
	for range 12 {
		if _, _, err := mgr.Login(ctx, "admin", "wrong", "", "10.0.0.1", ""); errors.Is(err, auth.ErrLockedOut) {
			lockedOut = true

			break
		}
	}
	if !lockedOut {
		t.Fatal("repeated failures should trigger a lockout")
	}

	// Even the correct password is refused while locked out.
	if _, _, err := mgr.Login(ctx, "admin", testPassword, "", "10.0.0.1", ""); !errors.Is(err, auth.ErrLockedOut) {
		t.Errorf("login during lockout = %v, want ErrLockedOut", err)
	}
}

func TestTOTPEnrollmentFlow(t *testing.T) {
	t.Parallel()

	mgr, _ := newManager(t)
	ctx := t.Context()

	user, err := mgr.CreateUser(ctx, "admin", testPassword, auth.RoleAdmin)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	enrollment, err := mgr.BeginTOTP(ctx, user.ID, user.Username)
	if err != nil {
		t.Fatalf("BeginTOTP: %v", err)
	}
	if enrollment.Secret == "" || !strings.HasPrefix(enrollment.URL, "otpauth://") {
		t.Fatalf("enrollment = %+v, want a secret and an otpauth URL", enrollment)
	}

	// Enrollment must not take effect until a working code proves the app
	// really has the secret — otherwise a mistyped setup locks the user out.
	if _, _, loginErr := mgr.Login(ctx, "admin", testPassword, "", "", ""); loginErr != nil {
		t.Errorf("login during enrollment = %v, want it to still work", loginErr)
	}

	code, err := totp.GenerateCode(enrollment.Secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	recovery, err := mgr.ConfirmTOTP(ctx, user.ID, code)
	if err != nil {
		t.Fatalf("ConfirmTOTP: %v", err)
	}
	if len(recovery) < 5 {
		t.Errorf("got %d recovery codes, want a usable set", len(recovery))
	}

	// Now the second factor is required.
	if _, _, err = mgr.Login(ctx, "admin", testPassword, "", "", ""); !errors.Is(err, auth.ErrTOTPRequired) {
		t.Errorf("login without a code = %v, want ErrTOTPRequired", err)
	}

	code, err = totp.GenerateCode(enrollment.Secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if _, _, err = mgr.Login(ctx, "admin", testPassword, code, "", ""); err != nil {
		t.Errorf("login with a valid code: %v", err)
	}
}

func TestRecoveryCodeIsSingleUse(t *testing.T) {
	t.Parallel()

	mgr, _ := newManager(t)
	ctx := t.Context()

	user, err := mgr.CreateUser(ctx, "admin", testPassword, auth.RoleAdmin)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	enrollment, err := mgr.BeginTOTP(ctx, user.ID, user.Username)
	if err != nil {
		t.Fatalf("BeginTOTP: %v", err)
	}

	code, err := totp.GenerateCode(enrollment.Secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	recovery, err := mgr.ConfirmTOTP(ctx, user.ID, code)
	if err != nil {
		t.Fatalf("ConfirmTOTP: %v", err)
	}

	// A recovery code stands in for the authenticator app when the phone is
	// gone, which is the difference between a lost phone and a lost network.
	if _, _, err = mgr.Login(ctx, "admin", testPassword, recovery[0], "", ""); err != nil {
		t.Fatalf("login with a recovery code: %v", err)
	}

	left, err := mgr.RecoveryCodesLeft(ctx, user.ID)
	if err != nil {
		t.Fatalf("RecoveryCodesLeft: %v", err)
	}
	if left != len(recovery)-1 {
		t.Errorf("%d codes left, want %d", left, len(recovery)-1)
	}

	// The same code must not work twice.
	if _, _, err = mgr.Login(ctx, "admin", testPassword, recovery[0], "", ""); err == nil {
		t.Error("a recovery code was accepted twice")
	}
}

func TestChangePasswordRevokesSessions(t *testing.T) {
	t.Parallel()

	mgr, _ := newManager(t)
	ctx := t.Context()

	user, err := mgr.CreateUser(ctx, "admin", testPassword, auth.RoleAdmin)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	token, _, err := mgr.Login(ctx, "admin", testPassword, "", "", "")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	const next = "an-entirely-different-passphrase"
	if err = mgr.ChangePassword(ctx, user.ID, testPassword, next); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	// Changing a password is usually a response to it being compromised, so
	// existing sessions have to go with it.
	if _, err = mgr.Authenticate(ctx, token); !errors.Is(err, auth.ErrNoSession) {
		t.Errorf("session after password change = %v, want ErrNoSession", err)
	}

	if _, _, err = mgr.Login(ctx, "admin", next, "", "", ""); err != nil {
		t.Errorf("login with the new password: %v", err)
	}
}

func TestChangePasswordRequiresCurrentOne(t *testing.T) {
	t.Parallel()

	mgr, _ := newManager(t)
	ctx := t.Context()

	user, err := mgr.CreateUser(ctx, "admin", testPassword, auth.RoleAdmin)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if err = mgr.ChangePassword(ctx, user.ID, "wrong", "another-long-enough-password"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("ChangePassword with the wrong current password = %v, want ErrInvalidCredentials", err)
	}
}

func TestExpiredSessionIsRejected(t *testing.T) {
	t.Parallel()

	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "aegisdns.db"))
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// A TTL in the past makes every session born expired.
	mgr := auth.New(db, -time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := t.Context()

	if _, err = mgr.CreateUser(ctx, "admin", testPassword, auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// A negative TTL falls back to the default, so age the row instead.
	token, user, err := mgr.Login(ctx, "admin", testPassword, "", "", "")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	if _, err = db.Writer().ExecContext(ctx,
		`UPDATE sessions SET expires_at = ? WHERE user_id = ?`, time.Now().Add(-time.Hour).Unix(), user.ID); err != nil {
		t.Fatalf("expiring session: %v", err)
	}

	if _, err = mgr.Authenticate(ctx, token); !errors.Is(err, auth.ErrNoSession) {
		t.Errorf("expired session = %v, want ErrNoSession", err)
	}
}

func TestPasswordPolicy(t *testing.T) {
	t.Parallel()

	if err := auth.ValidatePassword("short"); err == nil {
		t.Error("a short password should be rejected")
	}
	if err := auth.ValidatePassword(testPassword); err != nil {
		t.Errorf("a reasonable passphrase was rejected: %v", err)
	}
	if err := auth.ValidatePassword(strings.Repeat("a", 300)); err == nil {
		t.Error("an absurdly long password should be rejected")
	}
}
