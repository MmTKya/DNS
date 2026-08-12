package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

// recoveryCodeCount is how many one-time codes are issued when two-factor is
// switched on.  They exist for the case the authenticator app is on a phone
// that is now lost or wiped — without them, enabling TOTP is a way to lock
// yourself out of your own network's DNS.
const recoveryCodeCount = 10

// Enrollment is an in-progress two-factor setup.
type Enrollment struct {
	// Secret is shown as text for anyone typing it in by hand.
	Secret string `json:"secret"`

	// URL is the otpauth:// URI a QR code encodes.
	URL string `json:"url"`
}

// BeginTOTP creates a secret for a user without switching two-factor on.
//
// Enrollment is deliberately two-step: the secret only takes effect once the
// user has proved, with a working code, that their app really has it.
func (m *Manager) BeginTOTP(ctx context.Context, userID int64, username string) (enrollment Enrollment, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      Issuer,
		AccountName: username,
	})
	if err != nil {
		return Enrollment{}, fmt.Errorf("generating totp secret: %w", err)
	}

	if _, err = m.db.Writer().ExecContext(ctx,
		`UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE id = ?`,
		key.Secret(), userID,
	); err != nil {
		return Enrollment{}, fmt.Errorf("storing totp secret: %w", err)
	}

	return Enrollment{Secret: key.Secret(), URL: key.URL()}, nil
}

// ConfirmTOTP switches two-factor on once the user proves the app works, and
// returns the recovery codes.  They are shown once and stored only as hashes.
func (m *Manager) ConfirmTOTP(ctx context.Context, userID int64, code string) (recoveryCodes []string, err error) {
	var secret string
	if err = m.db.Reader().QueryRowContext(ctx,
		`SELECT totp_secret FROM users WHERE id = ?`, userID).Scan(&secret); err != nil {
		return nil, fmt.Errorf("reading totp secret: %w", err)
	}
	if secret == "" {
		return nil, errors.New("two-factor enrollment has not been started")
	}

	if !totp.Validate(strings.TrimSpace(code), secret) {
		return nil, ErrInvalidCredentials
	}

	if _, err = m.db.Writer().ExecContext(ctx,
		`UPDATE users SET totp_enabled = 1 WHERE id = ?`, userID); err != nil {
		return nil, fmt.Errorf("enabling two-factor: %w", err)
	}

	return m.regenerateRecoveryCodes(ctx, userID)
}

// DisableTOTP switches two-factor off, requiring the current password so that
// a borrowed session cannot quietly weaken the account.
func (m *Manager) DisableTOTP(ctx context.Context, userID int64, password string) error {
	var hash string
	if err := m.db.Reader().QueryRowContext(ctx,
		`SELECT password_hash FROM users WHERE id = ?`, userID).Scan(&hash); err != nil {
		return fmt.Errorf("reading user: %w", err)
	}

	ok, err := VerifyPassword(password, hash)
	if err != nil {
		return fmt.Errorf("verifying password: %w", err)
	}
	if !ok {
		return ErrInvalidCredentials
	}

	if _, err = m.db.Writer().ExecContext(ctx,
		`UPDATE users SET totp_enabled = 0, totp_secret = '' WHERE id = ?`, userID); err != nil {
		return fmt.Errorf("disabling two-factor: %w", err)
	}

	if _, err = m.db.Writer().ExecContext(ctx,
		`DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
		return fmt.Errorf("clearing recovery codes: %w", err)
	}

	return nil
}

// regenerateRecoveryCodes replaces any existing codes with a fresh set.
func (m *Manager) regenerateRecoveryCodes(ctx context.Context, userID int64) (codes []string, err error) {
	if _, err = m.db.Writer().ExecContext(ctx,
		`DELETE FROM recovery_codes WHERE user_id = ?`, userID); err != nil {
		return nil, fmt.Errorf("clearing recovery codes: %w", err)
	}

	codes = make([]string, 0, recoveryCodeCount)
	for range recoveryCodeCount {
		code, genErr := randomToken(8)
		if genErr != nil {
			return nil, genErr
		}

		if _, err = m.db.Writer().ExecContext(ctx,
			`INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)`,
			userID, hashToken(code),
		); err != nil {
			return nil, fmt.Errorf("storing recovery code: %w", err)
		}

		codes = append(codes, code)
	}

	return codes, nil
}

// RegenerateRecoveryCodes issues a new set, invalidating the old one.
func (m *Manager) RegenerateRecoveryCodes(ctx context.Context, userID int64) ([]string, error) {
	return m.regenerateRecoveryCodes(ctx, userID)
}

// consumeRecoveryCode spends a one-time code.
func (m *Manager) consumeRecoveryCode(ctx context.Context, userID int64, code string) (valid bool, err error) {
	rows, err := m.db.Reader().QueryContext(ctx,
		`SELECT id, code_hash FROM recovery_codes WHERE user_id = ? AND used_at = 0`, userID)
	if err != nil {
		return false, fmt.Errorf("reading recovery codes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	want := hashToken(code)

	var matchID int64
	for rows.Next() {
		var (
			id   int64
			hash string
		)
		if err = rows.Scan(&id, &hash); err != nil {
			return false, fmt.Errorf("scanning recovery code: %w", err)
		}

		// Constant time even though these are hashes: it costs nothing and
		// removes the question.
		if subtle.ConstantTimeCompare([]byte(hash), []byte(want)) == 1 {
			matchID = id
		}
	}

	if err = rows.Err(); err != nil {
		return false, fmt.Errorf("iterating recovery codes: %w", err)
	}

	if matchID == 0 {
		return false, nil
	}

	// Mark it spent rather than deleting it, so the panel can show how many
	// are left and that one was used.
	if _, err = m.db.Writer().ExecContext(ctx,
		`UPDATE recovery_codes SET used_at = ? WHERE id = ?`, time.Now().Unix(), matchID); err != nil {
		return false, fmt.Errorf("spending recovery code: %w", err)
	}

	return true, nil
}

// RecoveryCodesLeft reports how many unused codes a user has.
func (m *Manager) RecoveryCodesLeft(ctx context.Context, userID int64) (count int, err error) {
	if err = m.db.Reader().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at = 0`, userID,
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("counting recovery codes: %w", err)
	}

	return count, nil
}
