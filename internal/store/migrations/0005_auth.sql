-- Phase 1: authentication.
--
-- Sessions are server-side and their tokens are stored hashed, so a copy of
-- the database does not hand over live logins. Same reasoning as passwords:
-- the row is a verifier, never the secret itself.

CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'admin',

    -- The TOTP secret has to be recoverable to validate a code, so it is
    -- stored as-is. Protecting it is the job of the file permissions on the
    -- database and the systemd hardening around it.
    totp_secret   TEXT    NOT NULL DEFAULT '',
    totp_enabled  INTEGER NOT NULL DEFAULT 0,

    created_at    INTEGER NOT NULL,
    last_login_at INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE sessions (
    token_hash TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_used  INTEGER NOT NULL DEFAULT 0,
    user_agent TEXT    NOT NULL DEFAULT '',
    ip         TEXT    NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expires ON sessions (expires_at);

-- One-time codes for when the authenticator app is on a lost phone.
CREATE TABLE recovery_codes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash TEXT    NOT NULL,
    used_at   INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX recovery_codes_user ON recovery_codes (user_id);
