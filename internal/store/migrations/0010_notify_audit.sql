-- Phase 6: notifications and the audit trail.

-- Where alerts go. Several destinations can be active at once, because the
-- person who wants an email about a failed feed is often not the person who
-- wants a push about a device being paused.
CREATE TABLE notify_channels (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT    NOT NULL,
    name       TEXT    NOT NULL,

    -- Kind-specific settings as JSON: an SMTP server and credentials, a
    -- webhook URL, a chat token. Kept opaque here so a new channel type does
    -- not need a migration.
    config     TEXT    NOT NULL DEFAULT '{}',

    -- Only alerts at or above this severity are sent here.
    min_severity TEXT  NOT NULL DEFAULT 'warning',

    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,

    last_sent  INTEGER NOT NULL DEFAULT 0,
    last_error TEXT    NOT NULL DEFAULT ''
) STRICT;

-- What has already been sent, so the same problem does not arrive every minute
-- for an hour. An alert that repeats until it is ignored has stopped being an
-- alert.
CREATE TABLE notify_history (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    key       TEXT    NOT NULL,
    severity  TEXT    NOT NULL,
    title     TEXT    NOT NULL,
    body      TEXT    NOT NULL DEFAULT '',
    sent_at   INTEGER NOT NULL,
    delivered INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX notify_history_key ON notify_history (key, sent_at);

-- Who changed what, and when.
--
-- None of the comparable products keep one, and it is the difference between
-- "the internet broke last Tuesday" and "someone disabled the malware list on
-- Tuesday at nine".
CREATE TABLE audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    at        INTEGER NOT NULL,
    username  TEXT    NOT NULL DEFAULT '',
    ip        TEXT    NOT NULL DEFAULT '',
    action    TEXT    NOT NULL,
    target    TEXT    NOT NULL DEFAULT '',
    detail    TEXT    NOT NULL DEFAULT '',
    success   INTEGER NOT NULL DEFAULT 1
) STRICT;

CREATE INDEX audit_log_at ON audit_log (at);
CREATE INDEX audit_log_username ON audit_log (username, at);
