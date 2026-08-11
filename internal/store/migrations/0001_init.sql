-- Phase 0 schema.
--
-- Only the key/value settings table exists so far.  It holds small pieces of
-- node identity and state that must outlive a restart but do not belong in the
-- operator-editable YAML: the install id, the first-run setup token, the last
-- update check, and so on.  Query logs, filter rules, clients and cluster state
-- arrive in later phases as their own tables.

CREATE TABLE settings (
    key        TEXT    PRIMARY KEY,
    value      TEXT    NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;
