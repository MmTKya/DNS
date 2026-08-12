-- Phase 1: filtering state.
--
-- Feeds and user rules live here rather than in the YAML config because they
-- are managed from the panel and change often. The configuration file stays
-- the province of settings an operator writes once.

CREATE TABLE feeds (
    id              TEXT    PRIMARY KEY,
    name            TEXT    NOT NULL,
    url             TEXT    NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 0,

    -- Custom feeds were added by the operator and are not in the built-in
    -- catalogue, so their metadata cannot be looked up and is kept here.
    custom          INTEGER NOT NULL DEFAULT 0,

    -- Cache validators. Sending these back turns a daily poll of a
    -- half-million-entry list into a 304 with no body.
    etag            TEXT    NOT NULL DEFAULT '',
    last_modified   TEXT    NOT NULL DEFAULT '',

    last_fetch_at   INTEGER NOT NULL DEFAULT 0,
    last_success_at INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT    NOT NULL DEFAULT '',
    rule_count      INTEGER NOT NULL DEFAULT 0,
    bytes           INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX feeds_enabled ON feeds (enabled);

-- Rules the operator wrote themselves. These always win over feed content in
-- the compile order, so a manual allow can rescue a name that a feed blocks.
CREATE TABLE user_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    rule       TEXT    NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    comment    TEXT    NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
) STRICT;
