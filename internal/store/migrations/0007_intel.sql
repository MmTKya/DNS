-- Phase 2: threat intelligence and the "should I block this?" queue.

-- Cached verdicts. Every external source here is rate-limited and most are
-- free-tier, so asking twice about the same name is both slow and rude. A
-- verdict is kept until it expires; a clean result expires sooner than a
-- malicious one, because a name that is bad today is unlikely to be fine
-- tomorrow, while a name that is fine today may be compromised by then.
CREATE TABLE intel_verdicts (
    domain     TEXT    PRIMARY KEY,
    score      INTEGER NOT NULL DEFAULT 0,
    verdict    TEXT    NOT NULL DEFAULT 'unknown',

    -- The individual source findings, as JSON, so the panel can show who said
    -- what rather than only a number.
    findings   TEXT    NOT NULL DEFAULT '[]',

    checked_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
) STRICT;

CREATE INDEX intel_verdicts_expires ON intel_verdicts (expires_at);

-- Names the node thinks are worth blocking, waiting for a human to decide.
--
-- Automatic blocking is available but off by default. Machine-generated
-- blocklists are wrong often enough that an unexplained, unattributed,
-- automatic block is how a household loses trust in the thing that is
-- supposed to be protecting it.
CREATE TABLE intel_suggestions (
    domain      TEXT    PRIMARY KEY,
    score       INTEGER NOT NULL DEFAULT 0,
    reason      TEXT    NOT NULL DEFAULT '',
    findings    TEXT    NOT NULL DEFAULT '[]',

    -- Which devices asked for it, so the operator can see whether this is the
    -- smart TV phoning home or someone's laptop in trouble.
    clients     TEXT    NOT NULL DEFAULT '',

    query_count INTEGER NOT NULL DEFAULT 0,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,

    -- pending, blocked, allowed or ignored.
    status      TEXT    NOT NULL DEFAULT 'pending',
    decided_at  INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX intel_suggestions_status ON intel_suggestions (status, score DESC);
