-- Domains the operator has declared as their own — self-hosted services this
-- node must never treat as an unknown third-party name. Kept separate from
-- user_rules: an owned domain is not a block/allow decision, it is a
-- statement of fact that changes what the review queue even considers.
CREATE TABLE owned_domains (
    domain     TEXT PRIMARY KEY,
    label      TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);

-- Registration dates never change once known, so this is cached forever —
-- unlike intel_verdicts, which expires on purpose.
CREATE TABLE domain_age (
    domain        TEXT PRIMARY KEY,
    registered_at INTEGER NOT NULL,
    checked_at    INTEGER NOT NULL
);

-- Nullable on purpose: NULL means "never checked", which must not be read as
-- "checked and failed" — that mix-up is what put claude.ai in front of the
-- operator as something to block in the first place.
ALTER TABLE intel_verdicts ADD COLUMN tls_valid INTEGER;
ALTER TABLE intel_verdicts ADD COLUMN tls_checked_at INTEGER NOT NULL DEFAULT 0;
