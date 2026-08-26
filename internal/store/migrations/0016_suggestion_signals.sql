-- The review screen shows a domain's TLS/age signals, but until now nothing
-- carried them from the check that computed them to the suggestion a person
-- actually reads — the panel always showed "not checked" regardless of what
-- the node found, because there was nowhere to put the answer.
--
-- Nullable throughout, for the same reason intel_verdicts.tls_valid is: "not
-- checked" and "checked, found invalid" are different claims, and a column
-- that cannot tell them apart would make the same mistake this fixes.
ALTER TABLE intel_suggestions ADD COLUMN tls_valid INTEGER;
ALTER TABLE intel_suggestions ADD COLUMN tls_note TEXT NOT NULL DEFAULT '';
ALTER TABLE intel_suggestions ADD COLUMN domain_age_days INTEGER;
ALTER TABLE intel_suggestions ADD COLUMN protected INTEGER NOT NULL DEFAULT 0;
ALTER TABLE intel_suggestions ADD COLUMN high_risk INTEGER NOT NULL DEFAULT 0;
