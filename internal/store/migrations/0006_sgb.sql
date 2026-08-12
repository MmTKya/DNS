-- Phase 2: the Turkish national threat feed (USOM, now under the Cyber
-- Security Directorate).
--
-- This one is not a text file like the community lists, so it does not go
-- through the ordinary downloader. It is a paged JSON API whose ids are
-- monotonic, which allows an hourly delta of only what is new instead of
-- re-fetching 460,000 records. Entries can also be removed upstream, so a
-- daily full reconcile is what catches deletions; without it a domain would
-- stay blocked here forever after being cleared.
--
-- The rows are kept rather than only the compiled list because the category
-- and criticality are worth showing: "USOM lists this as banking phishing,
-- added three days ago" is a far better answer than "a blocklist said so".

CREATE TABLE sgb_entries (
    -- The upstream id, not ours: it is what the delta sync tracks.
    id          INTEGER PRIMARY KEY,
    value       TEXT    NOT NULL,
    type        TEXT    NOT NULL,
    category    TEXT    NOT NULL DEFAULT '',
    source      TEXT    NOT NULL DEFAULT '',
    criticality INTEGER NOT NULL DEFAULT 0,
    added_at    INTEGER NOT NULL DEFAULT 0,

    -- Which full pass last saw this row. A counter rather than a timestamp:
    -- two syncs inside the same second would compare equal, and a clock that
    -- steps backwards would make a timestamp comparison delete the wrong rows.
    sync_run    INTEGER NOT NULL DEFAULT 0,

    synced_at   INTEGER NOT NULL
) STRICT;

CREATE INDEX sgb_entries_value ON sgb_entries (value);
CREATE INDEX sgb_entries_type ON sgb_entries (type);
