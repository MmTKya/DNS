-- Phase 1: the query log.
--
-- The retention strategy matters more than the schema here. Comparable
-- products are known for query databases that grow into many gigabytes on an
-- SD card and for write patterns that wear the card out. So: rows are written
-- in batches rather than per query, kept only for the configured retention
-- window, and then rolled up into the two small aggregate tables below. The
-- live dashboard reads an in-memory ring buffer and never touches this at all.

CREATE TABLE query_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             INTEGER NOT NULL,
    client         TEXT    NOT NULL,
    client_id      TEXT    NOT NULL DEFAULT '',
    host           TEXT    NOT NULL,
    qtype          INTEGER NOT NULL,
    verdict        TEXT    NOT NULL,
    rule_source    TEXT    NOT NULL DEFAULT '',
    matched_domain TEXT    NOT NULL DEFAULT '',
    rcode          INTEGER NOT NULL DEFAULT 0,
    answers        INTEGER NOT NULL DEFAULT 0,
    elapsed_ms     REAL    NOT NULL DEFAULT 0,
    cached         INTEGER NOT NULL DEFAULT 0,
    upstream       TEXT    NOT NULL DEFAULT '',
    proto          TEXT    NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX query_log_ts ON query_log (ts);
CREATE INDEX query_log_client_ts ON query_log (client, ts);
CREATE INDEX query_log_host ON query_log (host);

-- Counts per hour and verdict. A handful of rows an hour, so this can be kept
-- effectively forever and is what the long-range charts read.
CREATE TABLE query_stats_hourly (
    hour    INTEGER NOT NULL,
    verdict TEXT    NOT NULL,
    count   INTEGER NOT NULL,
    PRIMARY KEY (hour, verdict)
) STRICT;

-- Bounded top-N per hour: the most queried names, the most blocked names and
-- the busiest clients. Keeping every name would reproduce exactly the growth
-- problem this design exists to avoid.
CREATE TABLE query_top_hourly (
    hour  INTEGER NOT NULL,
    kind  TEXT    NOT NULL,
    key   TEXT    NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (hour, kind, key)
) STRICT;
