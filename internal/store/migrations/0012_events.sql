-- Things the node noticed that are not queries.
--
-- These used to be visible only in the journal, which meant the answer to
-- "why did that page not open" was a shell session on the machine. A
-- household resolver should be able to explain itself from its own screen.
--
-- Deliberately not the query log: those are what devices asked for and there
-- are hundreds of thousands of them. These are the handful of moments that
-- explain a failure, so they are kept longer and read differently.
CREATE TABLE events (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	at       TEXT    NOT NULL DEFAULT (datetime('now')),

	-- What happened. Kept as text rather than an enum so a later version can
	-- record something new without a migration and an old panel can still
	-- display it.
	kind     TEXT    NOT NULL,

	-- info, warning, error — what it means for the household, not for the
	-- developer. A rescued lookup is information; a blocklist that has not
	-- updated in days is a warning.
	severity TEXT    NOT NULL DEFAULT 'info',

	-- The name, feed or resolver the event is about.
	subject  TEXT    NOT NULL DEFAULT '',

	-- One line of plain English. This is what someone reads.
	detail   TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX idx_events_at ON events (at DESC);
CREATE INDEX idx_events_kind ON events (kind, at DESC);
