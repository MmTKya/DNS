-- Upstream resolvers chosen by the operator.
--
-- Kept here rather than in the configuration file because this is a decision
-- people make from the panel after seeing how their own line behaves: the
-- shipped defaults are a guess about the whole world, and the nearest fast
-- resolver differs by country and by ISP.
--
-- An empty table means "use what shipped". That is what makes deleting the
-- last row safe: the node falls back to the built-in defaults rather than
-- ending up with no way to resolve anything.
CREATE TABLE upstreams (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	address    TEXT    NOT NULL UNIQUE,

	-- 'primary'  asked for every query
	-- 'fallback' asked only when every primary has failed
	--
	-- Not a preference order: a fallback that were merely lower priority
	-- would still be queried in normal operation, which is not what someone
	-- means when they nominate a resolver of last resort.
	role       TEXT    NOT NULL DEFAULT 'primary'
	           CHECK (role IN ('primary', 'fallback')),

	-- Ordering within a role, for the panel. The resolver load-balances
	-- across primaries by response time, so this is presentation, not policy.
	position   INTEGER NOT NULL DEFAULT 0,

	enabled    INTEGER NOT NULL DEFAULT 1,
	note       TEXT    NOT NULL DEFAULT '',
	created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_upstreams_role ON upstreams (role, position);
