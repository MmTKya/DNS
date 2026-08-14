-- Per-device speed limits.
--
-- Stored regardless of mode, applied only in gateway mode: a limit is enforced
-- by holding packets back, and a node that only answers questions about names
-- never touches them. Keeping the setting either way means someone can decide
-- what the limits should be before the machine can enforce them, and means the
-- decision survives the switch.
CREATE TABLE device_limits (
	client_key    TEXT PRIMARY KEY,

	-- Kilobits per second. Zero leaves that direction alone.
	download_kbps INTEGER NOT NULL DEFAULT 0,
	upload_kbps   INTEGER NOT NULL DEFAULT 0,

	enabled       INTEGER NOT NULL DEFAULT 1,
	updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);
