-- Phase 1: client identity.
--
-- A client is identified by one of three keys, tried from most to least
-- specific: a self-declared id (from a DoH path or DoT server name), an exact
-- address, or a subnet. The id matters most, because it is the only identity
-- that survives a device leaving the LAN — an address does not.
--
-- MAC-based identity arrives with DHCP in gateway mode (phase 3).

CREATE TABLE clients (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    key               TEXT    NOT NULL UNIQUE,
    key_type          TEXT    NOT NULL,
    name              TEXT    NOT NULL DEFAULT '',
    tags              TEXT    NOT NULL DEFAULT '',

    filtering_enabled INTEGER NOT NULL DEFAULT 1,

    -- Paused refuses this client's queries. In DNS-only mode that is content
    -- filtering, not a kill switch: the device keeps its network access and a
    -- hardcoded address or its own DoH walks straight around it. The panel
    -- says so rather than implying otherwise.
    paused            INTEGER NOT NULL DEFAULT 0,

    created_at        INTEGER NOT NULL,
    last_seen         INTEGER NOT NULL DEFAULT 0,
    query_count       INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX clients_key_type ON clients (key_type);
CREATE INDEX clients_last_seen ON clients (last_seen);
