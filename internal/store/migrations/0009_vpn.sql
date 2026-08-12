-- Phase 5: WireGuard peers.
--
-- A peer is a device that carries the household's filtering with it. That is
-- the point of the feature: a phone on mobile data resolves through this node,
-- so the ad blocking and the malware filtering do not stop at the front door.
--
-- Each peer is also a client (see the clients table): it has a fixed address
-- inside the tunnel, which makes per-device policy work far better for a phone
-- than a LAN address ever could.

CREATE TABLE vpn_peers (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL,

    -- The peer's own public key. The private key is generated in the browser's
    -- download and never stored here: a server that holds every device's
    -- private key is a single theft away from impersonating all of them.
    public_key    TEXT    NOT NULL UNIQUE,

    -- Optional symmetric key layered on top of the handshake.
    preshared_key TEXT    NOT NULL DEFAULT '',

    -- The address allocated inside the tunnel, e.g. 10.6.0.4/32.
    address       TEXT    NOT NULL UNIQUE,

    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL,

    -- Reported by the kernel, refreshed while the interface is up.
    last_handshake INTEGER NOT NULL DEFAULT 0,
    rx_bytes       INTEGER NOT NULL DEFAULT 0,
    tx_bytes       INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX vpn_peers_enabled ON vpn_peers (enabled);
