-- Phase 3: hardware identity for clients.
--
-- The node is on the same segment as its clients, so it can learn their
-- hardware addresses from the kernel's neighbour table without any traffic
-- passing through it. That is what turns "192.168.1.74" in a device list into
-- "Samsung tablet", and it works in DNS-only mode.
--
-- The address is stored rather than looked up on every read because a device
-- that has gone quiet drops out of the neighbour table, and a name in the panel
-- should not disappear with it.

ALTER TABLE clients ADD COLUMN mac TEXT NOT NULL DEFAULT '';

-- Resolved from the IEEE registry at the time the address was seen, so the
-- panel does not pay for 40,000 binary searches to render a list.
ALTER TABLE clients ADD COLUMN vendor TEXT NOT NULL DEFAULT '';

CREATE INDEX clients_mac ON clients (mac);
