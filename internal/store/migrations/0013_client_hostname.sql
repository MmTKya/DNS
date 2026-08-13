-- The name a device calls itself.
--
-- Separate from `name`, which is what the operator typed: a discovered
-- hostname must never overwrite a name someone chose, and someone who clears
-- their own name should fall back to the discovered one rather than to a bare
-- address.
ALTER TABLE clients ADD COLUMN hostname TEXT NOT NULL DEFAULT '';
