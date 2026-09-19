-- Weeks 5-8: wire approval workflow to dynamic leases + derived API key provider.
-- 1) key_hash on dynamic_leases lets a derived key be looked up without storing
--    the raw key (HMAC is one-way, hash enables O(1) validation lookups).
-- 2) secrets.dynamic_provider_id links a secret to the dynamic provider that
--    backs it; approval then mints a short-lived lease instead of returning the
--    static secret value.
-- 3) credential_sessions.lease_id ties the uniform session record to its lease.

ALTER TABLE dynamic_leases ADD COLUMN key_hash TEXT;
CREATE INDEX idx_dynamic_leases_key_hash ON dynamic_leases(key_hash) WHERE key_hash IS NOT NULL;

ALTER TABLE secrets ADD COLUMN dynamic_provider_id UUID REFERENCES dynamic_providers(id);

ALTER TABLE credential_sessions ADD COLUMN lease_id UUID REFERENCES dynamic_leases(id);
