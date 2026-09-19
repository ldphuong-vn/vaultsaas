ALTER TABLE credential_sessions DROP COLUMN IF EXISTS lease_id;
ALTER TABLE secrets DROP COLUMN IF EXISTS dynamic_provider_id;
DROP INDEX IF EXISTS idx_dynamic_leases_key_hash;
ALTER TABLE dynamic_leases DROP COLUMN IF EXISTS key_hash;
