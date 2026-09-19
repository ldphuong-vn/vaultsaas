DROP INDEX IF EXISTS idx_dynamic_leases_sweep;
ALTER TABLE dynamic_leases DROP COLUMN IF EXISTS backend_swept_at;
