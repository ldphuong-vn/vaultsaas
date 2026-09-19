-- Weeks 9-10: revoke cascade + backend sweeper.
-- backend_swept_at marks leases whose backend credential (e.g. a Postgres
-- temp role) has been dropped by the sweeper. NULL = not yet swept, so the
-- sweeper query is idempotent and resumable across restarts.

ALTER TABLE dynamic_leases ADD COLUMN backend_swept_at TIMESTAMPTZ;
CREATE INDEX idx_dynamic_leases_sweep
    ON dynamic_leases(expires_at)
    WHERE backend_swept_at IS NULL;
