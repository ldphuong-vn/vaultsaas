package dynsecret

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/valt-dev/valt/server/internal/testutil"
	"github.com/valt-dev/valt/server/pkg/crypto"
)

func newDynsecretIntegrationDB(t *testing.T, ctx context.Context) (*pgxpool.Pool, func()) {
	t.Helper()
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL is required for dynsecret integration tests")
	}

	schemaName := fmt.Sprintf("it_dynsecret_%d_%d", time.Now().UnixNano(), rand.Intn(100000))
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("create admin pool failed: %v", err)
	}
	if _, err := adminPool.Exec(ctx, fmt.Sprintf("CREATE SCHEMA %s", schemaName)); err != nil {
		adminPool.Close()
		t.Skipf("cannot create test schema (need CREATE privilege): %v", err)
	}

	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		adminPool.Close()
		t.Fatalf("parse database url failed: %v", err)
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schemaName
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		adminPool.Close()
		t.Fatalf("create schema pool failed: %v", err)
	}

	if err := testutil.ApplyMigrations(ctx, pool); err != nil {
		pool.Close()
		_, _ = adminPool.Exec(ctx, fmt.Sprintf("DROP SCHEMA %s CASCADE", schemaName))
		adminPool.Close()
		t.Fatalf("apply migrations failed: %v", err)
	}

	cleanup := func() {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), fmt.Sprintf("DROP SCHEMA %s CASCADE", schemaName))
		adminPool.Close()
	}
	return pool, cleanup
}

// seedSweepProjectChain seeds user → org → workspace → project so provider
// rows (NOT NULL FKs) can be inserted, returning the project ID.
func seedSweepProjectChain(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (userID, projectID string) {
	t.Helper()
	userID = "00000000-0000-0000-0000-000000000a01"
	orgID := "00000000-0000-0000-0000-000000000a02"
	wsID := "00000000-0000-0000-0000-000000000a03"
	projectID = "00000000-0000-0000-0000-000000000a04"

	stmts := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)`, []any{userID, "sweep@example.com", "hash"}},
		{`INSERT INTO organizations (id, name, slug, owner_id, plan) VALUES ($1, $2, $3, $4, $5)`, []any{orgID, "Org", "org-sweep", userID, "free"}},
		{`INSERT INTO workspaces (id, org_id, name, slug) VALUES ($1, $2, $3, $4)`, []any{wsID, orgID, "WS", "ws-sweep"}},
		{`INSERT INTO projects (id, workspace_id, name, slug) VALUES ($1, $2, $3, $4)`, []any{projectID, wsID, "Project", "proj-sweep"}},
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s.query, s.args...); err != nil {
			t.Fatalf("seed statement failed: %v\nquery=%s", err, s.query)
		}
	}
	return userID, projectID
}

// seedSweepProvider inserts a provider row (config encrypted like
// CreateProvider does) and returns its ID.
func seedSweepProvider(t *testing.T, ctx context.Context, pool *pgxpool.Pool, masterKey []byte, userID, projectID, providerType string, config map[string]string) string {
	t.Helper()
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal provider config: %v", err)
	}
	enc, err := crypto.EncryptAES256GCM(masterKey, raw)
	if err != nil {
		t.Fatalf("encrypt provider config: %v", err)
	}
	var id string
	if err := pool.QueryRow(ctx, `
		INSERT INTO dynamic_providers (project_id, name, provider_type, config_enc, created_by)
		VALUES ($1, 'sweep-test', $2, $3, $4) RETURNING id`,
		projectID, providerType, enc, userID,
	).Scan(&id); err != nil {
		t.Fatalf("insert provider: %v", err)
	}
	return id
}

// seedSweepLease inserts a lease row directly with a chosen expiry.
func seedSweepLease(t *testing.T, ctx context.Context, pool *pgxpool.Pool, masterKey []byte, providerID string, creds map[string]string, expiresAt time.Time) string {
	t.Helper()
	raw, err := json.Marshal(creds)
	if err != nil {
		t.Fatalf("marshal lease creds: %v", err)
	}
	enc, err := crypto.EncryptAES256GCM(masterKey, raw)
	if err != nil {
		t.Fatalf("encrypt lease creds: %v", err)
	}
	var id string
	if err := pool.QueryRow(ctx, `
		INSERT INTO dynamic_leases (provider_id, secret_data_enc, ttl_seconds, expires_at)
		VALUES ($1, $2, 60, $3) RETURNING id`,
		providerID, enc, expiresAt,
	).Scan(&id); err != nil {
		t.Fatalf("insert lease: %v", err)
	}
	return id
}

// roleExists checks pg_roles on the connected test instance.
func roleExists(t *testing.T, ctx context.Context, pool *pgxpool.Pool, role string) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)`, role).Scan(&exists); err != nil {
		t.Fatalf("check role exists: %v", err)
	}
	return exists
}

// sweptAt returns backend_swept_at for a lease (nil = not swept).
func sweptAt(t *testing.T, ctx context.Context, pool *pgxpool.Pool, leaseID string) *time.Time {
	t.Helper()
	var ts *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT backend_swept_at FROM dynamic_leases WHERE id = $1`, leaseID,
	).Scan(&ts); err != nil {
		t.Fatalf("read backend_swept_at: %v", err)
	}
	return ts
}

// TestSweeperDropsPostgresRole: an expired postgres-provider lease gets its
// temp role dropped and marked swept — the leftover-forever role problem from
// refactor-plan §A is gone.
func TestSweeperDropsPostgresRole(t *testing.T) {
	ctx := context.Background()
	pool, cleanup := newDynsecretIntegrationDB(t, ctx)
	defer cleanup()
	userID, projectID := seedSweepProjectChain(t, ctx, pool)

	masterKey := []byte("0123456789abcdef0123456789abcdef")
	// The test database itself is the backend: same instance, same pg_roles.
	providerID := seedSweepProvider(t, ctx, pool, masterKey, userID, projectID, "postgres", map[string]string{
		"host": "localhost", "port": "15432", "database": "postgres",
		"admin_user": "postgres", "admin_password": "", "ssl_mode": "disable",
	})

	prov := &PostgresProvider{config: ProviderConfig{ID: providerID, ProviderType: "postgres", Config: map[string]string{
		"host": "localhost", "port": "15432", "database": "postgres",
		"admin_user": "postgres", "admin_password": "", "ssl_mode": "disable",
	}}}
	lease, err := prov.Create(ctx, LeaseRequest{TTL: time.Hour})
	if err != nil {
		t.Fatalf("create temp role on test instance: %v", err)
	}
	username := lease.Credentials["username"]
	if !roleExists(t, ctx, pool, username) {
		t.Fatalf("temp role %s must exist before sweeping", username)
	}

	leaseID := seedSweepLease(t, ctx, pool, masterKey, providerID, lease.Credentials, time.Now().Add(-10*time.Minute))

	svc := NewService(pool, masterKey)
	swept, err := svc.SweepExpiredBackends(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if swept != 1 {
		t.Fatalf("expected 1 swept lease, got %d", swept)
	}
	if roleExists(t, ctx, pool, username) {
		t.Fatalf("temp role %s must be dropped by the sweeper", username)
	}
	if sweptAt(t, ctx, pool, leaseID) == nil {
		t.Fatal("lease must be marked swept")
	}

	// Idempotent: a second pass finds nothing.
	if swept2, err := svc.SweepExpiredBackends(ctx); err != nil || swept2 != 0 {
		t.Fatalf("second sweep must be a no-op, got %d (%v)", swept2, err)
	}
}

// TestSweeperMarksDerivedLeases: derived API key leases have no backend
// object — the sweeper only marks them.
func TestSweeperMarksDerivedLeases(t *testing.T) {
	ctx := context.Background()
	pool, cleanup := newDynsecretIntegrationDB(t, ctx)
	defer cleanup()
	userID, projectID := seedSweepProjectChain(t, ctx, pool)

	masterKey := []byte("0123456789abcdef0123456789abcdef")
	providerID := seedSweepProvider(t, ctx, pool, masterKey, userID, projectID, "derived_api_key", map[string]string{
		"master_key": "sk-x", "upstream": "api.example.com",
	})
	leaseID := seedSweepLease(t, ctx, pool, masterKey, providerID,
		map[string]string{"api_key": "valt_dk_test"}, time.Now().Add(-10*time.Minute))

	svc := NewService(pool, masterKey)
	swept, err := svc.SweepExpiredBackends(ctx)
	if err != nil || swept != 1 {
		t.Fatalf("sweep: %d (%v)", swept, err)
	}
	if sweptAt(t, ctx, pool, leaseID) == nil {
		t.Fatal("derived lease must be marked swept")
	}
}

// TestSweeperRespectsGrace: leases inside the grace window are untouched.
func TestSweeperRespectsGrace(t *testing.T) {
	ctx := context.Background()
	pool, cleanup := newDynsecretIntegrationDB(t, ctx)
	defer cleanup()
	userID, projectID := seedSweepProjectChain(t, ctx, pool)

	masterKey := []byte("0123456789abcdef0123456789abcdef")
	providerID := seedSweepProvider(t, ctx, pool, masterKey, userID, projectID, "derived_api_key", map[string]string{
		"master_key": "sk-x",
	})
	// Expired 1 minute ago — within the 5-minute sweep grace.
	leaseID := seedSweepLease(t, ctx, pool, masterKey, providerID,
		map[string]string{"api_key": "valt_dk_fresh"}, time.Now().Add(-1*time.Minute))

	svc := NewService(pool, masterKey)
	swept, err := svc.SweepExpiredBackends(ctx)
	if err != nil || swept != 0 {
		t.Fatalf("grace-window lease must not be swept, got %d (%v)", swept, err)
	}
	if sweptAt(t, ctx, pool, leaseID) != nil {
		t.Fatal("grace-window lease must not be marked swept")
	}
}
