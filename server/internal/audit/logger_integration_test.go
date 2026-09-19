package audit

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/valt-dev/valt/server/internal/database"
	"github.com/valt-dev/valt/server/internal/testutil"
)

// newAuditIntegrationDB provisions an isolated schema with all migrations
// applied. Skipped unless DATABASE_URL is set (see Makefile test-integration).
func newAuditIntegrationDB(t *testing.T, ctx context.Context) (*pgxpool.Pool, func()) {
	t.Helper()
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL is required for audit integration tests")
	}

	schemaName := fmt.Sprintf("it_audit_%d_%d", time.Now().UnixNano(), rand.Intn(100000))
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

	if err := applyAuditMigrations(ctx, pool); err != nil {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), fmt.Sprintf("DROP SCHEMA %s CASCADE", schemaName))
		adminPool.Close()
		t.Fatalf("apply migrations failed: %v", err)
	}
	database.EnsurePartitions(ctx, pool)

	cleanup := func() {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), fmt.Sprintf("DROP SCHEMA %s CASCADE", schemaName))
		adminPool.Close()
	}
	return pool, cleanup
}

func applyAuditMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	return testutil.ApplyMigrations(ctx, pool)
}

func fetchAllBySeq(ctx context.Context, t *testing.T, pool *pgxpool.Pool) []Entry {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT id, seq, event_time, user_id, action, resource_type, resource_id,
	                                      event_type, status, ip_address::TEXT, user_agent, region_code, metadata, hash_prev
	                               FROM audit_logs ORDER BY seq ASC`)
	if err != nil {
		t.Fatalf("fetch audit logs: %v", err)
	}
	defer rows.Close()

	var out []Entry
	for rows.Next() {
		var e Entry
		var userID, resourceID, ip, ua, region, hashPrev *string
		if err := rows.Scan(&e.ID, &e.Seq, &e.EventTime, &userID, &e.Action, &e.ResourceType, &resourceID,
			&e.EventType, &e.Status, &ip, &ua, &region, &e.Metadata, &hashPrev); err != nil {
			t.Fatalf("scan audit log: %v", err)
		}
		if userID != nil {
			e.UserID = *userID
		}
		if resourceID != nil {
			e.ResourceID = *resourceID
		}
		if ip != nil {
			e.IPAddress = *ip
		}
		if ua != nil {
			e.UserAgent = *ua
		}
		if region != nil {
			e.RegionCode = *region
		}
		if hashPrev != nil {
			e.HashPrev = *hashPrev
		}
		out = append(out, e)
	}
	return out
}

// Regression for bug 2: the chain head used to live only in Logger memory, so a
// server restart forked the chain. A fresh Logger must continue the chain that
// is persisted in the database.
func TestChainSurvivesLoggerRestart(t *testing.T) {
	ctx := context.Background()
	pool, cleanup := newAuditIntegrationDB(t, ctx)
	defer cleanup()

	loggerA := NewLogger(pool)
	for i := 0; i < 2; i++ {
		if _, err := loggerA.Log(ctx, Entry{UserID: "00000000-0000-0000-0000-000000000001", Action: fmt.Sprintf("step-%d", i), ResourceType: "test"}); err != nil {
			t.Fatalf("loggerA log: %v", err)
		}
	}

	// Simulate a restart: brand-new Logger with empty in-memory state.
	loggerB := NewLogger(pool)
	if _, err := loggerB.Log(ctx, Entry{UserID: "00000000-0000-0000-0000-000000000001", Action: "after-restart", ResourceType: "test"}); err != nil {
		t.Fatalf("loggerB log: %v", err)
	}

	entries := fetchAllBySeq(ctx, t, pool)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	for i, e := range entries {
		if e.Seq != int64(i+1) {
			t.Errorf("entry %d has seq %d, want %d", i, e.Seq, i+1)
		}
	}
	if ok, idx := VerifyChain(entries); !ok {
		t.Errorf("chain must verify across restart, broke at index %d", idx)
	}
}

// Concurrent writers must extend one chain with contiguous, unique seqs — the
// FOR UPDATE protocol on audit_chain_state serializes them.
func TestChainConcurrentWriters(t *testing.T) {
	ctx := context.Background()
	pool, cleanup := newAuditIntegrationDB(t, ctx)
	defer cleanup()

	logger := NewLogger(pool)
	const goroutines, perGoroutine = 8, 5

	var wg sync.WaitGroup
	errs := make(chan error, goroutines*perGoroutine)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				if _, err := logger.Log(ctx, Entry{
					UserID:       "00000000-0000-0000-0000-000000000002",
					Action:       fmt.Sprintf("g%d-i%d", g, i),
					ResourceType: "test",
				}); err != nil {
					errs <- err
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent log: %v", err)
	}

	entries := fetchAllBySeq(ctx, t, pool)
	if len(entries) != goroutines*perGoroutine {
		t.Fatalf("expected %d entries, got %d", goroutines*perGoroutine, len(entries))
	}
	for i, e := range entries {
		if e.Seq != int64(i+1) {
			t.Fatalf("seq gap/duplicate at position %d: seq=%d", i, e.Seq)
		}
	}
	if ok, idx := VerifyChain(entries); !ok {
		t.Errorf("chain must verify after concurrent writes, broke at index %d", idx)
	}
}

// Tampering directly with a database row (simulating a DBA edit) must break
// verification at that row.
func TestChainDetectsDBTampering(t *testing.T) {
	ctx := context.Background()
	pool, cleanup := newAuditIntegrationDB(t, ctx)
	defer cleanup()

	logger := NewLogger(pool)
	for i := 0; i < 3; i++ {
		if _, err := logger.Log(ctx, Entry{
			UserID:       "00000000-0000-0000-0000-000000000001",
			Action:       fmt.Sprintf("op-%d", i),
			ResourceType: "secret",
			ResourceID:   "00000000-0000-0000-0000-0000000000aa",
			IPAddress:    "10.0.0.1",
			Metadata:     `{"op":"read"}`,
		}); err != nil {
			t.Fatalf("log: %v", err)
		}
	}

	if _, err := pool.Exec(ctx, `UPDATE audit_logs SET ip_address = '203.0.113.9' WHERE seq = 2`); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	entries := fetchAllBySeq(ctx, t, pool)
	if ok, idx := VerifyChain(entries); ok || idx != 1 {
		t.Errorf("tampered row (seq=2, index=1) must break the chain, got ok=%v idx=%d", ok, idx)
	}
}
