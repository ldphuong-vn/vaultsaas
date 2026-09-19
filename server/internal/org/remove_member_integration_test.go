package org

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/valt-dev/valt/server/internal/testutil"
)

const (
	removeOwnerID  = "00000000-0000-0000-0000-000000000b01"
	removeMemberID = "00000000-0000-0000-0000-000000000b02"
	removeAdminID  = "00000000-0000-0000-0000-000000000b03"
	removeOrgID    = "00000000-0000-0000-0000-000000000b04"
	removeWSID     = "00000000-0000-0000-0000-000000000b05"
	removeProjID   = "00000000-0000-0000-0000-000000000b06"
)

func newOrgIntegrationDB(t *testing.T, ctx context.Context) (*pgxpool.Pool, func()) {
	t.Helper()
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL is required for org integration tests")
	}

	schemaName := fmt.Sprintf("it_org_%d_%d", time.Now().UnixNano(), rand.Intn(100000))
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

func seedRemoveMemberData(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	stmts := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)`, []any{removeOwnerID, "org-owner@example.com", "hash"}},
		{`INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)`, []any{removeMemberID, "org-member@example.com", "hash"}},
		{`INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)`, []any{removeAdminID, "org-admin@example.com", "hash"}},
		{`INSERT INTO organizations (id, name, slug, owner_id, plan) VALUES ($1, $2, $3, $4, $5)`, []any{removeOrgID, "Org", "org-remove", removeOwnerID, "free"}},
		{`INSERT INTO org_memberships (org_id, user_id, role) VALUES ($1, $2, $3)`, []any{removeOrgID, removeOwnerID, "owner"}},
		{`INSERT INTO org_memberships (org_id, user_id, role) VALUES ($1, $2, $3)`, []any{removeOrgID, removeMemberID, "member"}},
		{`INSERT INTO org_memberships (org_id, user_id, role) VALUES ($1, $2, $3)`, []any{removeOrgID, removeAdminID, "admin"}},
		{`INSERT INTO workspaces (id, org_id, name, slug) VALUES ($1, $2, $3, $4)`, []any{removeWSID, removeOrgID, "WS", "ws-remove"}},
		{`INSERT INTO projects (id, workspace_id, name, slug) VALUES ($1, $2, $3, $4)`, []any{removeProjID, removeWSID, "Project", "proj-remove"}},
		// The member has a project membership inside the org — must cascade away.
		{`INSERT INTO project_memberships (project_id, user_id, role) VALUES ($1, $2, $3)`, []any{removeProjID, removeMemberID, "member"}},
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s.query, s.args...); err != nil {
			t.Fatalf("seed statement failed: %v\nquery=%s", err, s.query)
		}
	}
}

func membershipCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, query string, args ...any) int {
	t.Helper()
	var cnt int
	if err := pool.QueryRow(ctx, query, args...).Scan(&cnt); err != nil {
		t.Fatalf("count query: %v", err)
	}
	return cnt
}

// TestRemoveMemberCascades: an org admin removes a member; the org membership
// and the member's project memberships inside the org are gone.
func TestRemoveMemberCascades(t *testing.T) {
	ctx := context.Background()
	pool, cleanup := newOrgIntegrationDB(t, ctx)
	defer cleanup()
	seedRemoveMemberData(t, ctx, pool)

	svc := NewService(pool)
	if err := svc.RemoveMember(ctx, removeOrgID, removeMemberID); err != nil {
		t.Fatalf("remove member: %v", err)
	}

	if got := membershipCount(t, ctx, pool,
		`SELECT COUNT(*) FROM org_memberships WHERE org_id = $1 AND user_id = $2`, removeOrgID, removeMemberID); got != 0 {
		t.Fatalf("org membership must be gone, got %d", got)
	}
	if got := membershipCount(t, ctx, pool,
		`SELECT COUNT(*) FROM project_memberships WHERE project_id = $1 AND user_id = $2`, removeProjID, removeMemberID); got != 0 {
		t.Fatalf("project membership must cascade away, got %d", got)
	}
	// Non-members stay untouched.
	if got := membershipCount(t, ctx, pool,
		`SELECT COUNT(*) FROM org_memberships WHERE org_id = $1`, removeOrgID); got != 2 {
		t.Fatalf("owner+admin must remain, got %d", got)
	}

	// Removing again reports the member is not there.
	if err := svc.RemoveMember(ctx, removeOrgID, removeMemberID); err != ErrMemberNotFound {
		t.Fatalf("second removal must be ErrMemberNotFound, got %v", err)
	}
}

// TestRemoveMemberGuards: the org owner cannot be removed, unknown orgs are
// reported, and (per the handler contract) only admins/owners get this far.
func TestRemoveMemberGuards(t *testing.T) {
	ctx := context.Background()
	pool, cleanup := newOrgIntegrationDB(t, ctx)
	defer cleanup()
	seedRemoveMemberData(t, ctx, pool)

	svc := NewService(pool)

	if err := svc.RemoveMember(ctx, removeOrgID, removeOwnerID); err != ErrRemoveOwner {
		t.Fatalf("removing the owner must be refused, got %v", err)
	}
	if err := svc.RemoveMember(ctx, "00000000-0000-0000-0000-000000000bff", removeMemberID); err != ErrOrgNotFound {
		t.Fatalf("unknown org must be reported, got %v", err)
	}

	// Authorization helper: plain member is not allowed to remove.
	ok, err := callerIsAdminOrOwner(ctx, svc, removeOrgID, removeMemberID)
	if err != nil || ok {
		t.Fatalf("plain member must not pass callerIsAdminOrOwner, got %v (%v)", ok, err)
	}
	if ok, _ := callerIsAdminOrOwner(ctx, svc, removeOrgID, removeAdminID); !ok {
		t.Fatal("org admin must pass callerIsAdminOrOwner")
	}
}
