package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/valt-dev/valt/server/internal/agent"
	"github.com/valt-dev/valt/server/internal/audit"
	"github.com/valt-dev/valt/server/internal/auth"
	"github.com/valt-dev/valt/server/internal/dynsecret"
	"github.com/valt-dev/valt/server/internal/vault"
)

const (
	revokeAdminID  = "00000000-0000-0000-0000-000000000701"
	revokeAgentA   = "00000000-0000-0000-0000-000000000702"
	revokeAgentB   = "00000000-0000-0000-0000-000000000703"
	revokeSecretID = "00000000-0000-0000-0000-000000000704"
)

func hashToken(t *testing.T, plain string) string {
	t.Helper()
	h := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(h[:])
}

// seedRevokeAllData seeds the full revoke-all scenario on top of
// seedWorkflowPolicyData: an admin, the target user's agent + the control
// agent, agent tokens, a derived provider linked to the project secret, and
// one extra static (unlinked) secret.
func seedRevokeAllData(t *testing.T, ctx context.Context, pool *pgxpool.Pool, dynSvc *dynsecret.Service) {
	t.Helper()

	stmts := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO users (id, email, password_hash, role) VALUES ($1, $2, $3, 'admin')`,
			[]any{revokeAdminID, "admin-revoke@example.com", "hash"}},
		{`INSERT INTO agent_identities (id, project_id, name, created_by) VALUES ($1, $2, 'agent-A', $3)`,
			[]any{revokeAgentA, projectID, requesterID}},
		{`INSERT INTO agent_identities (id, project_id, name, created_by) VALUES ($1, $2, 'agent-B', $3)`,
			[]any{revokeAgentB, projectID, ownerID}},
		{`INSERT INTO agent_tokens (agent_id, token_hash) VALUES ($1, $2)`,
			[]any{revokeAgentA, hashToken(t, "plain-token-a1")}},
		{`INSERT INTO agent_tokens (agent_id, token_hash) VALUES ($1, $2)`,
			[]any{revokeAgentA, hashToken(t, "plain-token-a2")}},
		{`INSERT INTO agent_tokens (agent_id, token_hash) VALUES ($1, $2)`,
			[]any{revokeAgentB, hashToken(t, "plain-token-b1")}},
		{`INSERT INTO secrets (id, user_id, name, description, storage_key, encrypted_dek, policy, credential_type, source, version, project_id)
		  VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11)`,
			[]any{revokeSecretID, ownerID, "static-secret", "", "k2", []byte{1, 2, 3}, `{}`, "api_key", "", 1, projectID}},
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s.query, s.args...); err != nil {
			t.Fatalf("seed statement failed: %v\nquery=%s", err, s.query)
		}
	}

	// Derived provider linked to the project secret.
	pc, err := dynSvc.CreateProvider(ctx, projectID, "revoke-provider", "derived_api_key",
		map[string]string{"master_key": newTestMasterKeyString(t)}, ownerID)
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	vaultSvc := vault.NewService(pool, nil)
	if _, err := vaultSvc.SetDynamicProvider(ctx, secretID, ownerID, &pc.ID); err != nil {
		t.Fatalf("link secret to provider: %v", err)
	}
}

// TestRevokeAllForUser covers the weeks 9-10 deliverable: one command kills
// every credential granted to a user, and only that user's.
func TestRevokeAllForUser(t *testing.T) {
	ctx := context.Background()
	pool, dynSvc, credMgr, issuer, cleanup := newLeaseE2EStack(t, ctx)
	defer cleanup()
	seedWorkflowPolicyData(t, ctx, pool)
	seedRevokeAllData(t, ctx, pool, dynSvc)

	wfSvc := NewService(pool, false)

	// --- Provision credentials for target (requesterID) and control (ownerID).
	issue := func(secretID, requesterUserID, agentID string) (*dynsecret.LeaseInfo, *CredentialSession) {
		requesterType := "human"
		if agentID != "" {
			requesterType = "ai_agent"
		}
		req, err := wfSvc.CreateRequest(ctx, CreateRequestInput{
			SecretID:        secretID,
			RequesterUserID: requesterUserID,
			RequesterType:   requesterType,
			AIAgentID:       agentID,
			Reason:          "revoke-all e2e",
			DurationMinutes: 30,
			CredentialType:  "api_key",
		})
		if err != nil {
			t.Fatalf("create request: %v", err)
		}
		secret, err := vault.NewService(pool, nil).GetSecretByID(ctx, secretID)
		if err != nil || secret == nil {
			t.Fatalf("get secret: %v", err)
		}
		session, err := issuer.IssueForRequest(ctx, req, secret)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		var lease *dynsecret.LeaseInfo
		if session.LeaseID != nil {
			lease, err = dynSvc.GetActiveLease(ctx, *session.LeaseID)
			if err != nil || lease == nil {
				t.Fatalf("active lease lookup: %v", err)
			}
		}
		return lease, session
	}

	leaseTargetHuman, sessionTargetHuman := issue(secretID, requesterID, "")         // L1 + S1
	leaseTargetAgent, sessionTargetAgent := issue(secretID, "", revokeAgentA)        // L2 + S2
	leaseControlAgent, sessionControlAgent := issue(secretID, ownerID, revokeAgentB) // L3 + S3
	_, sessionTargetStatic := issue(revokeSecretID, requesterID, "")                 // S4 (static)
	_, sessionControlStatic := issue(revokeSecretID, ownerID, "")                    // S5 (static)

	// Sanity: everything alive before the cascade.
	if leaseTargetHuman == nil || leaseTargetAgent == nil || leaseControlAgent == nil {
		t.Fatal("lease-backed sessions must carry active leases")
	}

	revokeSvc := NewRevokeService(pool, dynSvc, credMgr, audit.NewLogger(pool))
	summary, err := revokeSvc.RevokeAllForUser(ctx, requesterID, revokeAdminID)
	if err != nil {
		t.Fatalf("revoke-all: %v", err)
	}
	if summary.LeasesRevoked != 2 {
		t.Fatalf("expected 2 leases revoked, got %+v", summary)
	}
	if summary.SessionsRevoked != 3 { // S1, S2, S4
		t.Fatalf("expected 3 sessions revoked, got %+v", summary)
	}
	if summary.TokensRevoked != 2 || summary.AgentsDisabled != 1 {
		t.Fatalf("expected 2 tokens + 1 agent disabled, got %+v", summary)
	}

	// Target's leases dead, control alive.
	assertLeaseDead(t, ctx, dynSvc, leaseTargetHuman.ID)
	assertLeaseDead(t, ctx, dynSvc, leaseTargetAgent.ID)
	assertLeaseAlive(t, ctx, dynSvc, leaseControlAgent.ID)

	// Target's sessions dead (dynamic and static), control alive.
	for name, s := range map[string]*CredentialSession{
		"target human":   sessionTargetHuman,
		"target agent":   sessionTargetAgent,
		"target static":  sessionTargetStatic,
	} {
		if _, err := credMgr.GetCredential(ctx, s.AccessRequestID); err == nil {
			t.Fatalf("%s session must be dead after revoke-all", name)
		}
	}
	if _, err := credMgr.GetCredential(ctx, sessionControlAgent.AccessRequestID); err != nil {
		t.Fatalf("control agent session must survive: %v", err)
	}
	if _, err := credMgr.GetCredential(ctx, sessionControlStatic.AccessRequestID); err != nil {
		t.Fatalf("control static session must survive: %v", err)
	}

	// Target's agent tokens revoked; identity disabled. Control untouched.
	agentSvc := agent.NewService(pool)
	if tok, _ := agentSvc.ValidateToken(ctx, "plain-token-a1"); tok != nil {
		t.Fatal("agent A token must be revoked")
	}
	if tok, _ := agentSvc.ValidateToken(ctx, "plain-token-a2"); tok != nil {
		t.Fatal("agent A token #2 must be revoked")
	}
	if tok, _ := agentSvc.ValidateToken(ctx, "plain-token-b1"); tok == nil {
		t.Fatal("agent B token must survive")
	}
	var statusA, statusB string
	_ = pool.QueryRow(ctx, `SELECT status FROM agent_identities WHERE id = $1`, revokeAgentA).Scan(&statusA)
	_ = pool.QueryRow(ctx, `SELECT status FROM agent_identities WHERE id = $1`, revokeAgentB).Scan(&statusB)
	if statusA != "disabled" {
		t.Fatalf("agent A must be disabled, got %q", statusA)
	}
	if statusB != "active" {
		t.Fatalf("agent B must stay active, got %q", statusB)
	}

	// Access requests of the target (and their agents) are marked revoked.
	var pending int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM access_requests
		WHERE status IN ('approved', 'active')
		  AND (requester_user_id = $1 OR ai_agent_id = $2)`,
		requesterID, revokeAgentA,
	).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("target access requests must be revoked: %d (%v)", pending, err)
	}
}

func assertLeaseDead(t *testing.T, ctx context.Context, dynSvc *dynsecret.Service, leaseID string) {
	t.Helper()
	if got, err := dynSvc.GetActiveLease(ctx, leaseID); err != nil || got != nil {
		t.Fatalf("lease %s must be inactive: %v (%v)", leaseID, got, err)
	}
}

func assertLeaseAlive(t *testing.T, ctx context.Context, dynSvc *dynsecret.Service, leaseID string) {
	t.Helper()
	if got, err := dynSvc.GetActiveLease(ctx, leaseID); err != nil || got == nil {
		t.Fatalf("lease %s must stay active: %v (%v)", leaseID, got, err)
	}
}

// TestRevokeAllHandlerAuthz exercises the HTTP authorization matrix of
// POST /users/{user_id}/revoke-all: admin or self may call it, others may not.
func TestRevokeAllHandlerAuthz(t *testing.T) {
	ctx := context.Background()
	pool, dynSvc, _, _, cleanup := newLeaseE2EStack(t, ctx)
	defer cleanup()
	seedWorkflowPolicyData(t, ctx, pool)

	// Admin user (seedWorkflowPolicyData users default to role 'user').
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, email, password_hash, role) VALUES ($1, $2, $3, 'admin')`,
		revokeAdminID, "admin-authz@example.com", "hash"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}

	revokeSvc := NewRevokeService(pool, dynSvc, nil, nil)
	r := chi.NewRouter()
	r.Post("/api/v1/users/{user_id}/revoke-all", revokeSvc.HandleRevokeAllForUser)

	cases := []struct {
		name     string
		callerID string
		targetID string
		want     int
	}{
		{"self may revoke own credentials", requesterID, requesterID, http.StatusOK},
		{"admin may revoke anyone", revokeAdminID, requesterID, http.StatusOK},
		{"non-admin other is forbidden", ownerID, requesterID, http.StatusForbidden},
		{"unknown target is 404", revokeAdminID, "00000000-0000-0000-0000-0000000007ff", http.StatusNotFound},
		{"unauthenticated is 401", "", requesterID, http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{})
			req := httptest.NewRequest(http.MethodPost,
				fmt.Sprintf("/api/v1/users/%s/revoke-all", tc.targetID), strings.NewReader(string(body)))
			if tc.callerID != "" {
				req = req.WithContext(auth.WithUserID(req.Context(), tc.callerID))
			}
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}
