package workflow

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/valt-dev/valt/server/internal/audit"
	"github.com/valt-dev/valt/server/internal/database"
	"github.com/valt-dev/valt/server/internal/dynsecret"
	"github.com/valt-dev/valt/server/internal/vault"
)

const (
	leaseAgentID  = "00000000-0000-0000-0000-000000000601"
	leaseProvider = "00000000-0000-0000-0000-000000000602"
	testMasterKey = "0123456789abcdef0123456789abcdef"
)

// seedLeaseE2EData seeds an agent identity and a derived_api_key provider,
// then links the existing project secret (from seedWorkflowPolicyData) to it.
// Returns the linked vault secret as seen by the approval path.
func seedLeaseE2EData(t *testing.T, ctx context.Context, pool *pgxpool.Pool, dynSvc *dynsecret.Service) *vault.Secret {
	t.Helper()

	_, err := pool.Exec(ctx, `
		INSERT INTO agent_identities (id, project_id, name, created_by)
		VALUES ($1, $2, 'e2e-agent', $3)`,
		leaseAgentID, projectID, ownerID)
	if err != nil {
		t.Fatalf("seed agent identity: %v", err)
	}

	pc, err := dynSvc.CreateProvider(ctx, projectID, "ai-provider", "derived_api_key",
		map[string]string{"master_key": "sk-company-ai-master", "upstream": "api.openai.com"}, ownerID)
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}

	vaultSvc := vault.NewService(pool, nil)
	if _, err := vaultSvc.SetDynamicProvider(ctx, secretID, ownerID, &pc.ID); err != nil {
		t.Fatalf("link secret to provider: %v", err)
	}

	secret, err := vaultSvc.GetSecretByID(ctx, secretID)
	if err != nil || secret == nil {
		t.Fatalf("get secret after link: %v (secret=%v)", err, secret)
	}
	if secret.DynamicProviderID == nil || *secret.DynamicProviderID != pc.ID {
		t.Fatalf("secret must carry the provider link, got %v", secret.DynamicProviderID)
	}
	return secret
}

func newLeaseE2EStack(t *testing.T, ctx context.Context) (*pgxpool.Pool, *dynsecret.Service, *CredentialManager, *LeaseIssuer, func()) {
	t.Helper()
	pool, cleanup := newWorkflowIntegrationDB(t, ctx)
	database.EnsurePartitions(ctx, pool)

	dynSvc := dynsecret.NewService(pool, []byte(testMasterKey))
	credMgr := NewCredentialManager(pool, dynSvc)
	issuer := NewLeaseIssuer(credMgr, dynSvc, audit.NewLogger(pool))
	return pool, dynSvc, credMgr, issuer, cleanup
}

// TestLeaseIssuerEndToEnd covers the weeks 5-8 deliverable:
// agent xin → duyệt → nhận lease TTL ngắn → dùng key → revoke.
func TestLeaseIssuerEndToEnd(t *testing.T) {
	ctx := context.Background()
	pool, dynSvc, credMgr, issuer, cleanup := newLeaseE2EStack(t, ctx)
	defer cleanup()
	seedWorkflowPolicyData(t, ctx, pool)
	secret := seedLeaseE2EData(t, ctx, pool, dynSvc)

	wfSvc := NewService(pool, false)

	// 1. Agent requests access to the provider-backed secret.
	created, err := wfSvc.CreateRequest(ctx, CreateRequestInput{
		SecretID:        secretID,
		RequesterType:   "ai_agent",
		AIAgentID:       leaseAgentID,
		Reason:          "generate release notes",
		DurationMinutes: 30,
		CredentialType:  secret.CredentialType,
	})
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	// 2. Approval (auto-approved under TierLow api_key policy; mirror the
	// handler auto-approve branch by issuing right after CreateRequest).
	session, err := issuer.IssueForRequest(ctx, created, secret)
	if err != nil {
		t.Fatalf("issue for request: %v", err)
	}
	if session.LeaseID == nil {
		t.Fatal("session must be lease-backed for a provider-linked secret")
	}

	lease, err := dynSvc.GetActiveLease(ctx, *session.LeaseID)
	if err != nil || lease == nil {
		t.Fatalf("active lease lookup: %v (lease=%v)", err, lease)
	}
	if lease.AccessRequestID == nil || *lease.AccessRequestID != created.ID {
		t.Fatalf("lease must reference its access request, got %v", lease.AccessRequestID)
	}
	if lease.TTLSeconds != 30*60 {
		t.Fatalf("lease ttl must equal requested duration, got %d", lease.TTLSeconds)
	}
	if lease.AgentID == nil || *lease.AgentID != leaseAgentID {
		t.Fatalf("lease must be bound to the requesting agent, got %v", lease.AgentID)
	}

	// 3. Requester fetches the credential: a derived key, never the static value.
	creds, err := issuer.ResolveLeaseCredentials(ctx, session)
	if err != nil {
		t.Fatalf("resolve lease credentials: %v", err)
	}
	apiKey, ok := creds["api_key"]
	if !ok || !strings.HasPrefix(apiKey, dynsecret.DerivedKeyPrefix) {
		t.Fatalf("lease must carry a derived api_key, got %v", creds)
	}
	if strings.Contains(apiKey, "sk-company-ai-master") {
		t.Fatal("master key must never leave the vault through a lease")
	}

	// 4. Gateway-style validation of the presented key.
	got, err := dynSvc.ValidateDerivedKey(ctx, apiKey)
	if err != nil || got == nil {
		t.Fatalf("validate derived key: %v (lease=%v)", err, got)
	}
	if got.ID != lease.ID {
		t.Fatalf("validated lease id mismatch: %s vs %s", got.ID, lease.ID)
	}
	if unknown, _ := dynSvc.ValidateDerivedKey(ctx, dynsecret.DerivedKeyPrefix+"deadbeef"); unknown != nil {
		t.Fatal("unknown derived key must not validate")
	}

	// 5. Revoke the credential → the derived key dies with it.
	if err := credMgr.RevokeCredential(ctx, created.ID); err != nil {
		t.Fatalf("revoke credential: %v", err)
	}
	if got2, _ := dynSvc.ValidateDerivedKey(ctx, apiKey); got2 != nil {
		t.Fatal("revoked lease must no longer validate")
	}
	if _, err := credMgr.GetCredential(ctx, created.ID); err == nil {
		t.Fatal("no credential must be served after revocation")
	}
}

// TestLeaseIssuerExplicitApproval forces a pending request and approves it,
// matching the Slack/email human-approval path (decided_by is recorded and
// lands on the lease audit entry).
func TestLeaseIssuerExplicitApproval(t *testing.T) {
	ctx := context.Background()
	pool, dynSvc, _, issuer, cleanup := newLeaseE2EStack(t, ctx)
	defer cleanup()
	seedWorkflowPolicyData(t, ctx, pool)
	secret := seedLeaseE2EData(t, ctx, pool, dynSvc)

	wfSvc := NewService(pool, false)
	created, err := wfSvc.CreateRequest(ctx, CreateRequestInput{
		SecretID:        secretID,
		RequesterType:   "ai_agent",
		AIAgentID:       leaseAgentID,
		Reason:          "nightly report job",
		DurationMinutes: 20,
		CredentialType:  secret.CredentialType,
	})
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	// Force the request back to pending to exercise the explicit approval
	// path (default api_key policy auto-approves).
	if _, err := pool.Exec(ctx, `UPDATE access_requests SET status = 'pending' WHERE id = $1`, created.ID); err != nil {
		t.Fatalf("reset to pending: %v", err)
	}
	approved, err := wfSvc.Approve(ctx, created.ID, ownerID)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if approved.DecidedBy == nil || *approved.DecidedBy != ownerID {
		t.Fatalf("approval must record the approver, got %v", approved.DecidedBy)
	}

	session, err := issuer.IssueForRequest(ctx, approved, secret)
	if err != nil {
		t.Fatalf("issue after explicit approval: %v", err)
	}
	if session.LeaseID == nil {
		t.Fatal("session must be lease-backed")
	}
	creds, err := issuer.ResolveLeaseCredentials(ctx, session)
	if err != nil {
		t.Fatalf("resolve credentials: %v", err)
	}
	if apiKey := creds["api_key"]; !strings.HasPrefix(apiKey, dynsecret.DerivedKeyPrefix) {
		t.Fatalf("expected derived api_key, got %v", creds)
	}
}

// TestLeaseIssuerTTLCap: a request for longer than the lease cap still mints
// a capped lease — the session stays valid but the lease (and key) expires.
func TestLeaseIssuerTTLCap(t *testing.T) {
	ctx := context.Background()
	pool, dynSvc, _, issuer, cleanup := newLeaseE2EStack(t, ctx)
	defer cleanup()
	seedWorkflowPolicyData(t, ctx, pool)
	secret := seedLeaseE2EData(t, ctx, pool, dynSvc)

	wfSvc := NewService(pool, false)
	created, err := wfSvc.CreateRequest(ctx, CreateRequestInput{
		SecretID:        secretID,
		RequesterType:   "ai_agent",
		AIAgentID:       leaseAgentID,
		Reason:          "long running migration",
		DurationMinutes: 480, // 8h — TierLow max; lease caps at 1h
		CredentialType:  secret.CredentialType,
	})
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	session, err := issuer.IssueForRequest(ctx, created, secret)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	lease, err := dynSvc.GetActiveLease(ctx, *session.LeaseID)
	if err != nil || lease == nil {
		t.Fatalf("lease lookup: %v", err)
	}
	if lease.TTLSeconds != 3600 {
		t.Fatalf("lease ttl must be capped at 3600, got %d", lease.TTLSeconds)
	}
	if time.Until(lease.ExpiresAt) > 61*time.Minute {
		t.Fatalf("lease expiry too far out: %v", lease.ExpiresAt)
	}
}

// TestLeaseIssuerFailsClosed: when the provider cannot mint a lease, no
// credential session may appear — the static secret value must not leak as a
// fallback.
func TestLeaseIssuerFailsClosed(t *testing.T) {
	ctx := context.Background()
	pool, dynSvc, _, issuer, cleanup := newLeaseE2EStack(t, ctx)
	defer cleanup()
	seedWorkflowPolicyData(t, ctx, pool)

	// Seed agent + provider without master_key, then link the secret.
	_, err := pool.Exec(ctx, `
		INSERT INTO agent_identities (id, project_id, name, created_by)
		VALUES ($1, $2, 'e2e-agent', $3)`, leaseAgentID, projectID, ownerID)
	if err != nil {
		t.Fatalf("seed agent identity: %v", err)
	}
	pc, err := dynSvc.CreateProvider(ctx, projectID, "broken-provider", "derived_api_key",
		map[string]string{"upstream": "api.openai.com"}, ownerID) // missing master_key
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	vaultSvc := vault.NewService(pool, nil)
	if _, err := vaultSvc.SetDynamicProvider(ctx, secretID, ownerID, &pc.ID); err != nil {
		t.Fatalf("link secret: %v", err)
	}
	secret, err := vaultSvc.GetSecretByID(ctx, secretID)
	if err != nil || secret == nil {
		t.Fatalf("get secret: %v", err)
	}

	wfSvc := NewService(pool, false)
	created, err := wfSvc.CreateRequest(ctx, CreateRequestInput{
		SecretID:        secretID,
		RequesterType:   "ai_agent",
		AIAgentID:       leaseAgentID,
		Reason:          "lease mint will fail",
		DurationMinutes: 15,
		CredentialType:  secret.CredentialType,
	})
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	if _, err := issuer.IssueForRequest(ctx, created, secret); err == nil {
		t.Fatal("issuance must fail when the provider cannot mint a lease")
	}

	var cnt int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM credential_sessions WHERE access_request_id = $1`, created.ID,
	).Scan(&cnt); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if cnt != 0 {
		t.Fatalf("no credential session may exist after a failed lease mint, got %d", cnt)
	}
}

// TestLeaseIssuerStaticSecretUnchanged: secrets without a provider link keep
// the plain static credential-session path.
func TestLeaseIssuerStaticSecretUnchanged(t *testing.T) {
	ctx := context.Background()
	pool, dynSvc, _, issuer, cleanup := newLeaseE2EStack(t, ctx)
	defer cleanup()
	seedWorkflowPolicyData(t, ctx, pool)

	vaultSvc := vault.NewService(pool, nil)
	secret, err := vaultSvc.GetSecretByID(ctx, secretID)
	if err != nil || secret == nil {
		t.Fatalf("get secret: %v", err)
	}
	if secret.DynamicProviderID != nil {
		t.Fatalf("unlinked secret must have no provider, got %v", secret.DynamicProviderID)
	}

	wfSvc := NewService(pool, false)
	created, err := wfSvc.CreateRequest(ctx, CreateRequestInput{
		SecretID:        secretID,
		RequesterUserID: requesterID,
		RequesterType:   "human",
		Reason:          "static path stays static",
		DurationMinutes: 10,
		CredentialType:  secret.CredentialType,
	})
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	session, err := issuer.IssueForRequest(ctx, created, secret)
	if err != nil {
		t.Fatalf("issue static: %v", err)
	}
	if session.LeaseID != nil {
		t.Fatalf("static secret must not produce a lease, got %v", session.LeaseID)
	}

	// Sanity: dynSvc still sees zero leases for the (unused) provider path.
	if got, _ := dynSvc.ValidateDerivedKey(ctx, "valt_dk_nothing"); got != nil {
		t.Fatal("nothing to validate on the static path")
	}
}
