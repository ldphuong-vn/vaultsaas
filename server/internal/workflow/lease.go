package workflow

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/valt-dev/valt/server/internal/audit"
	"github.com/valt-dev/valt/server/internal/dynsecret"
	"github.com/valt-dev/valt/server/internal/vault"
)

// ErrLeaseInactive is returned when a session's lease has expired or been revoked.
var ErrLeaseInactive = errors.New("lease expired or revoked")

// maxLeaseTTLSeconds caps approval-minted leases, mirroring the direct
// POST /providers/{id}/leases handler. The stricter of policy duration and
// this cap wins; once the lease dies the agent must request again.
const maxLeaseTTLSeconds = 3600

// LeaseIssuer bridges the approval workflow to dynamic secret providers.
// For secrets backed by a dynamic provider it mints a short-lived lease at
// approval time; static secrets keep the plain credential-session path.
type LeaseIssuer struct {
	credMgr  *CredentialManager
	dynSvc   *dynsecret.Service
	auditLog *audit.Logger
}

// NewLeaseIssuer creates a LeaseIssuer. dynSvc may be nil (no dynamic
// secrets support); every request then falls back to static issuance.
func NewLeaseIssuer(credMgr *CredentialManager, dynSvc *dynsecret.Service, auditLog *audit.Logger) *LeaseIssuer {
	return &LeaseIssuer{credMgr: credMgr, dynSvc: dynSvc, auditLog: auditLog}
}

// IssueForRequest issues the credential granted by an approved request:
// a provider lease when the secret is linked to a dynamic provider,
// otherwise the static credential session. It fails closed — if the lease
// cannot be minted, no credential is issued and the static secret value is
// never silently substituted (that value is exactly what the dynamic
// provider exists to keep away from the requester).
func (li *LeaseIssuer) IssueForRequest(ctx context.Context, req *AccessRequest, secret *vault.Secret) (*CredentialSession, error) {
	if li.dynSvc == nil || secret == nil || secret.DynamicProviderID == nil || *secret.DynamicProviderID == "" {
		return li.credMgr.IssueCredential(ctx, req.ID, credentialTypeOf(secret), req.RequestedDurationMinutes, nil)
	}

	ttlSeconds := req.RequestedDurationMinutes * 60
	if ttlSeconds <= 0 {
		ttlSeconds = maxLeaseTTLSeconds
	}
	if ttlSeconds > maxLeaseTTLSeconds {
		ttlSeconds = maxLeaseTTLSeconds
	}

	lease, err := li.dynSvc.CreateLease(ctx, *secret.DynamicProviderID, agentIDOf(req), req.ID, ttlSeconds)
	if err != nil {
		return nil, fmt.Errorf("mint lease for request %s: %w", req.ID, err)
	}

	session, err := li.credMgr.IssueCredential(ctx, req.ID, credentialTypeOf(secret), req.RequestedDurationMinutes, &lease.ID)
	if err != nil {
		// Leave no orphaned lease behind a failed session.
		if revokeErr := li.dynSvc.RevokeLease(ctx, lease.ID); revokeErr != nil {
			log.Printf("lease issuer: failed to revoke orphaned lease %s: %v", lease.ID, revokeErr)
		}
		return nil, fmt.Errorf("issue credential session for lease: %w", err)
	}

	if li.auditLog != nil {
		// user_id is a UUID column: record the approver when there is one,
		// NULL otherwise (auto-approve), and put the decision path in metadata.
		decidedVia := "auto-approve"
		if req.DecidedBy != nil && *req.DecidedBy != "" {
			decidedVia = "approver"
		}
		if _, err := li.auditLog.Log(ctx, audit.Entry{
			UserID:       decidedByOf(req),
			Action:       "lease.create",
			ResourceType: "dynamic_lease",
			ResourceID:   lease.ID,
			EventType:    "action",
			Status:       "success",
			Metadata: fmt.Sprintf(`{"access_request_id":%q,"provider_id":%q,"agent_id":%q,"decided_via":%q,"ttl_seconds":%d}`,
				req.ID, *secret.DynamicProviderID, agentIDOf(req), decidedVia, ttlSeconds),
		}); err != nil {
			log.Printf("lease issuer: audit log error: %v", err)
		}
	}

	return session, nil
}

// ResolveLeaseCredentials returns the lease credentials for a session backed
// by a dynamic lease, verifying the lease is still active. Returns (nil, nil)
// for sessions without a lease (static secrets) and ErrLeaseInactive when the
// lease is dead.
func (li *LeaseIssuer) ResolveLeaseCredentials(ctx context.Context, session *CredentialSession) (map[string]string, error) {
	if session.LeaseID == nil || li.dynSvc == nil {
		return nil, nil
	}
	lease, err := li.dynSvc.GetActiveLease(ctx, *session.LeaseID)
	if err != nil {
		return nil, err
	}
	if lease == nil {
		return nil, ErrLeaseInactive
	}
	return li.dynSvc.GetLeaseCredentials(ctx, *session.LeaseID)
}

func credentialTypeOf(secret *vault.Secret) string {
	if secret == nil {
		return ""
	}
	return secret.CredentialType
}

func agentIDOf(req *AccessRequest) string {
	if req.AIAgentID == nil {
		return ""
	}
	return *req.AIAgentID
}

func decidedByOf(req *AccessRequest) string {
	if req.DecidedBy == nil {
		return ""
	}
	return *req.DecidedBy
}
