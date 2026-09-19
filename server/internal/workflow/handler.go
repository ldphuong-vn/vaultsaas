package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/valt-dev/valt/server/internal/agent"
	"github.com/valt-dev/valt/server/internal/audit"
	"github.com/valt-dev/valt/server/internal/auth"
	"github.com/valt-dev/valt/server/internal/notify"
	"github.com/valt-dev/valt/server/internal/vault"
	"github.com/valt-dev/valt/server/pkg/apierror"
	"github.com/valt-dev/valt/server/pkg/crypto"
	"github.com/valt-dev/valt/server/pkg/validator"
)

// Handler serves workflow HTTP endpoints.
type Handler struct {
	service     *Service
	credMgr     *CredentialManager
	leaseIssuer *LeaseIssuer
	vaultSvc    *vault.Service
	auditLog    *audit.Logger
	notifySvc   *notify.Service
	tokenStore  *notify.ActionTokenStore
	masterKey   []byte
	pool        *pgxpool.Pool
}

// NewHandler creates a workflow Handler.
func NewHandler(svc *Service, credMgr *CredentialManager, leaseIssuer *LeaseIssuer, vaultSvc *vault.Service, auditLog *audit.Logger, notifySvc *notify.Service, tokenStore *notify.ActionTokenStore, masterKey []byte, pool *pgxpool.Pool) *Handler {
	return &Handler{
		service:     svc,
		credMgr:     credMgr,
		leaseIssuer: leaseIssuer,
		vaultSvc:    vaultSvc,
		auditLog:    auditLog,
		notifySvc:   notifySvc,
		tokenStore:  tokenStore,
		masterKey:   masterKey,
		pool:        pool,
	}
}

type createRequestBody struct {
	RequesterType   string `json:"requester_type"`
	AIAgentID       string `json:"ai_agent_id,omitempty"`
	Reason          string `json:"reason"`
	DurationMinutes int    `json:"duration_minutes"`
}

// CreateRequest handles POST /secrets/{secret_id}/access-requests
func (h *Handler) CreateRequest(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	agentID := agent.AgentIDFromContext(r.Context())

	if userID == "" && agentID == "" {
		apierror.Unauthorized(w, "authentication required")
		return
	}

	secretID := chi.URLParam(r, "secret_id")
	if _, err := validator.ValidateUUID(secretID); err != nil {
		apierror.BadRequest(w, "invalid secret_id")
		return
	}

	var body createRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.BadRequest(w, "invalid request body")
		return
	}

	// Derive requester_type from auth context
	if agentID != "" {
		body.RequesterType = "ai_agent"
	} else if body.RequesterType == "" {
		body.RequesterType = "human"
	}
	if body.RequesterType != "human" && body.RequesterType != "ai_agent" {
		apierror.BadRequest(w, "requester_type must be 'human' or 'ai_agent'")
		return
	}

	// Fetch secret without owner constraint
	secret, err := h.vaultSvc.GetSecretByID(r.Context(), secretID)
	if err != nil {
		log.Printf("Failed to get secret for access request: %v", err)
		apierror.InternalError(w, "failed to validate secret")
		return
	}
	if secret == nil {
		apierror.NotFound(w, "secret not found")
		return
	}

	// Authorization: project-scoped or owner-only for legacy secrets
	if secret.ProjectID != nil {
		if agentID != "" {
			// Agent: check agent_identities.project_id == secret.project_id
			var agentProjectID string
			qErr := h.pool.QueryRow(r.Context(),
				`SELECT project_id FROM agent_identities WHERE id = $1 AND status = 'active'`,
				agentID,
			).Scan(&agentProjectID)
			if qErr != nil || agentProjectID != *secret.ProjectID {
				apierror.Forbidden(w, "agent not in secret's project")
				return
			}
		} else {
			// User: check project membership
			var memberCount int
			qErr := h.pool.QueryRow(r.Context(),
				`SELECT COUNT(*) FROM project_memberships WHERE project_id = $1 AND user_id = $2`,
				*secret.ProjectID, userID,
			).Scan(&memberCount)
			if qErr != nil || memberCount == 0 {
				apierror.Forbidden(w, "not a member of the secret's project")
				return
			}
		}
	} else {
		// Legacy secret (no project): owner-only
		if secret.UserID != userID {
			apierror.Forbidden(w, "only the owner can request access to this secret")
			return
		}
	}

	// Resolve agent ID for the request.
	// Context agentID is authoritative (set by dualAuthMiddleware from a validated token).
	// For ai_agent requester_type without a context agent, validate body field.
	// For human requester_type, always use empty string so the service stores nil.
	var requestAgentID string
	if agentID != "" {
		requestAgentID = agentID
	} else if body.RequesterType == "ai_agent" {
		// Human-authenticated caller claiming ai_agent type: validate agent exists
		// and belongs to the same project as the secret to prevent impersonation.
		if body.AIAgentID == "" {
			apierror.BadRequest(w, "ai_agent_id is required when requester_type is 'ai_agent'")
			return
		}
		var agentProjectID string
		agentErr := h.pool.QueryRow(r.Context(),
			`SELECT project_id FROM agent_identities WHERE id = $1 AND status = 'active'`,
			body.AIAgentID,
		).Scan(&agentProjectID)
		if agentErr != nil {
			apierror.BadRequest(w, "invalid or inactive ai_agent_id")
			return
		}
		if secret.ProjectID != nil && agentProjectID != *secret.ProjectID {
			apierror.Forbidden(w, "agent does not belong to the secret's project")
			return
		}
		requestAgentID = body.AIAgentID
	}
	// For human requester_type: requestAgentID remains "" → service converts to nil pointer

	callerDesc := userID
	if agentID != "" {
		callerDesc = "agent:" + agentID
	}

	req, err := h.service.CreateRequest(r.Context(), CreateRequestInput{
		SecretID:        secretID,
		RequesterUserID: userID,
		RequesterType:   body.RequesterType,
		AIAgentID:       requestAgentID,
		Reason:          body.Reason,
		DurationMinutes: body.DurationMinutes,
		CredentialType:  secret.CredentialType,
	})
	if err != nil {
		apierror.BadRequest(w, err.Error())
		return
	}

	h.auditLog.LogFromRequest(r, callerDesc, "access_request.create", "access_request", req.ID)

	// Auto-approve for Tier 1: issue credential immediately
	if req.Status == "approved" {
		if _, issueErr := h.leaseIssuer.IssueForRequest(r.Context(), req, secret); issueErr != nil {
			log.Printf("Failed to auto-issue credential: %v", issueErr)
		}
	}

	// Notify using immutable request-time policy snapshot (falls back to tier defaults)
	p := h.service.EffectivePolicyForRequest(r.Context(), req.ID, secret.CredentialType)
	if p.NotifyOnAccess && h.notifySvc != nil {
		var ownerEmail string
		_ = h.pool.QueryRow(r.Context(),
			`SELECT email FROM users WHERE id = $1`, secret.UserID,
		).Scan(&ownerEmail)
		_ = h.notifySvc.NotifyApprovalNeeded(r.Context(), secret.UserID, ownerEmail, req.ID, secret.Name, callerDesc, body.Reason)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(req)
}

// ListPending handles GET /access-requests?status=
func (h *Handler) ListPending(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	status := r.URL.Query().Get("status")

	pg, err := validator.ValidatePagination(
		r.URL.Query().Get("page"),
		r.URL.Query().Get("limit"),
	)
	if err != nil {
		apierror.BadRequest(w, err.Error())
		return
	}

	requests, total, err := h.service.ListPending(r.Context(), userID, status, pg.Limit, pg.Offset)
	if err != nil {
		log.Printf("Failed to list access requests: %v", err)
		apierror.InternalError(w, "failed to list access requests")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"requests": requests,
		"total":    total,
		"page":     pg.Page,
		"limit":    pg.Limit,
	})
}

type approveRejectBody struct {
	RejectionReason string `json:"rejection_reason,omitempty"`
}

// Approve handles POST /access-requests/{request_id}/approve
func (h *Handler) Approve(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	requestID := chi.URLParam(r, "request_id")

	if _, err := validator.ValidateUUID(requestID); err != nil {
		apierror.BadRequest(w, "invalid request_id")
		return
	}

	// Verify caller is an assigned approver or secret owner before approving.
	req0, err := h.service.GetRequestByID(r.Context(), requestID)
	if err != nil || req0 == nil {
		apierror.NotFound(w, "request not found")
		return
	}
	isApprover, _ := h.service.IsAssignedApprover(r.Context(), requestID, userID)
	if !isApprover {
		secret, _ := h.vaultSvc.GetSecretByID(r.Context(), req0.SecretID)
		isOwner := secret != nil && secret.UserID == userID
		if !isOwner {
			apierror.Forbidden(w, "not authorized to approve this request")
			return
		}
	}

	req, err := h.service.Approve(r.Context(), requestID, userID)
	if err != nil {
		apierror.BadRequest(w, err.Error())
		return
	}

	// Use GetSecretByID (no owner constraint) so approver != owner works.
	secret, err := h.vaultSvc.GetSecretByID(r.Context(), req.SecretID)
	if err != nil {
		log.Printf("Failed to fetch secret for credential issuance: %v", err)
		apierror.InternalError(w, "failed to issue credential")
		return
	}

	// Issue credential — a dynamic lease for provider-backed secrets, the
	// static credential session otherwise. Fails closed: no lease, no credential.
	if _, issueErr := h.leaseIssuer.IssueForRequest(r.Context(), req, secret); issueErr != nil {
		log.Printf("Failed to issue credential after approval: %v", issueErr)
		apierror.InternalError(w, "approved but failed to issue credential")
		return
	}

	h.auditLog.LogFromRequest(r, userID, "access_request.approve", "access_request", requestID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(req)
}

// GetRequest handles GET /access-requests/{request_id}
func (h *Handler) GetRequest(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	requestID := chi.URLParam(r, "request_id")

	if _, err := validator.ValidateUUID(requestID); err != nil {
		apierror.BadRequest(w, "invalid request_id")
		return
	}

	req, err := h.service.GetRequestByID(r.Context(), requestID)
	if err != nil {
		log.Printf("Failed to get request: %v", err)
		apierror.InternalError(w, "failed to get request")
		return
	}
	if req == nil {
		apierror.NotFound(w, "request not found")
		return
	}

	agentID := agent.AgentIDFromContext(r.Context())
	callerIsRequester := (userID != "" && req.RequesterUserID == userID) ||
		(agentID != "" && req.AIAgentID != nil && *req.AIAgentID == agentID)
	if !callerIsRequester {
		isApprover, _ := h.service.IsAssignedApprover(r.Context(), requestID, userID)
		isOwner := false
		if !isApprover && userID != "" {
			secret, _ := h.vaultSvc.GetSecretByID(r.Context(), req.SecretID)
			isOwner = secret != nil && secret.UserID == userID
		}
		if !isApprover && !isOwner {
			apierror.Forbidden(w, "not your request")
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(req)
}

// Reject handles POST /access-requests/{request_id}/reject
func (h *Handler) Reject(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	requestID := chi.URLParam(r, "request_id")

	if _, err := validator.ValidateUUID(requestID); err != nil {
		apierror.BadRequest(w, "invalid request_id")
		return
	}

	// Verify caller is an assigned approver or secret owner before rejecting.
	req0, err := h.service.GetRequestByID(r.Context(), requestID)
	if err != nil || req0 == nil {
		apierror.NotFound(w, "request not found")
		return
	}
	isApprover, _ := h.service.IsAssignedApprover(r.Context(), requestID, userID)
	if !isApprover {
		secret, _ := h.vaultSvc.GetSecretByID(r.Context(), req0.SecretID)
		isOwner := secret != nil && secret.UserID == userID
		if !isOwner {
			apierror.Forbidden(w, "not authorized to reject this request")
			return
		}
	}

	var body approveRejectBody
	_ = json.NewDecoder(r.Body).Decode(&body)

	req, err := h.service.Reject(r.Context(), requestID, userID, body.RejectionReason)
	if err != nil {
		apierror.BadRequest(w, err.Error())
		return
	}

	h.auditLog.LogFromRequest(r, userID, "access_request.reject", "access_request", requestID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(req)
}

// GetCredential handles GET /credentials/{request_id}
func (h *Handler) GetCredential(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	requestID := chi.URLParam(r, "request_id")

	if _, err := validator.ValidateUUID(requestID); err != nil {
		apierror.BadRequest(w, "invalid request_id")
		return
	}

	// Verify the requester owns this request
	req, err := h.service.GetRequestByID(r.Context(), requestID)
	if err != nil {
		log.Printf("Failed to get request: %v", err)
		apierror.InternalError(w, "failed to get request")
		return
	}
	if req == nil {
		apierror.NotFound(w, "request not found")
		return
	}

	agentID := agent.AgentIDFromContext(r.Context())
	callerIsRequester := (userID != "" && req.RequesterUserID == userID) ||
		(agentID != "" && req.AIAgentID != nil && *req.AIAgentID == agentID)
	if !callerIsRequester {
		apierror.Forbidden(w, "not your request")
		return
	}

	session, err := h.credMgr.GetCredential(r.Context(), requestID)
	if err != nil {
		apierror.NotFound(w, err.Error())
		return
	}

	// Policy source for single-use enforcement below.
	secret, err := h.vaultSvc.GetSecretByID(r.Context(), req.SecretID)
	if err != nil {
		log.Printf("Failed to fetch secret for credential delivery: %v", err)
	}

	callerDesc := userID
	if agentID != "" {
		callerDesc = "agent:" + agentID
	}
	h.auditLog.LogFromRequest(r, callerDesc, "credential.access", "credential_session", session.ID)

	// Lease-backed session: deliver the lease credentials (fail closed when
	// the lease is gone) and skip static-secret decryption entirely.
	if session.LeaseID != nil {
		creds, leaseErr := h.leaseIssuer.ResolveLeaseCredentials(r.Context(), session)
		if leaseErr != nil {
			if errors.Is(leaseErr, ErrLeaseInactive) {
				apierror.NotFound(w, "lease expired or revoked")
				return
			}
			log.Printf("Failed to resolve lease credentials for request %s: %v", requestID, leaseErr)
			apierror.InternalError(w, "failed to resolve lease credentials")
			return
		}
		session.Credentials = creds
		if v, ok := creds["api_key"]; ok {
			session.Value = v
		}
	} else if secret != nil && len(secret.EncryptedDEK) > 0 {
		blob, blobErr := h.vaultSvc.GetBlob(r.Context(), secret.StorageKey)
		if blobErr != nil {
			log.Printf("Failed to get blob for credential delivery: %v", blobErr)
		} else {
			dek, dekErr := crypto.DecryptAES256GCM(h.masterKey, secret.EncryptedDEK)
			if dekErr != nil {
				log.Printf("Failed to decrypt DEK for credential delivery: %v", dekErr)
			} else {
				plaintext, ptErr := crypto.DecryptAES256GCM(dek, blob)
				if ptErr != nil {
					log.Printf("Failed to decrypt blob for credential delivery: %v", ptErr)
				} else {
					session.Value = string(plaintext)
				}
				// Zero out DEK (best-effort)
				for i := range dek {
					dek[i] = 0
				}
			}
		}
	}

	// Auto-revoke if single-use
	if secret != nil {
		p := h.service.EffectivePolicyForRequest(r.Context(), requestID, secret.CredentialType)
		_ = h.credMgr.AutoRevokeIfSingleUse(r.Context(), requestID, p.SingleUse)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session)
}

// RedeemActionToken handles POST /action-tokens/{token}/redeem?action=approve|reject
// This is a PUBLIC endpoint — no JWT required.
func (h *Handler) RedeemActionToken(w http.ResponseWriter, r *http.Request) {
	rawToken := chi.URLParam(r, "token")
	action := r.URL.Query().Get("action")
	if action != "approve" && action != "reject" {
		http.Error(w, "invalid action", http.StatusBadRequest)
		return
	}

	tok, err := h.tokenStore.Consume(r.Context(), rawToken)
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusGone)
		fmt.Fprint(w, "<h2>Link expired or already used.</h2><p>You can close this tab.</p>")
		return
	}
	if tok.Action != action {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "<h2>Invalid action for this link.</h2>")
		return
	}

	switch action {
	case "approve":
		req, err := h.service.Approve(r.Context(), tok.RequestID, "email-action")
		if err != nil {
			http.Error(w, "Failed to approve: "+err.Error(), http.StatusBadRequest)
			return
		}
		secret, _ := h.vaultSvc.GetSecretByID(r.Context(), req.SecretID)
		if _, issueErr := h.leaseIssuer.IssueForRequest(r.Context(), req, secret); issueErr != nil {
			log.Printf("action-token approve: failed to issue credential: %v", issueErr)
		}
		h.auditLog.LogFromRequest(r, "email-action", "access_request.approve", "access_request", req.ID)
	case "reject":
		_, err := h.service.Reject(r.Context(), tok.RequestID, "email-action", "Rejected via email link")
		if err != nil {
			http.Error(w, "Failed to reject: "+err.Error(), http.StatusBadRequest)
			return
		}
		h.auditLog.LogFromRequest(r, "email-action", "access_request.reject", "access_request", tok.RequestID)
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<h2>Request %sd successfully.</h2><p>You can close this tab.</p>", action)
}

// activeCredentialItem is the response shape for active credential listings.
type activeCredentialItem struct {
	RequestID   string            `json:"request_id"`
	SecretID    string            `json:"secret_id"`
	SecretName  string            `json:"secret_name"`
	Value       string            `json:"value"`
	Credentials map[string]string `json:"credentials,omitempty"`
	LeaseID     string            `json:"lease_id,omitempty"`
	ExpiresAt   string            `json:"expires_at"`
}

// GetActiveCredentials handles GET /credentials/active?project_id=<id>
// Returns all active credential sessions with decrypted values for the caller.
func (h *Handler) GetActiveCredentials(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	agentID := agent.AgentIDFromContext(r.Context())
	projectID := r.URL.Query().Get("project_id")

	if userID == "" && agentID == "" {
		apierror.Unauthorized(w, "authentication required")
		return
	}

	// Build query: find active sessions for this caller in the given project.
	query := `
		SELECT ar.id, ar.secret_id, s.name, cs.expires_at,
		       cs.lease_id, s.encrypted_dek, s.storage_key
		FROM credential_sessions cs
		JOIN access_requests ar ON ar.id = cs.access_request_id
		JOIN secrets s ON s.id = ar.secret_id
		WHERE cs.status = 'active' AND cs.expires_at > NOW()`

	args := []interface{}{}
	argIdx := 1

	if userID != "" {
		query += fmt.Sprintf(" AND ar.requester_user_id = $%d", argIdx)
		args = append(args, userID)
		argIdx++
	} else {
		query += fmt.Sprintf(" AND ar.ai_agent_id = $%d", argIdx)
		args = append(args, agentID)
		argIdx++
	}

	if projectID != "" {
		query += fmt.Sprintf(" AND s.project_id = $%d", argIdx)
		args = append(args, projectID)
		argIdx++
	}

	rows, err := h.pool.Query(r.Context(), query, args...)
	if err != nil {
		log.Printf("GetActiveCredentials: query failed: %v", err)
		apierror.InternalError(w, "failed to fetch credentials")
		return
	}
	defer rows.Close()

	items := []activeCredentialItem{}
	for rows.Next() {
		var item activeCredentialItem
		var encDEK []byte
		var storageKey string
		var leaseID *string
		var expiresAt interface{}
		if err := rows.Scan(&item.RequestID, &item.SecretID, &item.SecretName,
			&expiresAt, &leaseID, &encDEK, &storageKey); err != nil {
			log.Printf("GetActiveCredentials: scan error: %v", err)
			continue
		}
		if t, ok := expiresAt.(interface{ String() string }); ok {
			item.ExpiresAt = t.String()
		}

		// Lease-backed session: deliver lease credentials, never the static
		// secret value stored on the secret row.
		if leaseID != nil {
			session := &CredentialSession{LeaseID: leaseID}
			creds, leaseErr := h.leaseIssuer.ResolveLeaseCredentials(r.Context(), session)
			if leaseErr != nil {
				if errors.Is(leaseErr, ErrLeaseInactive) {
					continue // lease already dead — session row will catch up
				}
				log.Printf("GetActiveCredentials: lease resolve error: %v", leaseErr)
				continue
			}
			item.LeaseID = *leaseID
			item.Credentials = creds
			if v, ok := creds["api_key"]; ok {
				item.Value = v
			}
			items = append(items, item)
			continue
		}

		// Decrypt value if DEK present
		if len(encDEK) > 0 {
			blob, blobErr := h.vaultSvc.GetBlob(r.Context(), storageKey)
			if blobErr == nil {
				dek, dekErr := crypto.DecryptAES256GCM(h.masterKey, encDEK)
				if dekErr == nil {
					if plaintext, ptErr := crypto.DecryptAES256GCM(dek, blob); ptErr == nil {
						item.Value = string(plaintext)
					}
					for i := range dek {
						dek[i] = 0
					}
				}
			}
		}

		items = append(items, item)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"credentials": items,
	})
}

// ApproveBySystem approves a request without user auth (called from Slack/email actions).
func (h *Handler) ApproveBySystem(ctx context.Context, requestID, actor string) error {
	req, err := h.service.Approve(ctx, requestID, actor)
	if err != nil {
		return err
	}
	secret, _ := h.vaultSvc.GetSecretByID(ctx, req.SecretID)
	if _, issueErr := h.leaseIssuer.IssueForRequest(ctx, req, secret); issueErr != nil {
		log.Printf("ApproveBySystem: failed to issue credential: %v", issueErr)
	}
	_, _ = h.auditLog.Log(ctx, audit.Entry{
		UserID:       actor,
		Action:       "access_request.approve",
		ResourceType: "access_request",
		ResourceID:   requestID,
		Metadata:     fmt.Sprintf(`{"via":%q}`, actor),
	})
	return nil
}

// RejectBySystem rejects a request without user auth (called from Slack/email actions).
func (h *Handler) RejectBySystem(ctx context.Context, requestID, actor, reason string) error {
	_, err := h.service.Reject(ctx, requestID, actor, reason)
	if err != nil {
		return err
	}
	_, _ = h.auditLog.Log(ctx, audit.Entry{
		UserID:       actor,
		Action:       "access_request.reject",
		ResourceType: "access_request",
		ResourceID:   requestID,
		Metadata:     fmt.Sprintf(`{"via":%q}`, actor),
	})
	return nil
}

// RevokeCredential handles POST /credentials/{request_id}/revoke
func (h *Handler) RevokeCredential(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	requestID := chi.URLParam(r, "request_id")

	if _, err := validator.ValidateUUID(requestID); err != nil {
		apierror.BadRequest(w, "invalid request_id")
		return
	}

	// Verify caller owns this access request or is the secret owner before revoking.
	req, err := h.service.GetRequestByID(r.Context(), requestID)
	if err != nil {
		log.Printf("Failed to get request for revoke: %v", err)
		apierror.InternalError(w, "failed to get request")
		return
	}
	if req == nil {
		apierror.NotFound(w, "request not found")
		return
	}

	agentID := agent.AgentIDFromContext(r.Context())
	callerIsRequester := (userID != "" && req.RequesterUserID == userID) ||
		(agentID != "" && req.AIAgentID != nil && *req.AIAgentID == agentID)
	if !callerIsRequester {
		// Also allow the secret owner to revoke
		secret, _ := h.vaultSvc.GetSecretByID(r.Context(), req.SecretID)
		isOwner := secret != nil && userID != "" && secret.UserID == userID
		if !isOwner {
			apierror.Forbidden(w, "not your request")
			return
		}
	}

	if err := h.credMgr.RevokeCredential(r.Context(), requestID); err != nil {
		apierror.BadRequest(w, err.Error())
		return
	}

	callerDesc := userID
	if agentID != "" {
		callerDesc = "agent:" + agentID
	}
	h.auditLog.LogFromRequest(r, callerDesc, "credential.revoke", "credential_session", requestID)

	w.WriteHeader(http.StatusNoContent)
}
