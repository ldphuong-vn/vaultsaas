package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/valt-dev/valt/server/internal/audit"
	"github.com/valt-dev/valt/server/internal/auth"
	"github.com/valt-dev/valt/server/internal/dynsecret"
	"github.com/valt-dev/valt/server/pkg/apierror"
	"github.com/valt-dev/valt/server/pkg/validator"
)

// RevokeSummary reports what one revoke-all run killed.
type RevokeSummary struct {
	LeasesRevoked   int `json:"leases_revoked"`
	SessionsRevoked int `json:"sessions_revoked"`
	TokensRevoked   int `json:"agent_tokens_revoked"`
	AgentsDisabled  int `json:"agents_disabled"`
}

// RevokeService implements the week 9-10 revoke cascade: one command kills
// every credential granted to a user — dynamic leases, credential sessions,
// agent tokens, and the agent identities they belong to. Nhân viên nghỉ →
// một lệnh, mọi credential chết trong vài giây.
type RevokeService struct {
	pool     *pgxpool.Pool
	dynSvc   *dynsecret.Service
	credMgr  *CredentialManager
	auditLog *audit.Logger
}

// NewRevokeService creates a RevokeService.
func NewRevokeService(pool *pgxpool.Pool, dynSvc *dynsecret.Service, credMgr *CredentialManager, auditLog *audit.Logger) *RevokeService {
	return &RevokeService{pool: pool, dynSvc: dynSvc, credMgr: credMgr, auditLog: auditLog}
}

// RevokeAllForUser kills all of targetUserID's active credentials and
// returns a summary. Orders matter for auditability but each step is
// independent: leases die at the source, sessions die by requester and by
// lease, agent tokens are revoked and the identities disabled.
func (s *RevokeService) RevokeAllForUser(ctx context.Context, targetUserID, actor string) (*RevokeSummary, error) {
	summary := &RevokeSummary{}

	// 1. Dynamic leases (backend credentials dropped best-effort).
	leases, err := s.dynSvc.RevokeLeasesForUser(ctx, targetUserID)
	if err != nil {
		return nil, fmt.Errorf("revoking leases: %w", err)
	}
	summary.LeasesRevoked = leases

	// 2. Credential sessions: those born from the user's own requests, and
	// those whose lease belonged to one of the user's agents.
	sessions, err := s.revokeSessionsForUser(ctx, targetUserID)
	if err != nil {
		return nil, fmt.Errorf("revoking credential sessions: %w", err)
	}
	summary.SessionsRevoked = sessions

	// 3. Agent tokens + identities (ValidateToken never checks identity
	// status, so tokens must be revoked directly).
	tokens, agents, err := s.disableAgentsForUser(ctx, targetUserID)
	if err != nil {
		return nil, fmt.Errorf("disabling agents: %w", err)
	}
	summary.TokensRevoked = tokens
	summary.AgentsDisabled = agents

	// 4. Reflect the cascade on the access requests themselves.
	// ai_agent_id is VARCHAR while agent_identities.id is UUID — compare in
	// the text domain so agent ids that are not UUIDs cannot break the cast.
	if _, err := s.pool.Exec(ctx, `
		UPDATE access_requests SET status = 'revoked'
		WHERE status IN ('approved', 'active')
		  AND (requester_user_id = $1
		       OR ai_agent_id::text IN (SELECT id::text FROM agent_identities WHERE created_by = $1))`,
		targetUserID); err != nil {
		return nil, fmt.Errorf("revoking access requests: %w", err)
	}

	if s.auditLog != nil {
		meta, _ := json.Marshal(summary)
		if _, err := s.auditLog.Log(ctx, audit.Entry{
			UserID:       actor,
			Action:       "user.revoke_all",
			ResourceType: "user",
			ResourceID:   targetUserID,
			EventType:    "action",
			Status:       "success",
			Metadata:     string(meta),
		}); err != nil {
			log.Printf("revoke-all: audit log error: %v", err)
		}
	}

	return summary, nil
}

// revokeSessionsForUser revokes active credential sessions for a user's own
// requests plus sessions backed by leases of the user's agents.
func (s *RevokeService) revokeSessionsForUser(ctx context.Context, targetUserID string) (int, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE credential_sessions SET status = 'revoked', revoked_at = now()
		WHERE status = 'active'
		  AND (
		    access_request_id IN (SELECT id FROM access_requests WHERE requester_user_id = $1)
		    OR lease_id IN (
		        SELECT l.id FROM dynamic_leases l
		        JOIN agent_identities a ON a.id = l.agent_id
		        WHERE a.created_by = $1)
		  )`, targetUserID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// disableAgentsForUser revokes all active agent tokens of the user's agents
// and disables the identities themselves. Returns (tokens, agents).
func (s *RevokeService) disableAgentsForUser(ctx context.Context, targetUserID string) (int, int, error) {
	tokTag, err := s.pool.Exec(ctx, `
		UPDATE agent_tokens SET revoked_at = now()
		WHERE revoked_at IS NULL
		  AND agent_id IN (SELECT id FROM agent_identities WHERE created_by = $1)`, targetUserID)
	if err != nil {
		return 0, 0, err
	}

	agentTag, err := s.pool.Exec(ctx, `
		UPDATE agent_identities SET status = 'disabled', updated_at = now()
		WHERE status = 'active' AND created_by = $1`, targetUserID)
	if err != nil {
		return 0, 0, err
	}
	return int(tokTag.RowsAffected()), int(agentTag.RowsAffected()), nil
}

// HandleRevokeAllForUser serves POST /users/{user_id}/revoke-all.
// Authorization: a global admin, or the user themselves (lost-laptop case).
func (s *RevokeService) HandleRevokeAllForUser(w http.ResponseWriter, r *http.Request) {
	callerID := auth.UserIDFromContext(r.Context())
	if callerID == "" {
		apierror.Unauthorized(w, "authentication required")
		return
	}

	targetUserID := chi.URLParam(r, "user_id")
	if _, err := validator.ValidateUUID(targetUserID); err != nil {
		apierror.BadRequest(w, "invalid user_id")
		return
	}
	if callerID != targetUserID {
		var role string
		err := s.pool.QueryRow(r.Context(),
			`SELECT COALESCE(role, 'user') FROM users WHERE id = $1`, callerID,
		).Scan(&role)
		if err != nil || role != "admin" {
			apierror.Forbidden(w, "admin access required")
			return
		}
	}

	var targetExists bool
	if err := s.pool.QueryRow(r.Context(),
		`SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, targetUserID,
	).Scan(&targetExists); err != nil || !targetExists {
		apierror.NotFound(w, "user not found")
		return
	}

	summary, err := s.RevokeAllForUser(r.Context(), targetUserID, callerID)
	if err != nil {
		log.Printf("revoke-all for user %s failed: %v", targetUserID, err)
		apierror.InternalError(w, "failed to revoke credentials")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary) //nolint:errcheck
}
