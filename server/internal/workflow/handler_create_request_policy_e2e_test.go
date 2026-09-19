package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/valt-dev/valt/server/internal/audit"
	"github.com/valt-dev/valt/server/internal/auth"
	"github.com/valt-dev/valt/server/internal/policy"
	"github.com/valt-dev/valt/server/internal/vault"
)

const outsiderID = "00000000-0000-0000-0000-000000000103"

type apiErrorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func TestCreateRequest_ForbiddenWhenUserNotProjectMember(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pool, cleanup := newWorkflowIntegrationDB(t, ctx)
	defer cleanup()
	seedWorkflowPolicyData(t, ctx, pool)

	if _, err := pool.Exec(ctx, `INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)`, outsiderID, "outsider@example.com", "hash"); err != nil {
		t.Fatalf("seed outsider user failed: %v", err)
	}
	bindPolicyToSecret(t, ctx, pool)

	h := newCreateRequestTestHandler(pool, true)
	router := newCreateRequestRouter(h, outsiderID)

	body := map[string]any{"reason": "reason long enough for policy checks", "duration_minutes": 60}
	w := performCreateRequest(t, router, secretID, body)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", w.Code, w.Body.String())
	}

	var resp apiErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error response failed: %v", err)
	}
	if resp.Error.Code != "forbidden" {
		t.Fatalf("expected forbidden code, got %s", resp.Error.Code)
	}
	if !strings.Contains(resp.Error.Message, "not a member") {
		t.Fatalf("expected membership message, got %q", resp.Error.Message)
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM access_requests WHERE secret_id = $1 AND requester_user_id = $2`, secretID, outsiderID).Scan(&count); err != nil {
		t.Fatalf("query access_requests failed: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected no access request rows, got %d", count)
	}
}

func TestCreateRequest_AcceptedUsesBoundPolicySnapshot(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pool, cleanup := newWorkflowIntegrationDB(t, ctx)
	defer cleanup()
	seedWorkflowPolicyData(t, ctx, pool)

	tpl, version := bindPolicyToSecret(t, ctx, pool)

	h := newCreateRequestTestHandler(pool, true)
	router := newCreateRequestRouter(h, requesterID)

	body := map[string]any{"reason": "this reason is long enough for approval policy", "duration_minutes": 120}
	w := performCreateRequest(t, router, secretID, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", w.Code, w.Body.String())
	}

	var req AccessRequest
	if err := json.Unmarshal(w.Body.Bytes(), &req); err != nil {
		t.Fatalf("decode create request response failed: %v", err)
	}
	if req.Status != "pending" {
		t.Fatalf("expected pending, got %s", req.Status)
	}
	if req.RequestedDurationMinutes != 45 {
		t.Fatalf("expected capped duration 45, got %d", req.RequestedDurationMinutes)
	}

	var source string
	var templateID *string
	var templateVersion *int
	var appliedRaw []byte
	if err := pool.QueryRow(ctx, `
		SELECT applied_policy_source, applied_template_id, applied_template_version, applied_policy
		FROM access_requests WHERE id = $1`, req.ID).Scan(&source, &templateID, &templateVersion, &appliedRaw); err != nil {
		t.Fatalf("load applied policy snapshot failed: %v", err)
	}
	if source != policy.PolicySourceTemplateOverride {
		t.Fatalf("expected source template_override, got %s", source)
	}
	if templateID == nil || *templateID != tpl.ID {
		t.Fatalf("unexpected applied template id: %v", templateID)
	}
	if templateVersion == nil || *templateVersion != version {
		t.Fatalf("unexpected applied template version: %v", templateVersion)
	}

	var applied policy.PolicyParameters
	if err := json.Unmarshal(appliedRaw, &applied); err != nil {
		t.Fatalf("decode applied policy failed: %v", err)
	}
	if applied.MaxDurationMinutes != 45 {
		t.Fatalf("expected applied max_duration_minutes=45, got %d", applied.MaxDurationMinutes)
	}
}

func bindPolicyToSecret(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (*policy.Template, int) {
	t.Helper()
	ps := policy.NewService(pool)
	params := map[string]any{
		"max_duration_minutes": 30,
		"require_approval":     true,
		"allow_auto_approve":   false,
		"require_reason":       true,
		"min_reason_length":    20,
		"max_requests_per_day": 100,
		"cool_down_minutes":    0,
		"single_use":           true,
		"notify_on_access":     true,
		"require_consent":      false,
	}
	tpl, err := ps.CreateTemplate(ctx, projectID, ownerID, "Workflow Handler Policy", "", strPtr("api_key"), params)
	if err != nil {
		t.Fatalf("create template failed: %v", err)
	}
	b, err := ps.UpdateBinding(ctx, secretID, ownerID, tpl.ID, tpl.CurrentVersion, map[string]any{"max_duration_minutes": 45})
	if err != nil {
		t.Fatalf("update binding failed: %v", err)
	}
	if b.TemplateVersion == nil {
		t.Fatal("binding template version must be set")
	}
	return tpl, *b.TemplateVersion
}

func newCreateRequestTestHandler(pool *pgxpool.Pool, policyV2Enabled bool) *Handler {
	vaultSvc := vault.NewService(pool, nil)
	credMgr := NewCredentialManager(pool, nil)
	return NewHandler(
		NewService(pool, policyV2Enabled),
		credMgr,
		NewLeaseIssuer(credMgr, nil, audit.NewLogger(pool)),
		vaultSvc,
		audit.NewLogger(pool),
		nil, // notifySvc: nil — these tests assert policy snapshots, not notifications
		nil,
		nil,
		pool,
	)
}

func newCreateRequestRouter(h *Handler, userID string) http.Handler {
	r := chi.NewRouter()
	r.Post("/api/v1/secrets/{secret_id}/access-requests", func(w http.ResponseWriter, req *http.Request) {
		h.CreateRequest(w, req.WithContext(auth.WithUserID(req.Context(), userID)))
	})
	return r
}

func performCreateRequest(t *testing.T, h http.Handler, secretID string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request body failed: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/"+secretID+"/access-requests", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}
