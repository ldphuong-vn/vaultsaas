package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valt-dev/valt/server/internal/auth"
	"github.com/valt-dev/valt/server/internal/testutil"
)

func TestPhase01PolicyAPIIntegration(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	pool, cleanup := newPolicyIntegrationDB(t, ctx)
	defer cleanup()

	seedPolicyIntegrationData(t, ctx, pool)

	svc := NewService(pool)
	h := NewHandler(svc)
	r := chi.NewRouter()
	h.RegisterRoutes(r)

	listResp := doPolicyRequest(t, r, http.MethodGet, "/projects/00000000-0000-0000-0000-000000000201/policy-templates", "00000000-0000-0000-0000-000000000101", nil)
	if listResp.Code != http.StatusOK {
		t.Fatalf("list templates status mismatch: got %d want %d body=%s", listResp.Code, http.StatusOK, listResp.Body.String())
	}
	var listBody struct {
		Templates []Template `json:"templates"`
	}
	decodePolicyBody(t, listResp, &listBody)
	if len(listBody.Templates) != len(defaultSystemTemplateSeeds) {
		t.Fatalf("seeded system templates mismatch: got %d want %d", len(listBody.Templates), len(defaultSystemTemplateSeeds))
	}

	tplParams := map[string]any{
		"max_duration_minutes": 60,
		"require_approval":     true,
		"allow_auto_approve":   false,
		"require_reason":       true,
		"min_reason_length":    20,
		"max_requests_per_day": 20,
		"cool_down_minutes":    5,
		"single_use":           false,
		"notify_on_access":     true,
		"require_consent":      false,
	}

	createResp := doPolicyRequest(t, r, http.MethodPost, "/projects/00000000-0000-0000-0000-000000000201/policy-templates", "00000000-0000-0000-0000-000000000101", map[string]any{
		"name":        "Custom DB Strict",
		"description": "custom policy for db",
		"parameters":  tplParams,
	})
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create template status mismatch: got %d want %d body=%s", createResp.Code, http.StatusCreated, createResp.Body.String())
	}
	var createdTpl Template
	decodePolicyBody(t, createResp, &createdTpl)
	if createdTpl.CurrentVersion != 1 {
		t.Fatalf("created template version mismatch: got %d want 1", createdTpl.CurrentVersion)
	}

	memberCreateResp := doPolicyRequest(t, r, http.MethodPost, "/projects/00000000-0000-0000-0000-000000000201/policy-templates", "00000000-0000-0000-0000-000000000102", map[string]any{
		"name":        "Forbidden Create",
		"description": "member cannot create",
		"parameters":  tplParams,
	})
	if memberCreateResp.Code != http.StatusForbidden {
		t.Fatalf("member create template should be forbidden: got %d body=%s", memberCreateResp.Code, memberCreateResp.Body.String())
	}

	dupResp := doPolicyRequest(t, r, http.MethodPost, "/projects/00000000-0000-0000-0000-000000000201/policy-templates", "00000000-0000-0000-0000-000000000101", map[string]any{
		"name":        "Custom DB Strict",
		"description": "duplicate",
		"parameters":  tplParams,
	})
	if dupResp.Code != http.StatusConflict {
		t.Fatalf("duplicate template should return conflict: got %d body=%s", dupResp.Code, dupResp.Body.String())
	}

	updateResp := doPolicyRequest(t, r, http.MethodPut, "/policy-templates/"+createdTpl.ID, "00000000-0000-0000-0000-000000000101", map[string]any{
		"parameters": map[string]any{
			"max_duration_minutes": 30,
			"require_approval":     true,
			"allow_auto_approve":   false,
			"require_reason":       true,
			"min_reason_length":    20,
			"max_requests_per_day": 20,
			"cool_down_minutes":    5,
			"single_use":           false,
			"notify_on_access":     true,
			"require_consent":      false,
		},
		"change_note": "tighten duration",
	})
	if updateResp.Code != http.StatusOK {
		t.Fatalf("update template status mismatch: got %d want %d body=%s", updateResp.Code, http.StatusOK, updateResp.Body.String())
	}
	var updatedVersion TemplateVersion
	decodePolicyBody(t, updateResp, &updatedVersion)
	if updatedVersion.Version != 2 {
		t.Fatalf("updated template version mismatch: got %d want 2", updatedVersion.Version)
	}

	versionsResp := doPolicyRequest(t, r, http.MethodGet, "/policy-templates/"+createdTpl.ID+"/versions", "00000000-0000-0000-0000-000000000101", nil)
	if versionsResp.Code != http.StatusOK {
		t.Fatalf("list versions status mismatch: got %d want %d body=%s", versionsResp.Code, http.StatusOK, versionsResp.Body.String())
	}
	var versionsBody struct {
		Versions []TemplateVersion `json:"versions"`
	}
	decodePolicyBody(t, versionsResp, &versionsBody)
	if len(versionsBody.Versions) != 2 {
		t.Fatalf("template versions mismatch: got %d want 2", len(versionsBody.Versions))
	}
	if versionsBody.Versions[0].Version != 2 || versionsBody.Versions[1].Version != 1 {
		t.Fatalf("template versions order mismatch: got [%d,%d] want [2,1]", versionsBody.Versions[0].Version, versionsBody.Versions[1].Version)
	}

	cloneResp := doPolicyRequest(t, r, http.MethodPost, "/policy-templates/"+createdTpl.ID+"/clone", "00000000-0000-0000-0000-000000000101", map[string]any{"name": "Cloned DB Strict"})
	if cloneResp.Code != http.StatusCreated {
		t.Fatalf("clone template status mismatch: got %d want %d body=%s", cloneResp.Code, http.StatusCreated, cloneResp.Body.String())
	}

	bindingResp := doPolicyRequest(t, r, http.MethodPut, "/secrets/00000000-0000-0000-0000-000000000301/policy-binding", "00000000-0000-0000-0000-000000000101", map[string]any{
		"template_id":      createdTpl.ID,
		"template_version": updatedVersion.Version,
		"override_parameters": map[string]any{
			"max_duration_minutes": 120,
		},
	})
	if bindingResp.Code != http.StatusOK {
		t.Fatalf("update binding status mismatch: got %d want %d body=%s", bindingResp.Code, http.StatusOK, bindingResp.Body.String())
	}
	var binding SecretPolicyBinding
	decodePolicyBody(t, bindingResp, &binding)
	if binding.Template == nil || binding.Template.ID != createdTpl.ID {
		t.Fatalf("binding template mismatch: got %+v", binding.Template)
	}
	if binding.AppliedPolicySource != PolicySourceTemplateOverride {
		t.Fatalf("binding source mismatch: got %s want %s", binding.AppliedPolicySource, PolicySourceTemplateOverride)
	}
	if !containsWarning(binding.OverrideWarnings, "weaker:max_duration_minutes") {
		t.Fatalf("expected weaker:max_duration_minutes warning, got %v", binding.OverrideWarnings)
	}

	getBindingResp := doPolicyRequest(t, r, http.MethodGet, "/secrets/00000000-0000-0000-0000-000000000301/policy-binding", "00000000-0000-0000-0000-000000000101", nil)
	if getBindingResp.Code != http.StatusOK {
		t.Fatalf("get binding status mismatch: got %d want %d body=%s", getBindingResp.Code, http.StatusOK, getBindingResp.Body.String())
	}

	grantResp := doPolicyRequest(t, r, http.MethodPost, "/secrets/00000000-0000-0000-0000-000000000301/policy-agent-permissions", "00000000-0000-0000-0000-000000000101", map[string]any{
		"agent_id": "00000000-0000-0000-0000-000000000401",
	})
	if grantResp.Code != http.StatusCreated {
		t.Fatalf("grant permission status mismatch: got %d want %d body=%s", grantResp.Code, http.StatusCreated, grantResp.Body.String())
	}

	memberGrantResp := doPolicyRequest(t, r, http.MethodPost, "/secrets/00000000-0000-0000-0000-000000000301/policy-agent-permissions", "00000000-0000-0000-0000-000000000102", map[string]any{
		"agent_id": "00000000-0000-0000-0000-000000000401",
	})
	if memberGrantResp.Code != http.StatusForbidden {
		t.Fatalf("member grant permission should be forbidden: got %d body=%s", memberGrantResp.Code, memberGrantResp.Body.String())
	}

	revokeResp := doPolicyRequest(t, r, http.MethodDelete, "/secrets/00000000-0000-0000-0000-000000000301/policy-agent-permissions/00000000-0000-0000-0000-000000000401", "00000000-0000-0000-0000-000000000101", nil)
	if revokeResp.Code != http.StatusNoContent {
		t.Fatalf("revoke permission status mismatch: got %d want %d body=%s", revokeResp.Code, http.StatusNoContent, revokeResp.Body.String())
	}

	revokeAgainResp := doPolicyRequest(t, r, http.MethodDelete, "/secrets/00000000-0000-0000-0000-000000000301/policy-agent-permissions/00000000-0000-0000-0000-000000000401", "00000000-0000-0000-0000-000000000101", nil)
	if revokeAgainResp.Code != http.StatusNotFound {
		t.Fatalf("second revoke should be not_found: got %d body=%s", revokeAgainResp.Code, revokeAgainResp.Body.String())
	}
}

func containsWarning(warnings []string, expected string) bool {
	for _, warning := range warnings {
		if warning == expected {
			return true
		}
	}
	return false
}

func doPolicyRequest(t *testing.T, handler http.Handler, method, path, userID string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body failed: %v", err)
		}
	}

	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	req = req.WithContext(auth.WithUserID(req.Context(), userID))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodePolicyBody(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("decode response failed: %v body=%s", err, rec.Body.String())
	}
}

func seedPolicyIntegrationData(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()

	stmts := []struct {
		query string
		args  []any
	}{
		{query: `INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)`, args: []any{"00000000-0000-0000-0000-000000000101", "owner@example.com", "hash"}},
		{query: `INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)`, args: []any{"00000000-0000-0000-0000-000000000102", "member@example.com", "hash"}},
		{query: `INSERT INTO organizations (id, name, slug, owner_id, plan) VALUES ($1, $2, $3, $4, $5)`, args: []any{"00000000-0000-0000-0000-000000000401", "Org", "org-it", "00000000-0000-0000-0000-000000000101", "free"}},
		{query: `INSERT INTO workspaces (id, org_id, name, slug) VALUES ($1, $2, $3, $4)`, args: []any{"00000000-0000-0000-0000-000000000501", "00000000-0000-0000-0000-000000000401", "Workspace", "workspace-it"}},
		{query: `INSERT INTO projects (id, workspace_id, name, slug) VALUES ($1, $2, $3, $4)`, args: []any{"00000000-0000-0000-0000-000000000201", "00000000-0000-0000-0000-000000000501", "Project", "project-it"}},
		{query: `INSERT INTO project_memberships (project_id, user_id, role) VALUES ($1, $2, $3)`, args: []any{"00000000-0000-0000-0000-000000000201", "00000000-0000-0000-0000-000000000101", "owner"}},
		{query: `INSERT INTO project_memberships (project_id, user_id, role) VALUES ($1, $2, $3)`, args: []any{"00000000-0000-0000-0000-000000000201", "00000000-0000-0000-0000-000000000102", "member"}},
		{query: `INSERT INTO secrets (id, user_id, name, description, storage_key, encrypted_dek, policy, credential_type, source, version, project_id) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11)`, args: []any{"00000000-0000-0000-0000-000000000301", "00000000-0000-0000-0000-000000000101", "db-pass", "", "k1", []byte{1, 2, 3}, `{}`, "db_credential", "", 1, "00000000-0000-0000-0000-000000000201"}},
		{query: `INSERT INTO agent_identities (id, project_id, name, description, agent_type, auth_method, allowed_scopes, max_session_ttl, status, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, args: []any{"00000000-0000-0000-0000-000000000401", "00000000-0000-0000-0000-000000000201", "agent-one", "", "custom", "token", []string{"read"}, 3600, "active", "00000000-0000-0000-0000-000000000101"}},
	}

	for _, stmt := range stmts {
		if _, err := pool.Exec(ctx, stmt.query, stmt.args...); err != nil {
			t.Fatalf("seed statement failed: %v\nquery=%s", err, stmt.query)
		}
	}
}

func newPolicyIntegrationDB(t *testing.T, ctx context.Context) (*pgxpool.Pool, func()) {
	t.Helper()

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL is required for policy phase01 integration tests")
	}

	schemaName := fmt.Sprintf("it_policy_%d_%d", time.Now().UnixNano(), rand.Intn(100000))

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

	if err := applyAllMigrations(ctx, pool); err != nil {
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

func applyAllMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	return testutil.ApplyMigrations(ctx, pool)
}
