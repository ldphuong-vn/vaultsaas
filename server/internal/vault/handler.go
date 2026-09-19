package vault

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/valt-dev/valt/server/internal/agent"
	"github.com/valt-dev/valt/server/internal/auth"
	"github.com/valt-dev/valt/server/internal/policy"
	"github.com/valt-dev/valt/server/pkg/apierror"
	"github.com/valt-dev/valt/server/pkg/crypto"
	"github.com/valt-dev/valt/server/pkg/validator"
)

var validCredentialTypes = map[string]bool{
	"api_key":          true,
	"db_credential":    true,
	"ssh_key":          true,
	"oauth_token":      true,
	"cloud_credential": true,
	"personal_session": true,
}

type Handler struct {
	service   *Service
	masterKey []byte
}

func NewHandler(service *Service, masterKey []byte) *Handler {
	return &Handler{service: service, masterKey: masterKey}
}

func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Post("/", h.CreateSecret)
	r.Get("/", h.ListSecrets)
	r.Get("/{id}", h.GetSecret)
	r.Put("/{id}", h.UpdateSecret)
	r.Delete("/{id}", h.DeleteSecret)
	r.Put("/{id}/dynamic-provider", h.SetDynamicProvider)
	r.Delete("/{id}/dynamic-provider", h.SetDynamicProvider)
	return r
}

type createSecretRequest struct {
	Name           string `json:"name"`
	Description    string `json:"description"`
	CredentialType string `json:"credential_type"`
	Source         string `json:"source"`
	ProjectID      string `json:"project_id"`
	Value          string `json:"value"`          // plaintext (server encrypts)
	EncryptedBlob  string `json:"encrypted_blob"` // base64 (pre-encrypted, backward compat)
	EncryptedDEK   string `json:"encrypted_dek"`  // base64 (pre-encrypted, backward compat)
	Policy         string `json:"policy"`
}

func (h *Handler) CreateSecret(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())

	var req createSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest(w, "invalid request body")
		return
	}

	if req.Name == "" {
		apierror.BadRequest(w, "name is required")
		return
	}

	if req.CredentialType != "" && !validCredentialTypes[req.CredentialType] {
		apierror.BadRequest(w, "invalid credential_type")
		return
	}

	if req.ProjectID != "" {
		if _, err := validator.ValidateUUID(req.ProjectID); err != nil {
			apierror.BadRequest(w, "invalid project_id")
			return
		}
		// Verify caller is a member of the target project
		isMember, err := h.service.IsProjectMember(r.Context(), req.ProjectID, userID)
		if err != nil {
			log.Printf("Failed to check project membership: %v", err)
			apierror.InternalError(w, "failed to verify project membership")
			return
		}
		if !isMember {
			apierror.Forbidden(w, "not a member of this project")
			return
		}
	}

	var blob, dek []byte

	if req.Value != "" {
		// Server-side envelope encryption path
		rawDEK, err := crypto.GenerateDEK()
		if err != nil {
			log.Printf("Failed to generate DEK: %v", err)
			apierror.InternalError(w, "failed to generate encryption key")
			return
		}
		blob, err = crypto.EncryptAES256GCM(rawDEK, []byte(req.Value))
		if err != nil {
			log.Printf("Failed to encrypt value: %v", err)
			apierror.InternalError(w, "failed to encrypt secret value")
			return
		}
		dek, err = crypto.EncryptAES256GCM(h.masterKey, rawDEK)
		if err != nil {
			log.Printf("Failed to wrap DEK: %v", err)
			apierror.InternalError(w, "failed to wrap encryption key")
			return
		}
		// Zero out rawDEK (best-effort)
		for i := range rawDEK {
			rawDEK[i] = 0
		}
	} else if req.EncryptedBlob != "" {
		// Pre-encrypted path (backward compat / future client-side encryption)
		var err error
		blob, err = base64.StdEncoding.DecodeString(req.EncryptedBlob)
		if err != nil {
			apierror.BadRequest(w, "invalid encrypted_blob encoding")
			return
		}
		dek, err = base64.StdEncoding.DecodeString(req.EncryptedDEK)
		if err != nil {
			apierror.BadRequest(w, "invalid encrypted_dek encoding")
			return
		}
	} else {
		apierror.BadRequest(w, "value or encrypted_blob is required")
		return
	}

	secret, err := h.service.CreateSecret(r.Context(), userID, CreateSecretInput{
		Name:           req.Name,
		Description:    req.Description,
		CredentialType: req.CredentialType,
		Source:         req.Source,
		ProjectID:      req.ProjectID,
		EncryptedBlob:  blob,
		EncryptedDEK:   dek,
		Policy:         req.Policy,
	})
	if err != nil {
		log.Printf("Failed to create secret: %v", err)
		apierror.InternalError(w, "failed to create secret")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(secret)
}

func (h *Handler) ListSecrets(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	agentID := agent.AgentIDFromContext(r.Context())

	if userID == "" && agentID == "" {
		apierror.Unauthorized(w, "authentication required")
		return
	}

	pg, err := validator.ValidatePagination(
		r.URL.Query().Get("page"),
		r.URL.Query().Get("limit"),
	)
	if err != nil {
		apierror.BadRequest(w, err.Error())
		return
	}

	var result *ListResult
	if agentID != "" {
		// Agent path: list secrets from agent's accessible projects
		result, err = h.service.ListSecretsForAgent(r.Context(), agentID, pg.Page, pg.Limit, pg.Offset)
	} else {
		// User path: list owned secrets
		result, err = h.service.ListSecrets(r.Context(), userID, pg.Page, pg.Limit, pg.Offset)
	}

	if err != nil {
		log.Printf("Failed to list secrets: %v", err)
		apierror.InternalError(w, "failed to list secrets")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) GetSecret(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	agentID := agent.AgentIDFromContext(r.Context())

	if userID == "" && agentID == "" {
		apierror.Unauthorized(w, "authentication required")
		return
	}

	secretID := chi.URLParam(r, "id")

	if _, err := validator.ValidateUUID(secretID); err != nil {
		apierror.BadRequest(w, "invalid secret ID")
		return
	}

	var secret *Secret
	var err error

	if agentID != "" {
		// Agent path: get secret from accessible projects
		secret, err = h.service.GetSecretForAgent(r.Context(), agentID, secretID)
	} else {
		// User path: get owned secret
		secret, err = h.service.GetSecret(r.Context(), userID, secretID)
	}

	if err != nil {
		log.Printf("Failed to get secret: %v", err)
		apierror.InternalError(w, "failed to get secret")
		return
	}
	if secret == nil {
		apierror.NotFound(w, "secret not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(secret)
}

type updateSecretRequest struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	Value         string `json:"value"`          // plaintext (server encrypts)
	EncryptedBlob string `json:"encrypted_blob"` // base64 (pre-encrypted)
	EncryptedDEK  string `json:"encrypted_dek"`  // base64 (pre-encrypted)
}

func (h *Handler) UpdateSecret(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	secretID := chi.URLParam(r, "id")

	if _, err := validator.ValidateUUID(secretID); err != nil {
		apierror.BadRequest(w, "invalid secret ID")
		return
	}

	var req updateSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest(w, "invalid request body")
		return
	}

	var blob, dek []byte
	if req.Value != "" {
		// Server-side envelope encryption path
		rawDEK, err := crypto.GenerateDEK()
		if err != nil {
			log.Printf("Failed to generate DEK for update: %v", err)
			apierror.InternalError(w, "failed to generate encryption key")
			return
		}
		blob, err = crypto.EncryptAES256GCM(rawDEK, []byte(req.Value))
		if err != nil {
			log.Printf("Failed to encrypt value for update: %v", err)
			apierror.InternalError(w, "failed to encrypt secret value")
			return
		}
		dek, err = crypto.EncryptAES256GCM(h.masterKey, rawDEK)
		if err != nil {
			log.Printf("Failed to wrap DEK for update: %v", err)
			apierror.InternalError(w, "failed to wrap encryption key")
			return
		}
		for i := range rawDEK {
			rawDEK[i] = 0
		}
	} else {
		if req.EncryptedBlob != "" {
			var err error
			blob, err = base64.StdEncoding.DecodeString(req.EncryptedBlob)
			if err != nil {
				apierror.BadRequest(w, "invalid encrypted_blob encoding")
				return
			}
		}
		if req.EncryptedDEK != "" {
			var err error
			dek, err = base64.StdEncoding.DecodeString(req.EncryptedDEK)
			if err != nil {
				apierror.BadRequest(w, "invalid encrypted_dek encoding")
				return
			}
		}
	}

	secret, err := h.service.UpdateSecret(r.Context(), userID, secretID, UpdateSecretInput{
		Name:          req.Name,
		Description:   req.Description,
		EncryptedBlob: blob,
		EncryptedDEK:  dek,
	})
	if err != nil {
		log.Printf("Failed to update secret: %v", err)
		apierror.InternalError(w, "failed to update secret")
		return
	}
	if secret == nil {
		apierror.NotFound(w, "secret not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(secret)
}

type setDynamicProviderRequest struct {
	ProviderID *string `json:"provider_id"` // null/absent = unlink
}

// SetDynamicProvider handles PUT/DELETE /{id}/dynamic-provider.
// PUT links a dynamic provider (body: {"provider_id": "..."}); DELETE unlinks.
// Once linked, approvals for this secret mint short-lived leases from the
// provider instead of returning the static secret value.
func (h *Handler) SetDynamicProvider(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	secretID := chi.URLParam(r, "id")

	if _, err := validator.ValidateUUID(secretID); err != nil {
		apierror.BadRequest(w, "invalid secret ID")
		return
	}

	var providerID *string
	if r.Method == http.MethodPut {
		var req setDynamicProviderRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			apierror.BadRequest(w, "invalid request body")
			return
		}
		if req.ProviderID == nil || *req.ProviderID == "" {
			apierror.BadRequest(w, "provider_id is required")
			return
		}
		if _, err := validator.ValidateUUID(*req.ProviderID); err != nil {
			apierror.BadRequest(w, "invalid provider_id")
			return
		}
		providerID = req.ProviderID
	}

	secret, err := h.service.SetDynamicProvider(r.Context(), secretID, userID, providerID)
	if err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "not authorized"):
			apierror.Forbidden(w, msg)
		case strings.Contains(msg, "not found") || strings.Contains(msg, "different project") || strings.Contains(msg, "not active"):
			apierror.BadRequest(w, msg)
		default:
			log.Printf("Failed to set dynamic provider for secret %s: %v", secretID, err)
			apierror.InternalError(w, "failed to set dynamic provider")
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(secret) //nolint:errcheck
}

func (h *Handler) DeleteSecret(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	secretID := chi.URLParam(r, "id")

	if _, err := validator.ValidateUUID(secretID); err != nil {
		apierror.BadRequest(w, "invalid secret ID")
		return
	}

	err := h.service.DeleteSecret(r.Context(), userID, secretID)
	if err != nil {
		if err == pgx.ErrNoRows {
			apierror.NotFound(w, "secret not found")
			return
		}
		log.Printf("Failed to delete secret: %v", err)
		apierror.InternalError(w, "failed to delete secret")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetSecretPolicy handles GET /secrets/{id}/policy
func (h *Handler) GetSecretPolicy(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	secretID := chi.URLParam(r, "id")
	if _, err := validator.ValidateUUID(secretID); err != nil {
		apierror.BadRequest(w, "invalid secret_id")
		return
	}
	policyJSON, err := h.service.GetPolicy(r.Context(), secretID, userID)
	if err != nil {
		apierror.NotFound(w, "secret not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(policyJSON) //nolint:errcheck
}

// PutSecretPolicy handles PUT /secrets/{id}/policy
func (h *Handler) PutSecretPolicy(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	secretID := chi.URLParam(r, "id")
	if _, err := validator.ValidateUUID(secretID); err != nil {
		apierror.BadRequest(w, "invalid secret_id")
		return
	}
	var cp policy.CustomPolicy
	if err := json.NewDecoder(r.Body).Decode(&cp); err != nil {
		apierror.BadRequest(w, "invalid policy body")
		return
	}
	if err := cp.Validate(); err != nil {
		apierror.BadRequest(w, err.Error())
		return
	}
	policyJSON, _ := json.Marshal(cp)
	if err := h.service.SetPolicy(r.Context(), secretID, userID, policyJSON); err != nil {
		apierror.NotFound(w, "secret not found or not authorized")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(policyJSON) //nolint:errcheck
}
