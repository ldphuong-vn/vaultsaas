package consent

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/valt-dev/valt/server/internal/audit"
	"github.com/valt-dev/valt/server/internal/auth"
	"github.com/valt-dev/valt/server/pkg/apierror"
)

// Handler serves consent endpoints.
type Handler struct {
	service *Service
}

// NewHandler creates a consent Handler.
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// Routes returns the consent router.
func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Post("/", h.recordConsent)
	return r
}

type consentRequest struct {
	SecretID       string `json:"secret_id"`
	CredentialType string `json:"credential_type"`
	ConsentType    string `json:"consent_type"`
	Granted        bool   `json:"granted"`
}

var validConsentTypes = map[string]bool{
	"access_grant":        true,
	"risk_acknowledgment": true,
}

func (h *Handler) recordConsent(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())

	var req consentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest(w, "invalid request body")
		return
	}

	if req.SecretID == "" || req.ConsentType == "" || req.CredentialType == "" {
		apierror.BadRequest(w, "secret_id, credential_type, and consent_type are required")
		return
	}

	if !validConsentTypes[req.ConsentType] {
		apierror.BadRequest(w, "invalid consent_type")
		return
	}

	input := ConsentInput{
		UserID:         userID,
		SecretID:       req.SecretID,
		CredentialType: req.CredentialType,
		ConsentType:    req.ConsentType,
		Granted:        req.Granted,
		IPAddress:      audit.ExtractIP(r),
		UserAgent:      r.UserAgent(),
	}

	if err := h.service.RecordConsent(r.Context(), input); err != nil {
		log.Printf("Failed to record consent: %v", err)
		apierror.InternalError(w, "failed to record consent")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "recorded"})
}

