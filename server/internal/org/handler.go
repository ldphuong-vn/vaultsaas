package org

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/valt-dev/valt/server/internal/auth"
	"github.com/valt-dev/valt/server/pkg/apierror"
)

// EmailSender sends transactional emails (nil disables email delivery).
type EmailSender interface {
	Send(ctx context.Context, to, subject, body string) error
}

type Handler struct {
	service      *Service
	emailSender  EmailSender
	dashboardURL string
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// SetEmailSender configures the email sender for invitation emails.
func (h *Handler) SetEmailSender(s EmailSender, dashboardURL string) {
	h.emailSender = s
	h.dashboardURL = dashboardURL
}

func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Post("/", h.createOrg)
	r.Get("/", h.listOrgs)
	r.Get("/{org_id}", h.getOrg)
	r.Put("/{org_id}", h.updateOrg)
	r.Post("/{org_id}/members", h.addMember)
	r.Get("/{org_id}/members", h.listMembers)
	r.Delete("/{org_id}/members/{user_id}", h.removeMember)
	r.Post("/{org_id}/invitations", h.createInvitation)
	r.Get("/{org_id}/invitations", h.listInvitations)
	r.Delete("/{org_id}/invitations/{invitation_id}", h.cancelInvitation)
	return r
}

// AcceptInvitation is the public endpoint (mounted under /auth).
func (h *Handler) AcceptInvitation(w http.ResponseWriter, r *http.Request) {
	h.acceptInvitation(w, r)
}

type createOrgRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

func (h *Handler) createOrg(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())

	var req createOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest(w, "invalid request body")
		return
	}
	if req.Name == "" {
		apierror.BadRequest(w, "name is required")
		return
	}
	if req.Slug == "" {
		apierror.BadRequest(w, "slug is required")
		return
	}

	o, err := h.service.Create(r.Context(), req.Name, req.Slug, userID)
	if err != nil {
		log.Printf("Failed to create org: %v", err)
		apierror.InternalError(w, "failed to create org")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(o) //nolint:errcheck
}

func (h *Handler) listOrgs(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())

	orgs, err := h.service.ListByUser(r.Context(), userID)
	if err != nil {
		log.Printf("Failed to list orgs: %v", err)
		apierror.InternalError(w, "failed to list orgs")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(orgs) //nolint:errcheck
}

func (h *Handler) getOrg(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "org_id")

	o, err := h.service.Get(r.Context(), orgID)
	if err != nil {
		log.Printf("Failed to get org: %v", err)
		apierror.InternalError(w, "failed to get org")
		return
	}
	if o == nil {
		apierror.NotFound(w, "org not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(o) //nolint:errcheck
}

type updateOrgRequest struct {
	Name string `json:"name"`
}

func (h *Handler) updateOrg(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "org_id")

	var req updateOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest(w, "invalid request body")
		return
	}
	if req.Name == "" {
		apierror.BadRequest(w, "name is required")
		return
	}

	err := h.service.UpdateName(r.Context(), orgID, req.Name)
	if err != nil {
		log.Printf("Failed to update org: %v", err)
		apierror.InternalError(w, "failed to update org")
		return
	}

	o, _ := h.service.Get(r.Context(), orgID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(o)
}

type addMemberRequest struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

func (h *Handler) addMember(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "org_id")

	var req addMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest(w, "invalid request body")
		return
	}
	if req.UserID == "" {
		apierror.BadRequest(w, "user_id is required")
		return
	}
	if req.Role == "" {
		apierror.BadRequest(w, "role is required")
		return
	}

	m, err := h.service.AddMember(r.Context(), orgID, req.UserID, req.Role)
	if err != nil {
		log.Printf("Failed to add org member: %v", err)
		apierror.InternalError(w, "failed to add member")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(m) //nolint:errcheck
}

// removeMember handles DELETE /orgs/{org_id}/members/{user_id}.
// Only org owners/admins may remove members; the org owner cannot be removed.
// The removed member's project memberships inside the org cascade away.
func (h *Handler) removeMember(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "org_id")
	targetUserID := chi.URLParam(r, "user_id")
	callerID := auth.UserIDFromContext(r.Context())

	ok, err := callerIsAdminOrOwner(r.Context(), h.service, orgID, callerID)
	if err != nil {
		log.Printf("Failed to check org role for member removal: %v", err)
		apierror.InternalError(w, "failed to remove member")
		return
	}
	if !ok {
		apierror.Forbidden(w, "org admin access required")
		return
	}

	err = h.service.RemoveMember(r.Context(), orgID, targetUserID)
	switch {
	case err == nil:
		// fall through to 204
	case errors.Is(err, ErrOrgNotFound):
		apierror.NotFound(w, "org not found")
		return
	case errors.Is(err, ErrRemoveOwner):
		apierror.BadRequest(w, "cannot remove the org owner")
		return
	case errors.Is(err, ErrMemberNotFound):
		apierror.NotFound(w, "member not found")
		return
	default:
		log.Printf("Failed to remove org member: %v", err)
		apierror.InternalError(w, "failed to remove member")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listMembers(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "org_id")

	members, err := h.service.ListMembers(r.Context(), orgID)
	if err != nil {
		log.Printf("Failed to list org members: %v", err)
		apierror.InternalError(w, "failed to list members")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(members) //nolint:errcheck
}
