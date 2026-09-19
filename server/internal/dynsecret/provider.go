package dynsecret

import (
	"context"
	"time"
)

// ProviderResponse is a safe, redacted view of a provider for API responses.
// It omits config_enc / decrypted config fields containing admin credentials.
type ProviderResponse struct {
	ID           string    `json:"id"`
	ProjectID    string    `json:"project_id"`
	Name         string    `json:"name"`
	ProviderType string    `json:"provider_type"`
	Status       string    `json:"status"`
}

// ToResponse returns a redacted ProviderResponse safe for API consumers.
func (pc *ProviderConfig) ToResponse() ProviderResponse {
	return ProviderResponse{
		ID:           pc.ID,
		ProjectID:    pc.ProjectID,
		Name:         pc.Name,
		ProviderType: pc.ProviderType,
		Status:       pc.Status,
	}
}

// LeaseRequest is the input to Provider.Create.
type LeaseRequest struct {
	TTL       time.Duration
	AgentID   string
	RequestID string
	Metadata  map[string]string
}

// Lease is the output of Provider.Create.
type Lease struct {
	ID          string
	Credentials map[string]string // e.g. {"username": "...", "password": "...", "host": "..."}
	KeyHash     string            // lookup hash for verifiable credentials (derived API keys); empty for providers that provision real backends
	ExpiresAt   time.Time
	ProviderID  string
}

// Provider defines the interface for dynamic secret backends.
type Provider interface {
	Type() string
	Create(ctx context.Context, req LeaseRequest) (*Lease, error)
	Revoke(ctx context.Context, leaseID string) error
	Renew(ctx context.Context, leaseID string, ttl time.Duration) (*Lease, error)
}

// ProviderConfig holds decrypted provider configuration.
type ProviderConfig struct {
	ID           string
	ProjectID    string
	Name         string
	ProviderType string
	Config       map[string]string // decrypted config
	Status       string
}

// LeaseInfo is a read-only view of a stored lease.
type LeaseInfo struct {
	ID               string     `json:"id"`
	ProviderID       string     `json:"provider_id"`
	AgentID          *string    `json:"agent_id,omitempty"`
	AccessRequestID  *string    `json:"access_request_id,omitempty"`
	TTLSeconds       int        `json:"ttl_seconds"`
	ExpiresAt        time.Time  `json:"expires_at"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}
