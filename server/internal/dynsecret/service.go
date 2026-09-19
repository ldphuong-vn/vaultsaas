package dynsecret

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/valt-dev/valt/server/pkg/crypto"
)

// Service manages dynamic secret providers and leases.
type Service struct {
	db        *pgxpool.Pool
	masterKey []byte
}

// NewService creates a new Service.
func NewService(db *pgxpool.Pool, masterKey []byte) *Service {
	return &Service{db: db, masterKey: masterKey}
}

// CreateProvider persists a new provider config.
func (s *Service) CreateProvider(ctx context.Context, projectID, name, providerType string, config map[string]string, userID string) (*ProviderConfig, error) {
	raw, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	enc, err := crypto.EncryptAES256GCM(s.masterKey, raw)
	if err != nil {
		return nil, fmt.Errorf("encrypt config: %w", err)
	}
	var pc ProviderConfig
	err = s.db.QueryRow(ctx, `
		INSERT INTO dynamic_providers (project_id, name, provider_type, config_enc, created_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, project_id, name, provider_type, status`,
		projectID, name, providerType, enc, userID,
	).Scan(&pc.ID, &pc.ProjectID, &pc.Name, &pc.ProviderType, &pc.Status)
	if err != nil {
		return nil, fmt.Errorf("insert provider: %w", err)
	}
	pc.Config = config
	return &pc, nil
}

// ListProviders returns all providers for a project.
func (s *Service) ListProviders(ctx context.Context, projectID string) ([]ProviderConfig, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, project_id, name, provider_type, config_enc, status
		FROM dynamic_providers WHERE project_id = $1 ORDER BY created_at DESC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ProviderConfig
	for rows.Next() {
		var pc ProviderConfig
		var raw []byte
		if err := rows.Scan(&pc.ID, &pc.ProjectID, &pc.Name, &pc.ProviderType, &raw, &pc.Status); err != nil {
			return nil, err
		}
		decrypted, decErr := crypto.DecryptAES256GCM(s.masterKey, raw)
		if decErr != nil {
			// Fallback: try plaintext JSON (pre-migration row)
			if jsonErr := json.Unmarshal(raw, &pc.Config); jsonErr != nil {
				log.Printf("Warning: failed to decrypt or parse provider config for ID %s: decrypt=%v json=%v", pc.ID, decErr, jsonErr)
				// Continue with empty config rather than aborting entire list
			}
		} else {
			_ = json.Unmarshal(decrypted, &pc.Config)
		}
		out = append(out, pc)
	}
	return out, rows.Err()
}

// GetProvider returns a single provider by ID.
func (s *Service) GetProvider(ctx context.Context, id string) (*ProviderConfig, error) {
	var pc ProviderConfig
	var raw []byte
	err := s.db.QueryRow(ctx, `
		SELECT id, project_id, name, provider_type, config_enc, status
		FROM dynamic_providers WHERE id = $1`, id,
	).Scan(&pc.ID, &pc.ProjectID, &pc.Name, &pc.ProviderType, &raw, &pc.Status)
	if err != nil {
		return nil, err
	}
	decrypted, decErr := crypto.DecryptAES256GCM(s.masterKey, raw)
	if decErr != nil {
		// Fallback: try plaintext JSON (pre-migration row)
		if jsonErr := json.Unmarshal(raw, &pc.Config); jsonErr != nil {
			log.Printf("Warning: failed to decrypt or parse provider config for ID %s: decrypt=%v json=%v", pc.ID, decErr, jsonErr)
			return nil, fmt.Errorf("corrupted provider config")
		}
	} else {
		_ = json.Unmarshal(decrypted, &pc.Config)
	}
	return &pc, nil
}

// newProviderInstance instantiates the correct Provider implementation.
func newProviderInstance(pc *ProviderConfig) (Provider, error) {
	switch pc.ProviderType {
	case "postgres":
		return &PostgresProvider{config: *pc}, nil
	case "derived_api_key":
		return &DerivedKeyProvider{config: *pc}, nil
	default:
		return nil, fmt.Errorf("unknown provider type: %s", pc.ProviderType)
	}
}

// CreateLease generates credentials from a provider and persists the lease.
// TODO: encrypt secret_data_enc with project key.
func (s *Service) CreateLease(ctx context.Context, providerID, agentID, requestID string, ttlSeconds int) (*Lease, error) {
	pc, err := s.GetProvider(ctx, providerID)
	if err != nil {
		return nil, fmt.Errorf("provider not found: %w", err)
	}
	prov, err := newProviderInstance(pc)
	if err != nil {
		return nil, err
	}

	ttl := time.Duration(ttlSeconds) * time.Second
	lease, err := prov.Create(ctx, LeaseRequest{TTL: ttl, AgentID: agentID, RequestID: requestID})
	if err != nil {
		return nil, fmt.Errorf("provider create: %w", err)
	}

	credBytes, err := json.Marshal(lease.Credentials)
	if err != nil {
		return nil, err
	}
	encCreds, err := crypto.EncryptAES256GCM(s.masterKey, credBytes)
	if err != nil {
		return nil, fmt.Errorf("encrypt credentials: %w", err)
	}

	var agentIDPtr, reqIDPtr *string
	if agentID != "" {
		agentIDPtr = &agentID
	}
	if requestID != "" {
		reqIDPtr = &requestID
	}

	err = s.db.QueryRow(ctx, `
		INSERT INTO dynamic_leases (provider_id, agent_id, access_request_id, secret_data_enc, key_hash, ttl_seconds, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		providerID, agentIDPtr, reqIDPtr, encCreds, lease.KeyHash, ttlSeconds, lease.ExpiresAt,
	).Scan(&lease.ID)
	if err != nil {
		return nil, fmt.Errorf("insert lease: %w", err)
	}
	lease.ProviderID = providerID
	return lease, nil
}

// RevokeLease marks a lease revoked and drops the backend credential.
func (s *Service) RevokeLease(ctx context.Context, leaseID string) error {
	var providerID string
	var credRaw []byte
	err := s.db.QueryRow(ctx, `
		SELECT provider_id, secret_data_enc FROM dynamic_leases
		WHERE id = $1 AND revoked_at IS NULL`, leaseID,
	).Scan(&providerID, &credRaw)
	if err != nil {
		return fmt.Errorf("lease not found: %w", err)
	}

	var creds map[string]string
	decCreds, decErr := crypto.DecryptAES256GCM(s.masterKey, credRaw)
	if decErr != nil {
		if jsonErr := json.Unmarshal(credRaw, &creds); jsonErr != nil {
			log.Printf("Warning: failed to decrypt or parse lease credentials for lease %s: %v", leaseID, jsonErr)
			return fmt.Errorf("corrupted lease credentials")
		}
	} else {
		_ = json.Unmarshal(decCreds, &creds)
	}

	_, err = s.db.Exec(ctx, `UPDATE dynamic_leases SET revoked_at = now() WHERE id = $1`, leaseID)
	if err != nil {
		return err
	}

	// Best-effort backend revocation using username as identifier
	if username, ok := creds["username"]; ok {
		pc, pcErr := s.GetProvider(ctx, providerID)
		if pcErr == nil {
			prov, provErr := newProviderInstance(pc)
			if provErr == nil {
				_ = prov.Revoke(ctx, username)
			}
		}
	}
	return nil
}

// ListActiveLeases returns non-revoked leases for a provider.
func (s *Service) ListActiveLeases(ctx context.Context, providerID string) ([]LeaseInfo, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, provider_id, agent_id, access_request_id, ttl_seconds, expires_at, revoked_at, created_at
		FROM dynamic_leases WHERE provider_id = $1 AND revoked_at IS NULL
		ORDER BY created_at DESC`, providerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []LeaseInfo
	for rows.Next() {
		var li LeaseInfo
		if err := rows.Scan(&li.ID, &li.ProviderID, &li.AgentID, &li.AccessRequestID,
			&li.TTLSeconds, &li.ExpiresAt, &li.RevokedAt, &li.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, li)
	}
	return out, rows.Err()
}

// GetLeaseProviderID returns the provider_id for a given lease.
func (s *Service) GetLeaseProviderID(ctx context.Context, leaseID string) (string, error) {
	var providerID string
	err := s.db.QueryRow(ctx, `SELECT provider_id FROM dynamic_leases WHERE id = $1`, leaseID).Scan(&providerID)
	return providerID, err
}

// ValidateDerivedKey resolves a presented derived API key to its active lease.
// Returns nil when the key is unknown, revoked, expired, or its provider was
// disabled — callers must treat a nil lease as "access denied".
func (s *Service) ValidateDerivedKey(ctx context.Context, rawKey string) (*LeaseInfo, error) {
	if rawKey == "" {
		return nil, nil
	}
	var li LeaseInfo
	err := s.db.QueryRow(ctx, `
		SELECT l.id, l.provider_id, l.agent_id, l.access_request_id, l.ttl_seconds, l.expires_at, l.revoked_at, l.created_at
		FROM dynamic_leases l
		JOIN dynamic_providers p ON p.id = l.provider_id AND p.status = 'active'
		WHERE l.key_hash = $1`, hashDerivedKey(rawKey),
	).Scan(&li.ID, &li.ProviderID, &li.AgentID, &li.AccessRequestID, &li.TTLSeconds, &li.ExpiresAt, &li.RevokedAt, &li.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if li.RevokedAt != nil || time.Now().After(li.ExpiresAt) {
		return nil, nil
	}
	return &li, nil
}

// GetActiveLease returns lease info only when the lease is still live
// (exists, not revoked, not expired). nil otherwise.
func (s *Service) GetActiveLease(ctx context.Context, leaseID string) (*LeaseInfo, error) {
	var li LeaseInfo
	err := s.db.QueryRow(ctx, `
		SELECT id, provider_id, agent_id, access_request_id, ttl_seconds, expires_at, revoked_at, created_at
		FROM dynamic_leases WHERE id = $1`, leaseID,
	).Scan(&li.ID, &li.ProviderID, &li.AgentID, &li.AccessRequestID, &li.TTLSeconds, &li.ExpiresAt, &li.RevokedAt, &li.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if li.RevokedAt != nil || time.Now().After(li.ExpiresAt) {
		return nil, nil
	}
	return &li, nil
}

// GetLeaseCredentials decrypts and returns the credentials stored on a lease.
func (s *Service) GetLeaseCredentials(ctx context.Context, leaseID string) (map[string]string, error) {
	var credRaw []byte
	err := s.db.QueryRow(ctx,
		`SELECT secret_data_enc FROM dynamic_leases WHERE id = $1`, leaseID,
	).Scan(&credRaw)
	if err != nil {
		return nil, fmt.Errorf("lease not found: %w", err)
	}

	var creds map[string]string
	decCreds, decErr := crypto.DecryptAES256GCM(s.masterKey, credRaw)
	if decErr != nil {
		if jsonErr := json.Unmarshal(credRaw, &creds); jsonErr != nil {
			return nil, fmt.Errorf("corrupted lease credentials")
		}
	} else if err := json.Unmarshal(decCreds, &creds); err != nil {
		return nil, fmt.Errorf("parse lease credentials: %w", err)
	}
	return creds, nil
}

// StartExpiryWorker runs a background goroutine that every 60s marks expired
// leases revoked and sweeps backend credentials (e.g. drops leftover Postgres
// temp roles) for leases that expired a while ago.
func (s *Service) StartExpiryWorker(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_, _ = s.db.Exec(ctx,
					`UPDATE dynamic_leases SET revoked_at = now() WHERE expires_at < now() AND revoked_at IS NULL`)
				if swept, err := s.SweepExpiredBackends(ctx); err != nil {
					log.Printf("dynsecret sweeper: %v", err)
				} else if swept > 0 {
					log.Printf("dynsecret sweeper: cleaned up %d expired lease backends", swept)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// RevokeLeasesForUser revokes every active lease belonging to a user: leases
// minted from the user's own access requests, and leases bound to agents the
// user created. Postgres backend roles are dropped best-effort immediately —
// the sweeper stays as the fallback for anything that fails. Returns the
// number of leases revoked. Part of the week 9-10 revoke cascade.
func (s *Service) RevokeLeasesForUser(ctx context.Context, userID string) (int, error) {
	rows, err := s.db.Query(ctx, `
		SELECT l.id, l.secret_data_enc, p.provider_type, p.config_enc
		FROM dynamic_leases l
		JOIN dynamic_providers p ON p.id = l.provider_id
		WHERE l.revoked_at IS NULL
		  AND (
		    l.access_request_id IN (SELECT id FROM access_requests WHERE requester_user_id = $1)
		    OR l.agent_id IN (SELECT id FROM agent_identities WHERE created_by = $1)
		  )`, userID)
	if err != nil {
		return 0, fmt.Errorf("querying leases for user: %w", err)
	}
	defer rows.Close()

	type leaseRef struct {
		id           string
		credRaw      []byte
		providerType string
		provCfgRaw   []byte
	}
	var refs []leaseRef
	for rows.Next() {
		var r leaseRef
		if err := rows.Scan(&r.id, &r.credRaw, &r.providerType, &r.provCfgRaw); err != nil {
			return 0, err
		}
		refs = append(refs, r)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	revoked := 0
	for _, r := range refs {
		if _, err := s.db.Exec(ctx,
			`UPDATE dynamic_leases SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, r.id); err != nil {
			return revoked, fmt.Errorf("revoke lease %s: %w", r.id, err)
		}
		revoked++

		// Best-effort immediate backend cut; the sweeper retries later.
		if r.providerType == "postgres" {
			if creds, credErr := s.decryptCreds(r.credRaw); credErr == nil {
				if username, ok := creds["username"]; ok && username != "" {
					if prov, provErr := s.providerFor(r.providerType, r.provCfgRaw); provErr == nil {
						if err := prov.Revoke(ctx, username); err != nil {
							log.Printf("dynsecret revoke-all: drop role %q for lease %s: %v", username, r.id, err)
						}
					}
				}
			} else {
				log.Printf("dynsecret revoke-all: decrypt lease %s: %v", r.id, credErr)
			}
		}
	}
	return revoked, nil
}
