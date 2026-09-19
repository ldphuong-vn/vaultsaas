package vault

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/valt-dev/valt/server/internal/rbac"
	"github.com/valt-dev/valt/server/pkg/crypto"
)

type Secret struct {
	ID                string     `json:"id"`
	UserID            string     `json:"user_id"`
	ProjectID         *string    `json:"project_id,omitempty"`
	Name              string     `json:"name"`
	Description       string     `json:"description,omitempty"`
	CredentialType    string     `json:"credential_type"`
	Source            string     `json:"source,omitempty"`
	Version           int        `json:"version"`
	StorageKey        string     `json:"-"`
	EncryptedDEK      []byte     `json:"-"`
	DynamicProviderID *string    `json:"dynamic_provider_id,omitempty"` // set = approval mints a dynamic lease instead of returning the static value
	Policy            string     `json:"policy,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	DeletedAt         *time.Time `json:"-"`
}

type CreateSecretInput struct {
	Name           string `json:"name"`
	Description    string `json:"description"`
	CredentialType string `json:"credential_type"`
	Source         string `json:"source"`
	ProjectID      string `json:"project_id"`
	EncryptedBlob  []byte `json:"encrypted_blob"`
	EncryptedDEK   []byte `json:"encrypted_dek"`
	Policy         string `json:"policy"`
}

type UpdateSecretInput struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	EncryptedBlob []byte `json:"encrypted_blob"`
	EncryptedDEK  []byte `json:"encrypted_dek"`
}

type ListResult struct {
	Secrets []Secret `json:"secrets"`
	Total   int      `json:"total"`
	Page    int      `json:"page"`
	Limit   int      `json:"limit"`
}

type Service struct {
	pool    *pgxpool.Pool
	storage Storage
}

func NewService(pool *pgxpool.Pool, storage Storage) *Service {
	return &Service{pool: pool, storage: storage}
}

// IsProjectMember checks if a user belongs to the given project.
func (s *Service) IsProjectMember(ctx context.Context, projectID, userID string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM project_memberships WHERE project_id = $1 AND user_id = $2)`,
		projectID, userID,
	).Scan(&exists)
	return exists, err
}

func (s *Service) CreateSecret(ctx context.Context, userID string, input CreateSecretInput) (*Secret, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	credType := input.CredentialType
	if credType == "" {
		credType = "api_key"
	}
	policy := input.Policy
	if policy == "" {
		policy = "{}"
	}

	var secret Secret
	storageKey := crypto.StorageKey(userID, "tmp")

	err = tx.QueryRow(ctx,
		`INSERT INTO secrets (user_id, project_id, name, description, storage_key, encrypted_dek, policy, credential_type, source)
		 VALUES ($1, NULLIF($2, '')::uuid, $3, $4, $5, $6, $7, $8, $9)
		 RETURNING id, user_id, project_id, name, description, storage_key, policy, credential_type, source, version, created_at, updated_at`,
		userID, input.ProjectID, input.Name, input.Description, storageKey, input.EncryptedDEK, policy, credType, input.Source,
	).Scan(&secret.ID, &secret.UserID, &secret.ProjectID, &secret.Name, &secret.Description,
		&secret.StorageKey, &secret.Policy, &secret.CredentialType, &secret.Source, &secret.Version,
		&secret.CreatedAt, &secret.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("inserting secret: %w", err)
	}

	// Update storage key with actual secret ID
	storageKey = crypto.StorageKey(userID, secret.ID)
	_, err = tx.Exec(ctx,
		`UPDATE secrets SET storage_key = $1 WHERE id = $2`, storageKey, secret.ID)
	if err != nil {
		return nil, fmt.Errorf("updating storage key: %w", err)
	}
	secret.StorageKey = storageKey

	// Store encrypted blob in MinIO
	if len(input.EncryptedBlob) > 0 {
		if err := s.storage.Put(ctx, storageKey, input.EncryptedBlob); err != nil {
			return nil, fmt.Errorf("storing blob: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing transaction: %w", err)
	}

	return &secret, nil
}

func (s *Service) ListSecrets(ctx context.Context, userID string, page, limit, offset int) (*ListResult, error) {
	var total int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM secrets WHERE user_id = $1 AND deleted_at IS NULL`,
		userID,
	).Scan(&total)
	if err != nil {
		return nil, fmt.Errorf("counting secrets: %w", err)
	}

	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, name, description, credential_type, source, version, policy, created_at, updated_at
		 FROM secrets WHERE user_id = $1 AND deleted_at IS NULL
		 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		userID, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("querying secrets: %w", err)
	}
	defer rows.Close()

	var secrets []Secret
	for rows.Next() {
		var sec Secret
		if err := rows.Scan(&sec.ID, &sec.UserID, &sec.Name, &sec.Description,
			&sec.CredentialType, &sec.Source, &sec.Version,
			&sec.Policy, &sec.CreatedAt, &sec.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning secret: %w", err)
		}
		secrets = append(secrets, sec)
	}
	if secrets == nil {
		secrets = []Secret{}
	}

	return &ListResult{Secrets: secrets, Total: total, Page: page, Limit: limit}, nil
}

func (s *Service) GetSecret(ctx context.Context, userID, secretID string) (*Secret, error) {
	var secret Secret
	err := s.pool.QueryRow(ctx,
		`SELECT id, user_id, name, description, storage_key, encrypted_dek,
		        credential_type, source, version, policy, created_at, updated_at,
		        project_id, dynamic_provider_id
		 FROM secrets WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL`,
		secretID, userID,
	).Scan(&secret.ID, &secret.UserID, &secret.Name, &secret.Description,
		&secret.StorageKey, &secret.EncryptedDEK,
		&secret.CredentialType, &secret.Source, &secret.Version,
		&secret.Policy, &secret.CreatedAt, &secret.UpdatedAt,
		&secret.ProjectID, &secret.DynamicProviderID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("querying secret: %w", err)
	}
	return &secret, nil
}

// UpdateSecret updates mutable fields of a secret. Name and description are always
// updated. encrypted_dek and the blob in object storage are only updated when a new
// value is provided, preserving the existing DEK when the caller only renames a secret.
func (s *Service) UpdateSecret(ctx context.Context, userID, secretID string, input UpdateSecretInput) (*Secret, error) {
	var secret Secret

	// Use COALESCE so that passing NULL for encrypted_dek keeps the existing value,
	// preventing accidental data loss when only name/description are being changed.
	err := s.pool.QueryRow(ctx,
		`UPDATE secrets
		    SET name          = $1,
		        description   = $2,
		        encrypted_dek = COALESCE($3, encrypted_dek),
		        version       = version + 1,
		        updated_at    = NOW()
		  WHERE id = $4 AND user_id = $5 AND deleted_at IS NULL
		  RETURNING id, user_id, name, description, storage_key, credential_type, source, version, policy, created_at, updated_at`,
		input.Name, input.Description, nullableBytes(input.EncryptedDEK), secretID, userID,
	).Scan(&secret.ID, &secret.UserID, &secret.Name, &secret.Description,
		&secret.StorageKey, &secret.CredentialType, &secret.Source, &secret.Version,
		&secret.Policy, &secret.CreatedAt, &secret.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("updating secret: %w", err)
	}

	// Update blob in MinIO only when a new encrypted blob is provided.
	if len(input.EncryptedBlob) > 0 {
		if err := s.storage.Put(ctx, secret.StorageKey, input.EncryptedBlob); err != nil {
			return nil, fmt.Errorf("updating blob: %w", err)
		}
	}

	return &secret, nil
}

// nullableBytes returns nil when b is empty so that pgx sends SQL NULL,
// allowing COALESCE in the UPDATE query to preserve the existing column value.
func nullableBytes(b []byte) interface{} {
	if len(b) == 0 {
		return nil
	}
	return b
}

// GetSecretByID fetches a secret by ID without owner constraint (for approved credential delivery).
func (s *Service) GetSecretByID(ctx context.Context, secretID string) (*Secret, error) {
	var secret Secret
	err := s.pool.QueryRow(ctx,
		`SELECT id, user_id, name, description, storage_key, encrypted_dek,
		        credential_type, source, version, policy, created_at, updated_at,
		        project_id, dynamic_provider_id
		 FROM secrets WHERE id = $1 AND deleted_at IS NULL`,
		secretID,
	).Scan(&secret.ID, &secret.UserID, &secret.Name, &secret.Description,
		&secret.StorageKey, &secret.EncryptedDEK,
		&secret.CredentialType, &secret.Source, &secret.Version,
		&secret.Policy, &secret.CreatedAt, &secret.UpdatedAt,
		&secret.ProjectID, &secret.DynamicProviderID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("querying secret by id: %w", err)
	}
	return &secret, nil
}

// SetDynamicProvider links (providerID) or unlinks (nil) a dynamic provider to
// a secret. When linked, approvals for this secret mint short-lived leases from
// the provider instead of returning the static secret value.
// Authorized callers: the secret owner, or a project member with secret write
// permission when the secret lives in a project.
func (s *Service) SetDynamicProvider(ctx context.Context, secretID, userID string, providerID *string) (*Secret, error) {
	var ownerID string
	var projectID *string
	err := s.pool.QueryRow(ctx,
		`SELECT user_id, project_id::text FROM secrets WHERE id = $1 AND deleted_at IS NULL`,
		secretID,
	).Scan(&ownerID, &projectID)
	if err != nil {
		return nil, fmt.Errorf("secret not found: %w", err)
	}
	if ownerID != userID {
		authorized := false
		if projectID != nil {
			var role string
			roleErr := s.pool.QueryRow(ctx,
				`SELECT role FROM project_memberships WHERE project_id = $1 AND user_id = $2`,
				*projectID, userID,
			).Scan(&role)
			if roleErr == nil {
				authorized = rbac.Can(rbac.RoleFromProjectMembership(role), rbac.ResourceSecret, rbac.ActionWrite)
			}
		}
		if !authorized {
			return nil, fmt.Errorf("not authorized to modify this secret")
		}
	}

	if providerID != nil {
		var providerProjectID *string
		var status string
		err = s.pool.QueryRow(ctx,
			`SELECT project_id::text, status FROM dynamic_providers WHERE id = $1`, *providerID,
		).Scan(&providerProjectID, &status)
		if err != nil {
			return nil, fmt.Errorf("provider not found: %w", err)
		}
		if status != "active" {
			return nil, fmt.Errorf("provider is not active")
		}
		// A lease provider lives in a project; the secret must belong to it.
		if projectID == nil || providerProjectID == nil || *projectID != *providerProjectID {
			return nil, fmt.Errorf("provider belongs to a different project than the secret")
		}
	}

	tag, err := s.pool.Exec(ctx,
		`UPDATE secrets SET dynamic_provider_id = $2, updated_at = NOW()
		 WHERE id = $1 AND deleted_at IS NULL`,
		secretID, providerID,
	)
	if err != nil {
		return nil, fmt.Errorf("updating secret provider link: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, fmt.Errorf("secret not found")
	}

	secret, err := s.GetSecretByID(ctx, secretID)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, fmt.Errorf("secret not found")
	}
	return secret, nil
}

// GetBlob retrieves the encrypted blob for a secret from object storage.
func (s *Service) GetBlob(ctx context.Context, storageKey string) ([]byte, error) {
	data, err := s.storage.Get(ctx, storageKey)
	if err != nil {
		return nil, fmt.Errorf("getting blob: %w", err)
	}
	return data, nil
}

func (s *Service) DeleteSecret(ctx context.Context, userID, secretID string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE secrets SET deleted_at = NOW() WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL`,
		secretID, userID,
	)
	if err != nil {
		return fmt.Errorf("soft-deleting secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// GetPolicy returns the policy_config JSON for a secret owned by userID.
func (s *Service) GetPolicy(ctx context.Context, secretID, userID string) ([]byte, error) {
	var policyJSON []byte
	err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(policy_config, '{}') FROM secrets WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL`,
		secretID, userID,
	).Scan(&policyJSON)
	if err != nil {
		return nil, err
	}
	return policyJSON, nil
}

// SetPolicy saves the policy_config JSON for a secret owned by userID.
func (s *Service) SetPolicy(ctx context.Context, secretID, userID string, policyJSON []byte) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE secrets SET policy_config = $1 WHERE id = $2 AND user_id = $3 AND deleted_at IS NULL`,
		policyJSON, secretID, userID,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("secret not found or not authorized")
	}
	return nil
}

// ListSecretsForAgent lists secrets accessible to an agent via their projects.
func (s *Service) ListSecretsForAgent(ctx context.Context, agentID string, page, limit, offset int) (*ListResult, error) {
	var total int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(DISTINCT s.id) FROM secrets s
		 WHERE s.project_id IN (SELECT project_id FROM agent_identities WHERE id = $1)
		 AND s.deleted_at IS NULL`,
		agentID,
	).Scan(&total)
	if err != nil {
		return nil, fmt.Errorf("counting secrets for agent: %w", err)
	}

	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT s.id, s.user_id, s.name, s.description, s.credential_type, s.source, s.version, s.policy, s.created_at, s.updated_at, s.dynamic_provider_id
		 FROM secrets s
		 WHERE s.project_id IN (SELECT project_id FROM agent_identities WHERE id = $1)
		 AND s.deleted_at IS NULL
		 ORDER BY s.created_at DESC LIMIT $2 OFFSET $3`,
		agentID, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("querying secrets for agent: %w", err)
	}
	defer rows.Close()

	var secrets []Secret
	for rows.Next() {
		var sec Secret
		if err := rows.Scan(&sec.ID, &sec.UserID, &sec.Name, &sec.Description,
			&sec.CredentialType, &sec.Source, &sec.Version,
			&sec.Policy, &sec.CreatedAt, &sec.UpdatedAt, &sec.DynamicProviderID); err != nil {
			return nil, fmt.Errorf("scanning secret: %w", err)
		}
		secrets = append(secrets, sec)
	}
	if secrets == nil {
		secrets = []Secret{}
	}

	return &ListResult{Secrets: secrets, Total: total, Page: page, Limit: limit}, nil
}

// GetSecretForAgent retrieves a secret accessible to an agent via their projects.
func (s *Service) GetSecretForAgent(ctx context.Context, agentID, secretID string) (*Secret, error) {
	var secret Secret
	err := s.pool.QueryRow(ctx,
		`SELECT s.id, s.user_id, s.name, s.description, s.storage_key, s.encrypted_dek,
		        s.credential_type, s.source, s.version, s.policy, s.created_at, s.updated_at
		 FROM secrets s
		 WHERE s.id = $1
		 AND s.project_id IN (SELECT project_id FROM agent_identities WHERE id = $2)
		 AND s.deleted_at IS NULL`,
		secretID, agentID,
	).Scan(&secret.ID, &secret.UserID, &secret.Name, &secret.Description,
		&secret.StorageKey, &secret.EncryptedDEK,
		&secret.CredentialType, &secret.Source, &secret.Version,
		&secret.Policy, &secret.CreatedAt, &secret.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("querying secret for agent: %w", err)
	}
	return &secret, nil
}
