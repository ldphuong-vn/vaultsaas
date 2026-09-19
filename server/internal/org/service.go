package org

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sentinel errors for member removal, mapped to HTTP statuses by the handler.
var (
	ErrOrgNotFound    = errors.New("org not found")
	ErrRemoveOwner    = errors.New("cannot remove the org owner")
	ErrMemberNotFound = errors.New("member not found")
)

type Org struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	OwnerID   string    `json:"owner_id"`
	Plan      string    `json:"plan"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Member struct {
	OrgID     string    `json:"org_id"`
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

// Create inserts a new org and adds creator as owner member in a transaction.
func (s *Service) Create(ctx context.Context, name, slug, ownerID string) (*Org, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var o Org
	err = tx.QueryRow(ctx,
		`INSERT INTO organizations (name, slug, owner_id, plan)
		 VALUES ($1, $2, $3, 'free')
		 RETURNING id, name, slug, owner_id, plan, created_at, updated_at`,
		name, slug, ownerID,
	).Scan(&o.ID, &o.Name, &o.Slug, &o.OwnerID, &o.Plan, &o.CreatedAt, &o.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("inserting org: %w", err)
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO org_memberships (org_id, user_id, role) VALUES ($1, $2, 'owner')`,
		o.ID, ownerID,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting owner membership: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing transaction: %w", err)
	}
	return &o, nil
}

// Get returns org by ID.
func (s *Service) Get(ctx context.Context, id string) (*Org, error) {
	var o Org
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, slug, owner_id, plan, created_at, updated_at
		 FROM organizations WHERE id = $1`,
		id,
	).Scan(&o.ID, &o.Name, &o.Slug, &o.OwnerID, &o.Plan, &o.CreatedAt, &o.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("querying org: %w", err)
	}
	return &o, nil
}

// UpdateName updates an org's display name.
func (s *Service) UpdateName(ctx context.Context, orgID, name string) error {
	_, err := s.pool.Exec(ctx, `UPDATE organizations SET name = $1, updated_at = NOW() WHERE id = $2`, name, orgID)
	return err
}

// ListByUser returns all orgs the user is a member of.
func (s *Service) ListByUser(ctx context.Context, userID string) ([]Org, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT o.id, o.name, o.slug, o.owner_id, o.plan, o.created_at, o.updated_at
		 FROM organizations o
		 JOIN org_memberships m ON m.org_id = o.id
		 WHERE m.user_id = $1
		 ORDER BY o.created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying orgs: %w", err)
	}
	defer rows.Close()

	var orgs []Org
	for rows.Next() {
		var o Org
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.OwnerID, &o.Plan, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning org: %w", err)
		}
		orgs = append(orgs, o)
	}
	if orgs == nil {
		orgs = []Org{}
	}
	return orgs, nil
}

// AddMember adds a user to an org with the given role.
func (s *Service) AddMember(ctx context.Context, orgID, userID, role string) (*Member, error) {
	var m Member
	err := s.pool.QueryRow(ctx,
		`INSERT INTO org_memberships (org_id, user_id, role)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role
		 RETURNING org_id, user_id, role, created_at`,
		orgID, userID, role,
	).Scan(&m.OrgID, &m.UserID, &m.Role, &m.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("adding member: %w", err)
	}
	return &m, nil
}

// RemoveMember removes a member from an org and cascades: their project
// memberships inside the org's workspaces are removed too, so no lingering
// project-level access survives. The org owner cannot be removed (transfer
// ownership first). Revoking the ex-member's issued credentials, if wanted,
// is a separate call: POST /users/{id}/revoke-all.
func (s *Service) RemoveMember(ctx context.Context, orgID, userID string) error {
	var ownerID string
	err := s.pool.QueryRow(ctx,
		`SELECT owner_id FROM organizations WHERE id = $1`, orgID,
	).Scan(&ownerID)
	if err != nil {
		return ErrOrgNotFound
	}
	if ownerID == userID {
		return ErrRemoveOwner
	}

	tag, err := s.pool.Exec(ctx,
		`DELETE FROM org_memberships WHERE org_id = $1 AND user_id = $2`, orgID, userID)
	if err != nil {
		return fmt.Errorf("removing member: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrMemberNotFound
	}

	_, _ = s.pool.Exec(ctx, `
		DELETE FROM project_memberships pm
		USING projects p
		JOIN workspaces w ON w.id = p.workspace_id
		WHERE pm.project_id = p.id AND w.org_id = $1 AND pm.user_id = $2`, orgID, userID)
	return nil
}

// ListMembers returns all members of an org.
func (s *Service) ListMembers(ctx context.Context, orgID string) ([]Member, error) {	rows, err := s.pool.Query(ctx,
		`SELECT org_id, user_id, role, created_at
		 FROM org_memberships WHERE org_id = $1
		 ORDER BY created_at ASC`,
		orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying members: %w", err)
	}
	defer rows.Close()

	var members []Member
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.OrgID, &m.UserID, &m.Role, &m.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning member: %w", err)
		}
		members = append(members, m)
	}
	if members == nil {
		members = []Member{}
	}
	return members, nil
}
