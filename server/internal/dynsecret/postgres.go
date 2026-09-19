package dynsecret

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
)

// validIdentifier matches safe Postgres identifiers (letters, digits, underscore; max 63 chars).
var validIdentifier = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,62}$`)

func validateIdentifier(name string) error {
	if !validIdentifier.MatchString(name) {
		return fmt.Errorf("invalid identifier: %q", name)
	}
	return nil
}

// PostgresProvider creates temporary DB roles with TTL.
// Config keys: host, port, database, admin_user, admin_password, ssl_mode
type PostgresProvider struct {
	config ProviderConfig
}

func (p *PostgresProvider) Type() string { return "postgres" }

func (p *PostgresProvider) connStr() string {
	host := p.config.Config["host"]
	port := p.config.Config["port"]
	if port == "" {
		port = "5432"
	}
	db := p.config.Config["database"]
	user := p.config.Config["admin_user"]
	pass := url.QueryEscape(p.config.Config["admin_password"])
	sslMode := p.config.Config["ssl_mode"]
	if sslMode == "" {
		sslMode = "require"
	}
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", user, pass, host, port, db, sslMode)
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Create issues a new temporary role via CREATE ROLE ... VALID UNTIL.
func (p *PostgresProvider) Create(ctx context.Context, req LeaseRequest) (*Lease, error) {
	db := p.config.Config["database"]
	if err := validateIdentifier(db); err != nil {
		return nil, fmt.Errorf("invalid database name: %w", err)
	}

	conn, err := pgx.Connect(ctx, p.connStr())
	if err != nil {
		return nil, fmt.Errorf("postgres provider connect: %w", err)
	}
	defer conn.Close(ctx)

	suffix, err := randHex(4)
	if err != nil {
		return nil, err
	}
	password, err := randHex(16)
	if err != nil {
		return nil, err
	}

	username := "valt_" + suffix
	if err := validateIdentifier(username); err != nil {
		return nil, fmt.Errorf("generated invalid username: %w", err)
	}

	expiresAt := time.Now().Add(req.TTL)
	validUntil := expiresAt.UTC().Format(time.RFC3339)

	_, err = conn.Exec(ctx,
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s' VALID UNTIL '%s' CONNECTION LIMIT 5`,
			pgx.Identifier{username}.Sanitize(), password, validUntil))
	if err != nil {
		return nil, fmt.Errorf("create role: %w", err)
	}

	grantSQL := fmt.Sprintf(`GRANT CONNECT ON DATABASE %s TO %s`,
		pgx.Identifier{db}.Sanitize(),
		pgx.Identifier{username}.Sanitize())
	_, err = conn.Exec(ctx, grantSQL)
	if err != nil {
		// Best-effort cleanup
		_, _ = conn.Exec(ctx, fmt.Sprintf(`DROP ROLE IF EXISTS %s`, pgx.Identifier{username}.Sanitize()))
		return nil, fmt.Errorf("grant connect: %w", err)
	}

	return &Lease{
		Credentials: map[string]string{
			"username": username,
			"password": password,
			"host":     p.config.Config["host"],
			"port":     p.config.Config["port"],
			"database": db,
			"ssl_mode": p.config.Config["ssl_mode"],
		},
		ExpiresAt:  expiresAt,
		ProviderID: p.config.ID,
	}, nil
}

// Revoke drops the temporary role. The role carries privileges (CONNECT on
// the database is granted at Create), and DROP ROLE refuses while objects
// depend on it — so privileges are revoked first.
func (p *PostgresProvider) Revoke(ctx context.Context, leaseID string) error {
	// leaseID here is the username stored in credentials
	if err := validateIdentifier(leaseID); err != nil {
		return fmt.Errorf("invalid lease identifier: %w", err)
	}
	conn, err := pgx.Connect(ctx, p.connStr())
	if err != nil {
		return fmt.Errorf("postgres provider connect: %w", err)
	}
	defer conn.Close(ctx)

	if db := p.config.Config["database"]; db != "" {
		// Best-effort: the definitive gate is DROP ROLE below.
		_, _ = conn.Exec(ctx, fmt.Sprintf(`REVOKE CONNECT ON DATABASE %s FROM %s`,
			pgx.Identifier{db}.Sanitize(), pgx.Identifier{leaseID}.Sanitize()))
		_, _ = conn.Exec(ctx, fmt.Sprintf(`DROP OWNED BY %s`,
			pgx.Identifier{leaseID}.Sanitize()))
	}
	_, err = conn.Exec(ctx, fmt.Sprintf(`DROP ROLE IF EXISTS %s`, pgx.Identifier{leaseID}.Sanitize()))
	return err
}

// Renew extends the VALID UNTIL timestamp for an existing role.
func (p *PostgresProvider) Renew(ctx context.Context, leaseID string, ttl time.Duration) (*Lease, error) {
	if err := validateIdentifier(leaseID); err != nil {
		return nil, fmt.Errorf("invalid lease identifier: %w", err)
	}
	conn, err := pgx.Connect(ctx, p.connStr())
	if err != nil {
		return nil, fmt.Errorf("postgres provider connect: %w", err)
	}
	defer conn.Close(ctx)
	newExpiry := time.Now().Add(ttl)
	_, err = conn.Exec(ctx,
		fmt.Sprintf(`ALTER ROLE %s VALID UNTIL '%s'`,
			pgx.Identifier{leaseID}.Sanitize(), newExpiry.UTC().Format(time.RFC3339)))
	if err != nil {
		return nil, fmt.Errorf("renew role: %w", err)
	}
	return &Lease{
		ID:         leaseID,
		ExpiresAt:  newExpiry,
		ProviderID: p.config.ID,
	}, nil
}
