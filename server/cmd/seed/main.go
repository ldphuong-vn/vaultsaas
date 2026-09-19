package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/argon2"

	"github.com/valt-dev/valt/server/internal/audit"
)

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL is required")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer pool.Close()

	tx, err := pool.Begin(ctx)
	if err != nil {
		log.Fatalf("Failed to begin tx: %v", err)
	}
	defer tx.Rollback(ctx)

	// Users
	adminHash := hashPassword("ValtAdmin2026!")
	devHash := hashPassword("ValtDev2026!!")

	var adminID, devID string
	err = tx.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, region_code, status)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (email) DO UPDATE SET password_hash = $2
		 RETURNING id`,
		"admin@valt.dev", adminHash, "us", "active",
	).Scan(&adminID)
	if err != nil {
		log.Fatalf("Failed to insert admin user: %v", err)
	}

	err = tx.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, region_code, status)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (email) DO UPDATE SET password_hash = $2
		 RETURNING id`,
		"dev@valt.dev", devHash, "eu", "active",
	).Scan(&devID)
	if err != nil {
		log.Fatalf("Failed to insert dev user: %v", err)
	}

	// Secrets (3 per user)
	secrets := []struct {
		userID string
		name   string
		desc   string
	}{
		{adminID, "AWS Access Key", "Production AWS credentials"},
		{adminID, "Database Credentials", "Main PostgreSQL connection string"},
		{adminID, "Stripe API Key", "Live Stripe secret key"},
		{devID, "AWS Access Key", "Staging AWS credentials"},
		{devID, "Database Credentials", "Dev PostgreSQL connection string"},
		{devID, "Stripe API Key", "Test Stripe secret key"},
	}

	secretIDs := make([]string, len(secrets))
	for i, s := range secrets {
		dek := make([]byte, 32)
		if _, err := rand.Read(dek); err != nil {
			log.Fatalf("Failed to generate DEK: %v", err)
		}
		storageKey := fmt.Sprintf("secrets/%s/%s", s.userID, s.name)

		err = tx.QueryRow(ctx,
			`INSERT INTO secrets (user_id, name, description, storage_key, encrypted_dek, policy)
			 VALUES ($1, $2, $3, $4, $5, $6)
			 RETURNING id`,
			s.userID, s.name, s.desc, storageKey, dek,
			`{"max_duration":"4h","require_reason":true}`,
		).Scan(&secretIDs[i])
		if err != nil {
			log.Fatalf("Failed to insert secret %q: %v", s.name, err)
		}
	}

	// Access requests
	var pendingReqID, approvedReqID string
	err = tx.QueryRow(ctx,
		`INSERT INTO access_requests (secret_id, requester_user_id, requester_type, ai_agent_id, status, reason, requested_duration_minutes)
		 VALUES ($1, $2, 'human', NULL, 'pending', 'CI pipeline needs AWS creds', 120)
		 RETURNING id`,
		secretIDs[0], devID,
	).Scan(&pendingReqID)
	if err != nil {
		log.Fatalf("Failed to insert pending request: %v", err)
	}

	now := time.Now().UTC()
	err = tx.QueryRow(ctx,
		`INSERT INTO access_requests (secret_id, requester_user_id, requester_type, ai_agent_id, status, reason, requested_duration_minutes, decided_by, decided_at, expires_at)
		 VALUES ($1, $2, 'human', NULL, 'approved', 'Deploy script needs DB creds', 60, $3, $4, $5)
		 RETURNING id`,
		secretIDs[1], devID, adminID, now, now.Add(1*time.Hour),
	).Scan(&approvedReqID)
	if err != nil {
		log.Fatalf("Failed to insert approved request: %v", err)
	}

	// Credential session for approved request
	_, err = tx.Exec(ctx,
		`INSERT INTO credential_sessions (access_request_id, status, expires_at)
		 VALUES ($1, 'active', $2)`,
		approvedReqID, now.Add(1*time.Hour),
	)
	if err != nil {
		log.Fatalf("Failed to insert credential session: %v", err)
	}

	// Audit log entries
	auditEntries := []struct {
		actorID    string
		action     string
		resource   string
		resourceID string
	}{
		{adminID, "user.login", "user", adminID},
		{adminID, "secret.create", "secret", secretIDs[0]},
		{devID, "access_request.create", "access_request", pendingReqID},
		{adminID, "access_request.approve", "access_request", approvedReqID},
	}
	// Audit rows must go through the hash chain (AppendChainNoTx) — direct
	// inserts would leave seq/hash_prev NULL and break /audit/verify.
	auditLogger := audit.NewLogger(pool)
	for _, e := range auditEntries {
		_, err = auditLogger.AppendChainNoTx(ctx, tx, audit.Entry{
			UserID:       e.actorID,
			Action:       e.action,
			ResourceType: e.resource,
			ResourceID:   e.resourceID,
			EventType:    "action",
			Status:       "success",
			Metadata:     "{}",
		})
		if err != nil {
			log.Fatalf("Failed to insert audit log %q: %v", e.action, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		log.Fatalf("Failed to commit: %v", err)
	}

	log.Println("Seed data inserted successfully")
	log.Printf("  Admin user: admin@valt.dev (id=%s)", adminID)
	log.Printf("  Dev user:   dev@valt.dev   (id=%s)", devID)
	log.Printf("  Secrets: %d", len(secretIDs))
	log.Printf("  Access requests: 2 (pending=%s, approved=%s)", pendingReqID, approvedReqID)
}

func hashPassword(password string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		log.Fatalf("Failed to generate salt: %v", err)
	}

	hash := argon2.IDKey([]byte(password), salt, 3, 65536, 4, 32)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$%s$%s", b64Salt, b64Hash)
}
