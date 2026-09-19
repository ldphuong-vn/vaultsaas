package testutil

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/valt-dev/valt/server/internal/database"
)

// migrationAdvisoryLockKey ("valt" as int32) serializes schema migration
// application across concurrently running integration test helpers.
const migrationAdvisoryLockKey = 1986353238

// ApplyMigrations applies every up migration on pool in filename order.
// It holds a database-level advisory lock for the whole run: migration
// 000001's CREATE EXTENSION pgcrypto registers the extension in the shared
// pg_extension catalog, and concurrent helpers applying migrations on their
// own schemas race there (duplicate pg_extension_name_index) — see
// docs/refactor-plan.md §D.
func ApplyMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection for advisory lock: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationAdvisoryLockKey); err != nil {
		return fmt.Errorf("take migration advisory lock: %w", err)
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationAdvisoryLockKey) //nolint:errcheck

	entries, err := fs.ReadDir(database.MigrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}
	upFiles := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".up.sql") {
			upFiles = append(upFiles, name)
		}
	}
	sort.Strings(upFiles)

	for _, filename := range upFiles {
		raw, err := fs.ReadFile(database.MigrationsFS, "migrations/"+filename)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", filename, err)
		}
		if _, err := pool.Exec(ctx, string(raw)); err != nil {
			return fmt.Errorf("exec migration %s: %w", filename, err)
		}
	}
	return nil
}
