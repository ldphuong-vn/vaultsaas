package dynsecret

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/valt-dev/valt/server/pkg/crypto"
)

// sweepGrace delays backend cleanup after expiry so an operation that was
// already in flight when the lease ran out can finish seeing its role. The
// role is already unusable (VALID UNTIL in the past) — this only governs
// when the object gets dropped.
const sweepGrace = 5 * time.Minute

// SweepExpiredBackends drops backend credentials for expired leases whose
// provider provisions real objects (Postgres temp roles). Idempotent: only
// leases with backend_swept_at IS NULL are considered, and each is marked
// on success. Derived API key leases have nothing upstream to drop and are
// just marked. Returns the number of leases swept.
func (s *Service) SweepExpiredBackends(ctx context.Context) (int, error) {
	rows, err := s.db.Query(ctx, `
		SELECT l.id, l.secret_data_enc, p.provider_type, p.config_enc
		FROM dynamic_leases l
		JOIN dynamic_providers p ON p.id = l.provider_id
		WHERE l.expires_at < now() - $1::interval
		  AND l.backend_swept_at IS NULL`, sweepGrace)
	if err != nil {
		return 0, fmt.Errorf("querying leases to sweep: %w", err)
	}
	defer rows.Close()

	type sweepItem struct {
		leaseID      string
		credRaw      []byte
		providerType string
		provCfgRaw   []byte
	}
	var items []sweepItem
	for rows.Next() {
		var it sweepItem
		if err := rows.Scan(&it.leaseID, &it.credRaw, &it.providerType, &it.provCfgRaw); err != nil {
			return len(items), fmt.Errorf("scan lease to sweep: %w", err)
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	swept := 0
	for _, it := range items {
		if err := s.sweepOne(ctx, it.leaseID, it.credRaw, it.providerType, it.provCfgRaw); err != nil {
			// Leave backend_swept_at NULL so the next tick retries; a role
			// that cannot be dropped today must not be silently abandoned.
			log.Printf("dynsecret sweeper: lease %s (%s): %v", it.leaseID, it.providerType, err)
			continue
		}
		swept++
	}
	return swept, nil
}

// sweepOne drops one lease's backend credential and marks it swept.
func (s *Service) sweepOne(ctx context.Context, leaseID string, credRaw []byte, providerType string, provCfgRaw []byte) error {
	if providerType == "postgres" {
		creds, err := s.decryptCreds(credRaw)
		if err != nil {
			return err
		}
		username, ok := creds["username"]
		if !ok || username == "" {
			return fmt.Errorf("lease has no username to drop")
		}
		prov, err := s.providerFor(providerType, provCfgRaw)
		if err != nil {
			return err
		}
		if err := prov.Revoke(ctx, username); err != nil {
			return fmt.Errorf("drop role %q: %w", username, err)
		}
	}
	// Other provider types keep no backend object: marking is the whole job.

	if _, err := s.db.Exec(ctx,
		`UPDATE dynamic_leases SET backend_swept_at = now() WHERE id = $1`, leaseID); err != nil {
		return fmt.Errorf("mark swept: %w", err)
	}
	return nil
}

// decryptCreds decrypts lease credentials, tolerating pre-migration plaintext
// rows (same fallback as the rest of the package).
func (s *Service) decryptCreds(credRaw []byte) (map[string]string, error) {
	var creds map[string]string
	decCreds, decErr := crypto.DecryptAES256GCM(s.masterKey, credRaw)
	if decErr != nil {
		if jsonErr := json.Unmarshal(credRaw, &creds); jsonErr != nil {
			return nil, fmt.Errorf("corrupted lease credentials: %v", jsonErr)
		}
		return creds, nil
	}
	if err := json.Unmarshal(decCreds, &creds); err != nil {
		return nil, fmt.Errorf("parse lease credentials: %w", err)
	}
	return creds, nil
}

// providerFor rebuilds a Provider from its encrypted config blob.
func (s *Service) providerFor(providerType string, provCfgRaw []byte) (Provider, error) {
	var pc ProviderConfig
	decrypted, decErr := crypto.DecryptAES256GCM(s.masterKey, provCfgRaw)
	if decErr != nil {
		if jsonErr := json.Unmarshal(provCfgRaw, &pc.Config); jsonErr != nil {
			return nil, fmt.Errorf("corrupted provider config: %v", jsonErr)
		}
	} else if err := json.Unmarshal(decrypted, &pc.Config); err != nil {
		return nil, fmt.Errorf("parse provider config: %w", err)
	}
	pc.ProviderType = providerType
	return newProviderInstance(&pc)
}
