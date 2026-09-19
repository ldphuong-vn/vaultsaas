package dynsecret

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// DerivedKeyPrefix marks a credential as a Valt-derived API key, so the
// gateway can tell it apart from a real upstream key or an agent token.
const DerivedKeyPrefix = "valt_dk_"

// DerivedKeyProvider issues short-lived API keys derived from a master
// provider key. Use case: cấp AI API key cho nhân viên/agent — master key
// không bao giờ rời vault, người dùng chỉ nhận key dẫn xuất tự hết hạn.
//
// The derived key is HMAC-SHA256(master_key, random nonce): it cannot be
// reversed to recover the master key, and it is not accepted by any upstream
// API — it only means something to Valt, which validates it by hash lookup
// (dynamic_leases.key_hash) and swaps in the real master key at the gateway.
// Config keys: master_key (required), upstream (informational label).
type DerivedKeyProvider struct {
	config ProviderConfig
}

func (p *DerivedKeyProvider) Type() string { return "derived_api_key" }

// deriveDerivedKey computes the lease credential from master key material and
// a fresh nonce. Pure function so unit tests can pin the key format.
func deriveDerivedKey(masterKey, nonce []byte) string {
	mac := hmac.New(sha256.New, masterKey)
	mac.Write(nonce)
	return DerivedKeyPrefix + hex.EncodeToString(mac.Sum(nil))
}

// hashDerivedKey returns the lookup hash stored in dynamic_leases.key_hash.
func hashDerivedKey(rawKey string) string {
	sum := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(sum[:])
}

// Create issues a new derived API key. Nothing is provisioned upstream: the
// credential exists only as a lease row inside Valt.
func (p *DerivedKeyProvider) Create(ctx context.Context, req LeaseRequest) (*Lease, error) {
	masterKey := p.config.Config["master_key"]
	if masterKey == "" {
		return nil, fmt.Errorf("derived_api_key provider requires master_key in config")
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	apiKey := deriveDerivedKey([]byte(masterKey), nonce)
	creds := map[string]string{
		"api_key": apiKey,
	}
	if upstream := p.config.Config["upstream"]; upstream != "" {
		creds["upstream"] = upstream
	}

	return &Lease{
		Credentials: creds,
		KeyHash:     hashDerivedKey(apiKey),
		ExpiresAt:   time.Now().Add(req.TTL),
		ProviderID:  p.config.ID,
	}, nil
}

// Revoke is a no-op: the derived key lives only in Valt's database, so
// marking the lease revoked is the entire revocation.
func (p *DerivedKeyProvider) Revoke(ctx context.Context, leaseID string) error {
	return nil
}

// Renew has no upstream effect either; the returned Lease only reflects the
// extended expiry for callers that want it.
func (p *DerivedKeyProvider) Renew(ctx context.Context, leaseID string, ttl time.Duration) (*Lease, error) {
	return &Lease{
		ID:         leaseID,
		ExpiresAt:  time.Now().Add(ttl),
		ProviderID: p.config.ID,
	}, nil
}
