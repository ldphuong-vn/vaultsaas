package dynsecret

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestDeriveDerivedKeyFormat(t *testing.T) {
	master := []byte("sk-company-master-key")
	nonce := []byte("0123456789abcdef")

	key := deriveDerivedKey(master, nonce)
	if !strings.HasPrefix(key, DerivedKeyPrefix) {
		t.Fatalf("key must start with %q, got %q", DerivedKeyPrefix, key)
	}
	hexPart := strings.TrimPrefix(key, DerivedKeyPrefix)
	if len(hexPart) != 64 { // hex(HMAC-SHA256) = 64 chars
		t.Fatalf("key body must be 64 hex chars, got %d: %q", len(hexPart), key)
	}

	// Deterministic for the same inputs...
	if again := deriveDerivedKey(master, nonce); again != key {
		t.Fatalf("derivation must be deterministic: %q vs %q", key, again)
	}
	// ...but different per nonce (uniqueness across leases)...
	if otherNonce := deriveDerivedKey(master, []byte("fedcba9876543210")); otherNonce == key {
		t.Fatal("different nonces must yield different keys")
	}
	// ...and different per master (lease keys diverge when the master rotates).
	if otherMaster := deriveDerivedKey([]byte("sk-rotated"), nonce); otherMaster == key {
		t.Fatal("different master keys must yield different keys")
	}
}

func TestHashDerivedKey(t *testing.T) {
	h1 := hashDerivedKey("valt_dk_a")
	h2 := hashDerivedKey("valt_dk_a")
	h3 := hashDerivedKey("valt_dk_b")
	if h1 != h2 {
		t.Fatal("hash must be stable for the same key")
	}
	if h1 == h3 {
		t.Fatal("different keys must hash differently")
	}
}

func TestDerivedKeyProviderCreate(t *testing.T) {
	p := &DerivedKeyProvider{config: ProviderConfig{
		ID:     "provider-1",
		Config: map[string]string{"master_key": "sk-company-master-key", "upstream": "api.openai.com"},
	}}
	if p.Type() != "derived_api_key" {
		t.Fatalf("unexpected type: %s", p.Type())
	}

	lease, err := p.Create(context.Background(), LeaseRequest{TTL: 30 * time.Minute, AgentID: "agent-1"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	apiKey, ok := lease.Credentials["api_key"]
	if !ok || !strings.HasPrefix(apiKey, DerivedKeyPrefix) {
		t.Fatalf("lease must carry a %q credential, got %v", DerivedKeyPrefix, lease.Credentials)
	}
	if lease.Credentials["upstream"] != "api.openai.com" {
		t.Fatalf("upstream label must be preserved, got %q", lease.Credentials["upstream"])
	}
	if lease.KeyHash != hashDerivedKey(apiKey) {
		t.Fatal("KeyHash must be the lookup hash of the issued key")
	}
	if time.Until(lease.ExpiresAt) > 31*time.Minute {
		t.Fatalf("expiry must respect TTL, got %v", lease.ExpiresAt)
	}
	// The master key must never appear in the issued credential.
	if strings.Contains(apiKey, "sk-company-master-key") {
		t.Fatal("derived key must not leak master key material")
	}
}

func TestDerivedKeyProviderRequiresMasterKey(t *testing.T) {
	p := &DerivedKeyProvider{config: ProviderConfig{Config: map[string]string{}}}
	if _, err := p.Create(context.Background(), LeaseRequest{TTL: time.Minute}); err == nil {
		t.Fatal("create must fail without master_key config")
	}
}

func TestDerivedKeyProviderRevokeRenew(t *testing.T) {
	p := &DerivedKeyProvider{config: ProviderConfig{ID: "provider-1"}}
	if err := p.Revoke(context.Background(), "any"); err != nil {
		t.Fatalf("revoke is a no-op for derived keys: %v", err)
	}
	lease, err := p.Renew(context.Background(), "lease-1", 5*time.Minute)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if lease.ID != "lease-1" {
		t.Fatalf("renew must echo lease id, got %q", lease.ID)
	}
	if time.Until(lease.ExpiresAt) > 6*time.Minute {
		t.Fatalf("renew expiry must reflect new ttl, got %v", lease.ExpiresAt)
	}
}
