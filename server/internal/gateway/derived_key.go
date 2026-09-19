package gateway

import (
	"context"
	"fmt"
	"log"

	"github.com/valt-dev/valt/server/internal/dynsecret"
)

// derivedKeyAuth resolves a Valt-derived API key presented on a proxied
// request to its active lease, enforcing agent binding. Returns an error when
// the key is unknown, revoked, expired, or used by the wrong agent.
func derivedKeyAuth(ctx context.Context, dynSvc *dynsecret.Service, rawKey, agentID string) (*dynsecret.LeaseInfo, error) {
	lease, err := dynSvc.ValidateDerivedKey(ctx, rawKey)
	if err != nil {
		return nil, fmt.Errorf("derived key lookup: %w", err)
	}
	if lease == nil {
		return nil, fmt.Errorf("invalid or expired derived key")
	}
	// A lease minted for a specific agent must not be used by another one.
	if lease.AgentID != nil && *lease.AgentID != "" && agentID != "" && *lease.AgentID != agentID {
		return nil, fmt.Errorf("derived key belongs to a different agent")
	}
	return lease, nil
}

// logDerivedKeyError keeps gateway failures observable without leaking key material.
func logDerivedKeyError(agentID string, err error) {
	log.Printf("gateway: derived key auth failed for agent %s: %v", agentID, err)
}
