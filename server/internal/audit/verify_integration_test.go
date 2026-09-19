package audit

import (
	"context"
	"fmt"
	"testing"
)

// Happy path: a chain written through Logger verifies with the right head.
func TestVerifyFromDB_ValidChain(t *testing.T) {
	ctx := context.Background()
	pool, cleanup := newAuditIntegrationDB(t, ctx)
	defer cleanup()

	logger := NewLogger(pool)
	const n = 5
	for i := 0; i < n; i++ {
		if _, err := logger.Log(ctx, Entry{
			UserID:       "00000000-0000-0000-0000-000000000001",
			Action:       fmt.Sprintf("op-%d", i),
			ResourceType: "test",
			IPAddress:    "10.0.0.1",
		}); err != nil {
			t.Fatalf("log: %v", err)
		}
	}

	res, err := VerifyFromDB(ctx, pool, "")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.Valid {
		t.Errorf("chain should be valid, got %+v", res)
	}
	if res.Checked != n || res.HeadSeq != n {
		t.Errorf("checked=%d head_seq=%d, want %d/%d", res.Checked, res.HeadSeq, n, n)
	}
	if len(res.HeadHash) != 64 {
		t.Errorf("head_hash should be sha-256 hex, got %q", res.HeadHash)
	}
	if res.BrokenIndex != -1 {
		t.Errorf("broken_index should be -1, got %d", res.BrokenIndex)
	}
}

// Empty table is trivially valid with an empty head.
func TestVerifyFromDB_EmptyTable(t *testing.T) {
	ctx := context.Background()
	pool, cleanup := newAuditIntegrationDB(t, ctx)
	defer cleanup()

	res, err := VerifyFromDB(ctx, pool, "")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.Valid || res.Checked != 0 || res.HeadHash != "" {
		t.Errorf("empty table should be valid with empty head, got %+v", res)
	}
}

// expected_head: matching the head keeps the chain valid; a stale or foreign
// anchor marks the result invalid (tail deletion detection).
func TestVerifyFromDB_ExpectedHead(t *testing.T) {
	ctx := context.Background()
	pool, cleanup := newAuditIntegrationDB(t, ctx)
	defer cleanup()

	logger := NewLogger(pool)
	for i := 0; i < 3; i++ {
		if _, err := logger.Log(ctx, Entry{UserID: "00000000-0000-0000-0000-000000000001", Action: fmt.Sprintf("op-%d", i), ResourceType: "test"}); err != nil {
			t.Fatalf("log: %v", err)
		}
	}
	head, err := VerifyFromDB(ctx, pool, "")
	if err != nil || !head.Valid {
		t.Fatalf("baseline verify failed: %+v err=%v", head, err)
	}

	ok, err := VerifyFromDB(ctx, pool, head.HeadHash)
	if err != nil || !ok.Valid || ok.HeadMismatch {
		t.Errorf("matching anchor should stay valid, got %+v err=%v", ok, err)
	}

	bad, err := VerifyFromDB(ctx, pool, "deadbeef")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if bad.Valid || !bad.HeadMismatch || bad.ExpectedHead != "deadbeef" {
		t.Errorf("foreign anchor must flag head_mismatch, got %+v", bad)
	}
}

// A row edited directly in the database is located by seq and stops the check.
func TestVerifyFromDB_LocatesTamperedRow(t *testing.T) {
	ctx := context.Background()
	pool, cleanup := newAuditIntegrationDB(t, ctx)
	defer cleanup()

	logger := NewLogger(pool)
	for i := 0; i < 4; i++ {
		if _, err := logger.Log(ctx, Entry{
			UserID:       "00000000-0000-0000-0000-000000000001",
			Action:       fmt.Sprintf("op-%d", i),
			ResourceType: "secret",
			ResourceID:   "00000000-0000-0000-0000-0000000000aa",
			IPAddress:    "10.0.0.1",
			Metadata:     `{"op":"read"}`,
		}); err != nil {
			t.Fatalf("log: %v", err)
		}
	}

	if _, err := pool.Exec(ctx, `UPDATE audit_logs SET user_agent = 'evil/1.0' WHERE seq = 3`); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	res, err := VerifyFromDB(ctx, pool, "")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Valid {
		t.Errorf("tampered chain must be invalid, got %+v", res)
	}
	if res.BrokenSeq == nil || *res.BrokenSeq != 3 {
		t.Errorf("break should be at seq 3, got %+v", res.BrokenSeq)
	}
	if res.Checked != 3 {
		t.Errorf("checking should stop at the break (3), got %d", res.Checked)
	}
}
