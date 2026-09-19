package audit

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// VerifyResult is the outcome of a chain verification over the audit_logs table.
//
// The compliance workflow is to record head_hash externally (email, ticket,
// printed report) at audit time, then verify later with expected_head set: a
// valid chain whose head no longer matches the externally anchored hash means
// entries were deleted from the tail — something an in-table chain alone
// cannot detect.
type VerifyResult struct {
	Valid        bool    `json:"valid"`
	Checked      int64   `json:"checked"`                 // entries verified (stopped at first break)
	HeadSeq      int64   `json:"head_seq"`                // seq of last verified entry
	HeadHash     string  `json:"head_hash"`               // chain hash of last verified entry
	BrokenIndex  int64   `json:"broken_index"`            // -1 when valid
	BrokenSeq    *int64  `json:"broken_seq,omitempty"`    // seq of first entry failing verification
	BrokenID     *string `json:"broken_id,omitempty"`     // id of that entry
	HeadMismatch bool    `json:"head_mismatch,omitempty"` // expected_head provided and != HeadHash
	ExpectedHead string  `json:"expected_head,omitempty"`
}

// VerifyFromDB streams every audit entry in seq order and verifies the chain
// incrementally. It stops at the first broken link; everything before it is
// still reported as checked so the operator knows where trust ends.
func VerifyFromDB(ctx context.Context, pool *pgxpool.Pool, expectedHead string) (VerifyResult, error) {
	res := VerifyResult{BrokenIndex: -1}

	rows, err := pool.Query(ctx, `
		SELECT id, seq, event_time, user_id, action, resource_type, resource_id,
		       event_type, status, ip_address::TEXT, user_agent, region_code, metadata, hash_prev
		FROM audit_logs
		ORDER BY seq ASC NULLS LAST`)
	if err != nil {
		return res, fmt.Errorf("query audit logs: %w", err)
	}
	defer rows.Close()

	prevHash := ""
	for rows.Next() {
		var e Entry
		var userID, resourceID, ip, ua, region, hashPrev *string
		if err := rows.Scan(&e.ID, &e.Seq, &e.EventTime, &userID, &e.Action, &e.ResourceType, &resourceID,
			&e.EventType, &e.Status, &ip, &ua, &region, &e.Metadata, &hashPrev); err != nil {
			return res, fmt.Errorf("scan audit log: %w", err)
		}
		if userID != nil {
			e.UserID = *userID
		}
		if resourceID != nil {
			e.ResourceID = *resourceID
		}
		if ip != nil {
			e.IPAddress = *ip
		}
		if ua != nil {
			e.UserAgent = *ua
		}
		if region != nil {
			e.RegionCode = *region
		}
		if hashPrev != nil {
			e.HashPrev = *hashPrev
		}

		res.Checked++
		expected := ComputeHash(e, prevHash)
		if e.HashPrev != expected && e.HashPrev != computeHashV1(e, prevHash) {
			idx := res.Checked - 1
			res.BrokenIndex = idx
			s := e.Seq
			id := e.ID
			res.BrokenSeq = &s
			res.BrokenID = &id
			// A broken link poisons every later one; stop and report where.
			break
		}
		prevHash = e.HashPrev
		res.HeadSeq = e.Seq
		res.HeadHash = e.HashPrev
	}
	if err := rows.Err(); err != nil {
		return res, fmt.Errorf("iterate audit logs: %w", err)
	}

	res.Valid = res.BrokenIndex == -1
	if expectedHead != "" {
		res.ExpectedHead = expectedHead
		if expectedHead != res.HeadHash {
			res.HeadMismatch = true
			res.Valid = false
		}
	}
	return res, nil
}
