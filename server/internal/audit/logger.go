package audit

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Entry represents a structured audit log entry.
type Entry struct {
	ID           string    `json:"id"`
	Seq          int64     `json:"seq"`
	EventTime    time.Time `json:"event_time"`
	UserID       string    `json:"user_id"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	EventType    string    `json:"event_type"`
	Status       string    `json:"status"`
	IPAddress    string    `json:"ip_address,omitempty"`
	UserAgent    string    `json:"user_agent,omitempty"`
	RegionCode   string    `json:"region_code,omitempty"`
	Metadata     string    `json:"metadata"`
	HashPrev     string    `json:"hash_prev,omitempty"`
}

// Logger writes audit log entries to the database with hash chaining.
//
// The chain head (last hash + sequence number) lives in audit_chain_state, not
// in memory: concurrent writers and server restarts extend the same chain. Each
// Log call runs in one transaction that locks the state row (FOR UPDATE),
// assigns seq = last_seq + 1, inserts the entry, then advances the state row —
// so seqs are contiguous and the chain has exactly one append order.
type Logger struct {
	pool *pgxpool.Pool
}

// NewLogger creates a new audit Logger.
func NewLogger(pool *pgxpool.Pool) *Logger {
	return &Logger{pool: pool}
}

// Log writes a single audit entry and returns its assigned id and seq.
func (l *Logger) Log(ctx context.Context, e Entry) (Entry, error) {
	if e.EventType == "" {
		e.EventType = "action"
	}
	if e.Status == "" {
		e.Status = "success"
	}
	if e.Metadata == "" {
		e.Metadata = "{}"
	}
	if e.EventTime.IsZero() {
		e.EventTime = time.Now().UTC()
	}
	// Match the column the hash is verified against after read-back; see
	// canonicalTime for why microsecond truncation is required.
	e.EventTime = e.EventTime.Truncate(time.Microsecond)
	e.IPAddress = canonicalIP(e.IPAddress)

	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return e, fmt.Errorf("audit begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	var lastSeq int64
	var prevHash string
	err = tx.QueryRow(ctx,
		`SELECT last_seq, last_hash FROM audit_chain_state WHERE id = 1 FOR UPDATE`,
	).Scan(&lastSeq, &prevHash)
	if err != nil {
		return e, fmt.Errorf("audit lock chain state: %w", err)
	}

	hash := ComputeHash(e, prevHash)
	e.Seq = lastSeq + 1
	e.HashPrev = hash

	err = tx.QueryRow(ctx,
		`INSERT INTO audit_logs (user_id, action, resource_type, resource_id, event_time, event_type, status, ip_address, user_agent, region_code, metadata, hash_prev, seq)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::inet, $9, $10, $11, $12, $13)
		 RETURNING id`,
		nilIfEmpty(e.UserID), e.Action, e.ResourceType, nilIfEmpty(e.ResourceID),
		e.EventTime, e.EventType, e.Status, nilIfEmpty(e.IPAddress), nilIfEmpty(e.UserAgent),
		nilIfEmpty(e.RegionCode), e.Metadata, hash, e.Seq,
	).Scan(&e.ID)
	if err != nil {
		return e, fmt.Errorf("writing audit log: %w", err)
	}

	if _, err = tx.Exec(ctx,
		`UPDATE audit_chain_state SET last_seq = $1, last_hash = $2 WHERE id = 1`,
		e.Seq, hash,
	); err != nil {
		return e, fmt.Errorf("advance chain state: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return e, fmt.Errorf("audit commit: %w", err)
	}
	return e, nil
}

// LogFromRequest creates and writes an audit entry extracting IP/UA from request.
func (l *Logger) LogFromRequest(r *http.Request, userID, action, resourceType, resourceID string) {
	e := Entry{
		UserID:       userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		EventType:    "action",
		Status:       "success",
		IPAddress:    ExtractIP(r),
		UserAgent:    r.UserAgent(),
	}
	if _, err := l.Log(r.Context(), e); err != nil {
		log.Printf("audit log error: %v", err)
	}
}

// AppendChainNoTx is reserved for callers that already hold a transaction: it
// extends the chain within tx using the same lock-append-advance protocol as
// Log. The transaction must not have touched audit_chain_state yet.
func (l *Logger) AppendChainNoTx(ctx context.Context, tx pgx.Tx, e Entry) (Entry, error) {
	if e.EventType == "" {
		e.EventType = "action"
	}
	if e.Status == "" {
		e.Status = "success"
	}
	if e.Metadata == "" {
		e.Metadata = "{}"
	}
	if e.EventTime.IsZero() {
		e.EventTime = time.Now().UTC()
	}
	e.EventTime = e.EventTime.Truncate(time.Microsecond)

	var lastSeq int64
	var prevHash string
	err := tx.QueryRow(ctx,
		`SELECT last_seq, last_hash FROM audit_chain_state WHERE id = 1 FOR UPDATE`,
	).Scan(&lastSeq, &prevHash)
	if err != nil {
		return e, fmt.Errorf("audit lock chain state: %w", err)
	}

	hash := ComputeHash(e, prevHash)
	e.Seq = lastSeq + 1
	e.HashPrev = hash

	err = tx.QueryRow(ctx,
		`INSERT INTO audit_logs (user_id, action, resource_type, resource_id, event_time, event_type, status, ip_address, user_agent, region_code, metadata, hash_prev, seq)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::inet, $9, $10, $11, $12, $13)
		 RETURNING id`,
		nilIfEmpty(e.UserID), e.Action, e.ResourceType, nilIfEmpty(e.ResourceID),
		e.EventTime, e.EventType, e.Status, nilIfEmpty(e.IPAddress), nilIfEmpty(e.UserAgent),
		nilIfEmpty(e.RegionCode), e.Metadata, hash, e.Seq,
	).Scan(&e.ID)
	if err != nil {
		return e, fmt.Errorf("writing audit log: %w", err)
	}

	if _, err = tx.Exec(ctx,
		`UPDATE audit_chain_state SET last_seq = $1, last_hash = $2 WHERE id = 1`,
		e.Seq, hash,
	); err != nil {
		return e, fmt.Errorf("advance chain state: %w", err)
	}
	return e, nil
}

// ExtractIP returns the best client IP for an incoming request: the first
// X-Forwarded-For entry, then X-Real-Ip, then the connection address without
// its port. Raw header values may be lists or junk; Logger.Log canonicalizes
// before persisting, so callers can pass the result straight through.
func ExtractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	if xri := r.Header.Get("X-Real-Ip"); xri != "" {
		return xri
	}
	// Strip port from RemoteAddr
	host := r.RemoteAddr
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			return host[:i]
		}
	}
	return host
}

// canonicalIP normalizes an address to the exact text form PostgreSQL's inet
// type renders on read-back ("addr/NN"), so the hash computed before insert
// equals the hash recomputed from the fetched row. X-Forwarded-For may carry a
// comma-separated list or junk; only the first parseable address survives, and
// anything unparseable is dropped (stored as NULL) rather than breaking the
// inet cast.
func canonicalIP(ip string) string {
	if ip == "" {
		return ""
	}
	first := strings.TrimSpace(strings.SplitN(ip, ",", 2)[0])
	addr, err := netip.ParseAddr(first)
	if err != nil || addr.IsUnspecified() {
		return ""
	}
	addr = addr.Unmap() // IPv4-mapped IPv6 is stored as plain IPv4
	return netip.PrefixFrom(addr, addr.BitLen()).String()
}

func nilIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
