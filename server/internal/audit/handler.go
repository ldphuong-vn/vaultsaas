package audit

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/valt-dev/valt/server/internal/admin"
	"github.com/valt-dev/valt/server/internal/auth"
	"github.com/valt-dev/valt/server/pkg/apierror"
	"github.com/valt-dev/valt/server/pkg/validator"
)

// Handler serves audit log query endpoints.
type Handler struct {
	pool *pgxpool.Pool
}

// NewHandler creates a new audit Handler.
func NewHandler(pool *pgxpool.Pool) *Handler {
	return &Handler{pool: pool}
}

// Routes returns the audit router. verify and export expose the complete
// audit trail (all users' IPs and agents), so they are restricted to users
// with the admin role; /logs keeps its existing member-level access.
func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Get("/logs", h.queryLogs)
	r.With(admin.AdminMiddleware(h.pool)).Get("/verify", h.verifyChain)
	r.With(admin.AdminMiddleware(h.pool)).Get("/export.csv", h.exportCSV)
	return r
}

// verifyChain streams the audit table through the hash chain and reports the
// result. Optional ?expected_head=<hash> compares the verified head against an
// externally anchored hash (compliance workflow — see VerifyResult).
func (h *Handler) verifyChain(w http.ResponseWriter, r *http.Request) {
	res, err := VerifyFromDB(r.Context(), h.pool, r.URL.Query().Get("expected_head"))
	if err != nil {
		log.Printf("Failed to verify audit chain: %v", err)
		apierror.InternalError(w, "failed to verify audit chain")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res) //nolint:errcheck
}

var csvHeader = []string{
	"seq", "id", "event_time", "user_id", "action", "resource_type", "resource_id",
	"event_type", "status", "ip_address", "user_agent", "region_code", "metadata", "hash_prev",
}

// exportCSV streams every audit entry (ordered by seq) as CSV for compliance
// archives. Supports the same start/end/event_type filters as /logs. Cells
// that could be interpreted as formulas by spreadsheet apps are neutralized
// with a leading quote (CSV injection guard).
func (h *Handler) exportCSV(w http.ResponseWriter, r *http.Request) {
	query := `SELECT id, seq, event_time, user_id, action, resource_type, resource_id,
	                 event_type, status, ip_address::TEXT, user_agent, region_code, metadata, hash_prev
	          FROM audit_logs WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if et := r.URL.Query().Get("event_type"); et != "" {
		query += fmt.Sprintf(" AND event_type = $%d", argIdx)
		args = append(args, et)
		argIdx++
	}
	if startStr := r.URL.Query().Get("start"); startStr != "" {
		start, err := time.Parse(time.RFC3339, startStr)
		if err != nil {
			apierror.BadRequest(w, "invalid start date format, use RFC3339")
			return
		}
		query += fmt.Sprintf(" AND event_time >= $%d", argIdx)
		args = append(args, start)
		argIdx++
	}
	if endStr := r.URL.Query().Get("end"); endStr != "" {
		end, err := time.Parse(time.RFC3339, endStr)
		if err != nil {
			apierror.BadRequest(w, "invalid end date format, use RFC3339")
			return
		}
		query += fmt.Sprintf(" AND event_time <= $%d", argIdx)
		args = append(args, end)
		argIdx++
	}
	query += fmt.Sprintf(" ORDER BY seq ASC NULLS LAST")

	rows, err := h.pool.Query(r.Context(), query, args...)
	if err != nil {
		log.Printf("Failed to query audit logs for export: %v", err)
		apierror.InternalError(w, "failed to export audit logs")
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="valt-audit-export.csv"`)
	w.WriteHeader(http.StatusOK)

	cw := csv.NewWriter(w)
	_ = cw.Write(csvHeader)
	for rows.Next() {
		var e Entry
		var userID, resourceID, ipAddr, ua, regionCode, hashPrev *string
		if err := rows.Scan(&e.ID, &e.Seq, &e.EventTime, &userID, &e.Action, &e.ResourceType, &resourceID,
			&e.EventType, &e.Status, &ipAddr, &ua, &regionCode, &e.Metadata, &hashPrev); err != nil {
			log.Printf("Failed to scan audit log during export: %v", err)
			return // headers already sent; abort mid-stream
		}
		_ = cw.Write([]string{
			strconv.FormatInt(e.Seq, 10),
			e.ID,
			e.EventTime.UTC().Format(time.RFC3339Nano),
			deref(userID),
			sanitizeCSVCell(e.Action),
			sanitizeCSVCell(e.ResourceType),
			deref(resourceID),
			e.EventType,
			e.Status,
			deref(ipAddr),
			sanitizeCSVCell(deref(ua)),
			deref(regionCode),
			sanitizeCSVCell(e.Metadata),
			deref(hashPrev),
		})
	}
	cw.Flush()
}

// sanitizeCSVCell prevents CSV formula injection (=, +, -, @, tab, CR prefixes
// would execute as formulas in Excel/LibreOffice).
func sanitizeCSVCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

type auditLogResponse struct {
	Logs  []Entry `json:"logs"`
	Total int     `json:"total"`
	Page  int     `json:"page"`
	Limit int     `json:"limit"`
}

func (h *Handler) queryLogs(w http.ResponseWriter, r *http.Request) {
	_ = auth.UserIDFromContext(r.Context())

	pg, err := validator.ValidatePagination(
		r.URL.Query().Get("page"),
		r.URL.Query().Get("limit"),
	)
	if err != nil {
		apierror.BadRequest(w, err.Error())
		return
	}

	eventType := r.URL.Query().Get("event_type")
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")

	query := `SELECT id, seq, event_time, user_id, action, resource_type, resource_id,
	                 event_type, status, ip_address::TEXT, user_agent, region_code, metadata, hash_prev
	          FROM audit_logs WHERE 1=1`
	countQuery := `SELECT COUNT(*) FROM audit_logs WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if eventType != "" {
		query += fmt.Sprintf(" AND event_type = $%d", argIdx)
		countQuery += fmt.Sprintf(" AND event_type = $%d", argIdx)
		args = append(args, eventType)
		argIdx++
	}
	if startStr != "" {
		start, parseErr := time.Parse(time.RFC3339, startStr)
		if parseErr != nil {
			apierror.BadRequest(w, "invalid start date format, use RFC3339")
			return
		}
		query += fmt.Sprintf(" AND event_time >= $%d", argIdx)
		countQuery += fmt.Sprintf(" AND event_time >= $%d", argIdx)
		args = append(args, start)
		argIdx++
	}
	if endStr != "" {
		end, parseErr := time.Parse(time.RFC3339, endStr)
		if parseErr != nil {
			apierror.BadRequest(w, "invalid end date format, use RFC3339")
			return
		}
		query += fmt.Sprintf(" AND event_time <= $%d", argIdx)
		countQuery += fmt.Sprintf(" AND event_time <= $%d", argIdx)
		args = append(args, end)
		argIdx++
	}

	var total int
	if err := h.pool.QueryRow(r.Context(), countQuery, args...).Scan(&total); err != nil {
		log.Printf("Failed to count audit logs: %v", err)
		apierror.InternalError(w, "failed to query audit logs")
		return
	}

	query += fmt.Sprintf(" ORDER BY seq DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, pg.Limit, pg.Offset)

	rows, err := h.pool.Query(r.Context(), query, args...)
	if err != nil {
		log.Printf("Failed to query audit logs: %v", err)
		apierror.InternalError(w, "failed to query audit logs")
		return
	}
	defer rows.Close()

	var logs []Entry
	for rows.Next() {
		var e Entry
		var userID, resourceID, ipAddr, ua, regionCode, hashPrev *string
		if err := rows.Scan(&e.ID, &e.Seq, &e.EventTime, &userID, &e.Action, &e.ResourceType, &resourceID,
			&e.EventType, &e.Status, &ipAddr, &ua, &regionCode, &e.Metadata, &hashPrev); err != nil {
			log.Printf("Failed to scan audit log: %v", err)
			apierror.InternalError(w, "failed to read audit logs")
			return
		}
		if userID != nil {
			e.UserID = *userID
		}
		if resourceID != nil {
			e.ResourceID = *resourceID
		}
		if ipAddr != nil {
			e.IPAddress = *ipAddr
		}
		if ua != nil {
			e.UserAgent = *ua
		}
		if regionCode != nil {
			e.RegionCode = *regionCode
		}
		if hashPrev != nil {
			e.HashPrev = *hashPrev
		}
		logs = append(logs, e)
	}
	if logs == nil {
		logs = []Entry{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(auditLogResponse{
		Logs:  logs,
		Total: total,
		Page:  pg.Page,
		Limit: pg.Limit,
	})
}
