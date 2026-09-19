# Valt — Kế hoạch refactor (soạn 2026-08-31)

Nguồn: rà soát code trực tiếp ngày 2026-08-31 + thảo luận chiến lược
(xem [decisions.md](decisions.md) cho lý do từng hướng). Mục tiêu refactor:
biến Valt từ "vault có SaaS layer dở dang" thành **MCP credential gate tự host,
thuần Apache-2.0**, với ba key features: dynamic lease, revoke cascade, audit 4W1H.

## A. Kết quả rà code (chân dung hiện trạng)

### Dynamic lease — `internal/dynsecret/` (688 dòng)
- Kiến trúc đúng hướng: `Provider` interface (Create/Revoke/Renew), 1 impl
  `postgres` tạo role tạm `valt_xxxx` (`CREATE ROLE ... VALID UNTIL`, password
  random, CONNECTION LIMIT 5).
- **Đứt gãy chính:** workflow approval KHÔNG gọi dynsecret — lease tạo qua
  endpoint riêng. Luồng "xin quyền → duyệt → nhận dynamic lease" chưa tồn tại.
- Expiry worker 60s chỉ `UPDATE revoked_at` trong DB, không DROP role ở backend
  (role tự chết theo VALID UNTIL nhưng để lại rác vĩnh viễn trong pg).
- TODO trong code: lease credential mã hóa bằng master key, chưa per-project key.
- Chỉ 1 provider; thiếu provider "derived API key" (use case cấp AI per nhân viên).

### Revoke — chỉ theo đơn vị lẻ
- Có `RevokeCredential(requestID)`, `RevokeLease(leaseID)`.
- Không có: `RemoveMember` org (chỉ có add/list), revoke-all theo user, hook IdP.

### Audit — schema tốt, hash-chain có 2 bug thật
- `Entry` đã có `ip_address`, `user_agent`, `region_code`, `metadata`;
  `LogFromRequest` tự điền IP (XFF/X-Real-IP) + UA. Nhưng chỉ 2 call site dùng IP.
- **Bug 1:** `ComputeHash` chỉ hash `prev|user|action|resource|event_type|status`
  — không bao gồm IP, UA, metadata, event_time → sửa các trường đó trong DB
  KHÔNG phá vỡ chuỗi. Chain chưa đúng nghĩa "chống sửa".
- **Bug 2:** `lastHash` chỉ in-memory — không load lại từ DB khi restart, không
  mutex khi ghi đồng thời → chuỗi fork, `VerifyChain` fail.
- Chưa có endpoint verify-chain, export CSV/PDF.

### Khác
- README claim "zero-knowledge" nhưng Phase 10 cho server decrypt rồi trả
  plaintext qua API → sửa claim hoặc làm client-side decrypt (chọn sửa claim trước).
- Client: `valt-cli` đã có thiết kế đúng (`setup`, `mcp install --ide claude`,
  `run` inject env, `request/status`). Release workflow chỉ build CLI
  (GoReleaser, tag `cli/v*`), chưa build MCP server Rust.

## B. Giữ – Cắt – Sửa

**GIỮ:** vault core (envelope encryption), workflow approval + policy engine,
agent identity, audit (sau khi fix), dynsecret, org/workspace/project, MCP server,
valt-cli, docker-compose + scripts VPS, `plans/` (tham khảo).

**CẮT:** landing pricing section, dashboard `/settings/upgrade`, SaaS super-admin
pages, billing package — theo Quyết định 1 (không SaaS). Cắt bằng cách ẩn/xóa route,
giữ migration DB nguyên (không phá dữ liệu người dùng cũ).

**SỬA:** hash-chain (bug 1+2), README (bỏ claim zero-knowledge sai, viết lại theo
định vị credential gate), điền where-context ở mọi call site audit.

## C. Roadmap 90 ngày (thứ tự theo dependency)

| Tuần | Việc | Đầu ra đo được |
|---|---|---|
| ~~1–2~~ ✅ | ~~Fix hash-chain~~ (DONE 2026-09-04, xem §E) | test tái tạo bug 1, 2 → pass |
| ~~3–4~~ ✅ | ~~Where-context + verify + export CSV~~ (DONE 2026-09-19, xem §F) | verify endpoint chạy được trên dữ liệu thật |
| ~~5–8~~ ✅ | ~~Provider "derived API key" + nối workflow approval → dynsecret lease~~ (DONE 2026-09-19, xem §H) | e2e: agent xin → duyệt → nhận lease TTL ngắn (test integration 5 kịch bản pass) |
| ~~9–10~~ ✅ | ~~Revoke cascade (`POST /users/{id}/revoke-all`), `RemoveMember` org, sweeper DROP role~~ (DONE 2026-09-19, xem §I) | 1 lệnh làm chết mọi credential của 1 user |
| 11–12 | Slack approval (từ notify → action), release pipeline MCP server + README mới, tag v1.0 | release có checksum 3 nền tảng |

## D. Việc nhà đã xong / còn treo

- [x] 2026-08-31: dọn binary khỏi repo (server.exe, valt-cli.exe ~36MB,
  repomix-output.xml, tsbuildinfo) + rule .gitignore (commit 2796380).
- [x] 2026-09-03: transfer repo → `ldphuong-vn/vaultsaas`; redirect URL cũ hoạt động.
- [x] 2026-09-04: `git filter-repo` xóa binary khỏi lịch sử + force push
  (master + feat/custom-policy). Repo pack: ~50MB → 1.47MB.
- [x] Known pre-existing (không phải của đợt này): integration test
  `internal/workflow` fail khi chạy song song trên một DB chung — race
  `CREATE EXTENSION pgcrypto` giữa các schema, helper không gọi
  `database.EnsurePartitions`, và một test dựng Handler với notify store nil.
  Đã xác nhận fail giống hệt trên bản code trước fix hash-chain.
  **[FIXED 2026-09-19, xem §H.6]** — helper migrate chung trong `internal/testutil`
  bọc advisory lock; helper workflow gọi `EnsurePartitions`; test policy-e2e
  không còn dựng Handler với notify store nil. Toàn bộ
  `go test ./internal/... ./pkg/...` pass khi chạy song song.

## E. Nhật ký thực hiện — Fix hash-chain (2026-09-04)

Scope: bug 1 + bug 2 trong §A, kèm hai lỗi round-trip chỉ phát hiện được khi
chạy integration test thật.

1. **Hash bao phủ toàn bộ trường** (`hash-chain.go`): preimage v2 = JSON
   canonical của mọi cột (user, action, resource, event_type, status, ip, ua,
   region, metadata, event_time + prev hash). Sửa bất kỳ cột nào trong DB đều
   gãy chuỗi. `computeHashV1` giữ lại chỉ để verify các row cũ (v1 không bao
   phủ ip/metadata/time — ghi chú hạn chế trong code).
2. **Chain head nằm trong DB** (`audit_chain_state`, migration 000042):
   `Log()` chạy một transaction: `SELECT ... FOR UPDATE` state row → gán
   `seq = last_seq + 1` → insert → update state. seq liên tục, đúng thứ tự
   commit, sống qua restart; concurrency an toàn. Bảng `audit_logs` thêm cột
   `seq`, index thường (unique index không đặt được trên bảng partition không
   chứa partition key; tính duy nhất do cursor đảm bảo).
3. **Lỗi round-trip #1 — metadata JSONB**: Postgres render JSONB lại text
   (thêm dấu cách, sort key theo độ dài) làm hash đọc lại ≠ hash lúc ghi.
   Migration 000042 đổi cột sang TEXT (giữ nguyên byte); không có query dùng
   toán tử JSONB trên cột này.
4. **Lỗi round-trip #2 — INET**: `::TEXT` render `10.0.0.1/32`. Thêm
   `canonicalIP()`: lấy entry đầu của XFF, parse bằng netip, chuẩn hóa về dạng
   `addr/NN` trước khi hash; junk → NULL (trước đây junk/líst IP trong XFF
   làm INSERT lỗi cast inet).
5. **Dọn code chết**: xóa `internal/database/audit.go` (`WriteAuditLog` ghi
   row audit NGOÀI chuỗi hash, 0 caller — footgun). `Logger.Log` đổi signature
   trả về `(Entry, error)` kèm id/seq/hash; thêm `AppendChainNoTx` cho caller
   giữ tx riêng. `EnsurePartitions` xuất khẩu từ database package.
6. **Test**: unit (bao phủ trường, phát hiện tamper IP/metadata/time, chuỗi v1
   cũ vẫn verify, `canonicalIP`) + integration trên Postgres thật
   (sống qua restart — tái hiện bug 2; 8 goroutine × 5 log → seq 1..40 liền
   mạch, chuỗi valid; UPDATE thẳng DB → gãy đúng chỗ). Toàn bộ
   `go test ./internal/... ./pkg/...` pass (12 package).

## F. Nhật ký thực hiện — Where-context + verify + export (2026-09-19)

Tuần 3–4 của roadmap §C, trên nền hash-chain v2 đã fix ở §E.

1. **Where-context đầy đủ** (trước đây chỉ 2 call site có IP):
   - Gateway proxy (sự kiện audit quan trọng nhất — agent đi qua): `logProxyRequest`
     giờ nhận IP + user-agent từ request của agent trước khi fire goroutine.
   - `extractIP` → export thành `audit.ExtractIP`; consent handler bỏ bản copy
     cục bộ, dùng chung.
   - System actor (duyệt qua Slack/Telegram): metadata `{"via":"<actor>"}` ghi
     rõ kênh ra quyết định (IP là của nền tảng chat nên không đưa vào ip_address
     — trung thực hơn là misleading).
   - **Seed chèn audit thẳng không có seq/hash → gãy chuỗi ngay từ dữ liệu mẫu**:
     chuyển sang `Logger.AppendChainNoTx` trong tx của seed.
2. **`GET /audit/verify`** (`verify.go` + handler): stream toàn bảng theo seq,
   chain từng entry, dừng ở liên kết gãy đầu tiên. Trả về checked/head_seq/
   head_hash/broken_seq/broken_id. **Tham số `?expected_head=<hash>`** — workflow
   compliance thật: ghi head hash ra ngoài (email/biên bản) lúc audit, sau đó
   verify ngược; head lệch = có row bị xóa ở đuôi (thứ bảng trong-table chain
   không tự phát hiện được). Route chặn bằng admin middleware (dữ liệu chứa IP
   của mọi user); `/logs` giữ quyền member như cũ.
3. **`GET /audit/export.csv`**: stream CSV theo seq ASC, nhận cùng bộ filter
   start/end/event_type như /logs, Content-Disposition attachment. Có guard
   chống CSV formula injection (=, +, -, @, tab, CR ở đầu cell → thêm quote).
4. **Test**: 4 integration mới cho VerifyFromDB (valid/empty/expected_head
   match+mismatch/locate tampered row) + unit cho sanitizeCSVCell. Toàn bộ
   audit suite 19 test pass; full build + go test pass.
5. **Lính mới từ Mimosa scan**: sửa `internal/config/env_loader.go` — đọc
   `.env` bằng `os.ReadFile` thay vì shell-out `powershell Get-Content`/`cat`
   (command injection có thật, code vô lý có sẵn).

## G. Security debt — triage Mimosa deep scan 2026-09-19 (12 findings)

Kết quả scan toàn repo (`~/.mimosa/security-scans/...ed06f041ade5`). Không
finding nào nằm ở các file thay đổi của đợt audit này. **Đã xử lý cùng ngày
(xem cột trạng thái); chỉ còn 3 mục acknowledge-by-owner.**

| Finding | Đánh giá | Trạng thái |
|---|---|---|
| Dashboard SSRF ×4 (`layout`, `secrets/[id]` ×2, `api/auth/refresh`, `api/proxy/[...path]`) | BFF fetch origin cố định từ env, path từ input | ✅ **Đã sửa**: helper chung `lib/backend.ts` — origin luôn từ `BACKEND_URL`, path segment validate (chặn `..`, `\`, CR/LF/NUL) + encode từng segment; 4 call site chuyển sang helper; tsc --noEmit pass |
| `sdk/python/valt/__init__.py` SSRF | Client SDK fetch base_url từ config người dùng | ✅ **Đã sửa**: validate scheme http(s), resolve host và chặn private/loopback/link-local/reserved (opt-out `VALT_ALLOW_PRIVATE_NETWORKS=1` cho local dev), encode path segment |
| `valt-cli/cmd/setup.go:162` command injection | `openBrowser` exec tên binary qua biến + URL chưa validate | ✅ **Đã sửa**: validate scheme http(s) trước, exec literal từng nhánh (`rundll32 url.dll,FileProtocolHandler` cho Windows — tránh builtin `start` qua shell) |
| `test_e2e.sh` + `test_e2e_comprehensive.py` + `run_e2e_tests.sh` hardcoded credentials | Password test + URL production hardcode trong source | ✅ **Đã sửa**: đọc từ env (`VALT_E2E_PASSWORD` bắt buộc, `VALT_E2E_BASE_URL` mặc định localhost:8080); URL production cũ `valt.turbo.ai.vn` không còn default ở test script nào |
| `mcp-server/src/scanner.rs` hardcoded credential | Regex detection patterns cho secret scanner (AKIA…, ghp_…) — dữ liệu sản phẩm, không phải credential | Acknowledged FP — won't-fix |
| `server/cmd/valt/commands/run.go` + `valt-cli/cmd/run.go` command injection | **By design** — `valt run -- <cmd>` là executor cục bộ (mô hình `op run`), args tách rời không qua shell. Write-hook của Mimosa chặn cả ghi comment vào 2 file này | Acknowledged by-owner — won't-fix; nhắc lại trong `--help` khi chạm vào file lần tới (tuần 11–12 release pipeline) |
| `SOC-SIEM-HIPAA`, `echeckin-proposal` path traversal | Khác dự án (hook quét cả workspace) | Ngoài phạm vi vaultsaas |

Lưu ý quy trình: hook commit của Mimosa quét theo workspace (không phải theo
diff) với mẫu ngẫu nhiên mỗi lần → chặn cả commit không dính finding. Anh
(chủ repo) đã chọn phương án xử lý: sửa hết finding có thể sửa của vaultsaas
trước khi commit (mục ✅ phía trên); 2 mục acknowledged còn lại được chấp nhận
rõ ràng, có lý do ghi ở đây.

## H. Nhật ký thực hiện — Tuần 5–8: derived API key + nối approval → lease (2026-09-19)

Deliverable của §C: e2e "agent xin → duyệt → nhận lease TTL ngắn". Migration
000043 (`dynamic_provider_link`) gom 3 thay đổi schema của đợt này.

1. **Provider `derived_api_key`** (`internal/dynsecret/derived_key.go`): config
   giữ `master_key` (key AI API của công ty). `Create` trả
   `valt_dk_<HMAC-SHA256(master_key, nonce 16B)>` — một chiều, không suy ra
   được master key, và upstream thật không chấp nhận key này: nó chỉ có nghĩa
   với Valt. Lease lưu `key_hash` (SHA256 hex) trong `dynamic_leases` để tra
   O(1); raw key chỉ nằm trong `secret_data_enc` đã mã hóa. `Revoke`/`Renew`
   là no-op phía backend — DB là nguồn chân lý (revoke = đánh dấu `revoked_at`).
2. **Verify + tiêu thụ key dẫn xuất**:
   - `Service.ValidateDerivedKey` — hash-lookup, trả nil khi key lạ/lease
     hết hạn/revoke/provider bị disable.
   - Gateway proxy xác thực được key dẫn xuất (`authenticateRequest`): agent
     token (Proxy-Authorization) + key dẫn xuất (Authorization) đồng thời,
     hoặc key dẫn xuất một mình. Lease cấp cho agent nào thì agent đó dùng
     (binding check); khi tiêu thụ, gateway **hoán** key dẫn xuất thành
     master key theo config `injection_type`/`injection_key` (mặc định bearer)
     — key dẫn xuất không bao giờ tới upstream, master key không bao giờ tới
     client.
3. **Nối secret ↔ provider**: cột `secrets.dynamic_provider_id` +
   `PUT/DELETE /secrets/{id}/dynamic-provider` (owner, hoặc member đủ quyền
   write khi secret thuộc project). Provider phải active và cùng project.
4. **Approval → lease** (`internal/workflow/lease.go`, `LeaseIssuer`): 4 điểm
   phát credential (auto-approve, Approve, email action-token, ApproveBySystem)
   đều đi qua một lỗ: secret có provider → mint lease TTL ngắn
   `min(requested_duration, 3600s)` gắn `access_request_id`/`agent_id` thật;
   session ghi `lease_id` để không phá luồng CLI/agent hiện có. **Fail
   closed**: mint lỗi → không có credential nào được cấp, tuyệt đối không
   fallback về giá trị tĩnh (chính là thứ provider này dùng để giữ lại).
   Audit `lease.create` ghi approver (user_id UUID) hoặc NULL + `decided_via`
   cho auto-approve. `GET /credentials/{request_id}` trả `credentials` của
   lease (fail closed khi lease chết) — KHÔNG decrypt secret tĩnh;
   `GET /credentials/active` cũng vậy ( vá luôn đường rò giá trị tĩnh qua
   endpoint list). Revoke session → revoke lease (và ngược lại credential
   chết ngay).
5. **Test**: unit cho format key/HMAC/hash + gateway header parsing;
   integration 5 kịch bản (`lease_issuer_integration_test.go`) trên Postgres
   thật: e2e xin→duyệt→nhận key→verify→revoke; explicit approval; TTL cap;
   fail-closed (không session nào tồn tại khi mint lỗi); static path không
   đổi. Full suite 13 package pass (xem 6).
6. **Fix luôn nợ kỹ thuật §D** (pre-existing): helper apply-migrations chung
   `internal/testutil.ApplyMigrations` bọc `pg_advisory_lock` — hết race
   `CREATE EXTENSION pgcrypto` khi chạy song song; helper workflow gọi
   `EnsurePartitions`; test policy-e2e không còn dựng Handler với notify
   store nil (truyền nil notifySvc — test đo policy, không đo notification).
   `go test ./internal/... ./pkg/...` giờ pass khi chạy song song trên một DB.

## I. Nhật ký thực hiện — Tuần 9–10: revoke cascade + sweeper (2026-09-19)

Deliverable của §C: "1 lệnh làm chết mọi credential của 1 user". Migration
000044 (`lease_backend_sweep`) thêm `dynamic_leases.backend_swept_at` +
partial index cho truy vấn sweeper.

1. **`POST /users/{user_id}/revoke-all`** (`internal/workflow/revoke.go`,
   `RevokeService`): ủy quyền = global admin (`users.role='admin'`) hoặc
   chính chủ (trường hợp mất laptop). Cascade 4 bước, trả summary:
   - **Leases** (`dynSvc.RevokeLeasesForUser`): mọi lease active mà
     `access_request.requester_user_id` = user HOẶC `lease.agent_id` thuộc
     agent `created_by` user. Lease postgres được DROP ROLE best-effort ngay
     (sweeper là lưới dự phòng); key dẫn xuất chết theo `revoked_at`.
   - **Credential sessions**: active session sinh từ request của user hoặc
     session có `lease_id` thuộc lease của agent user — giết cả static lẫn
     lease-backed.
   - **Agent tokens + identities**: revoke `agent_tokens` trực tiếp
     (phát hiện thật: `ValidateToken` KHÔNG kiểm tra
     `agent_identities.status` — disable identity không đủ, token phải
     revoked) rồi mới `status='disabled'` cho identity.
   - **Access requests**: đánh dấu `'revoked'` cho request approved của user
     và của agent user. Audit 1 entry `user.revoke_all` kèm summary JSON.
   - Bug nhỏ sửa trong lúc test: `access_requests.ai_agent_id` là
     VARCHAR(255) còn `agent_identities.id` là UUID → so sánh phải qua
     `::text` (error `character varying = uuid` thật trên PG).
2. **`RemoveMember` org** (`DELETE /orgs/{org_id}/members/{user_id}`): chỉ
   org owner/admin được gọi (`callerIsAdminOrOwner` có sẵn); cấm xóa owner
   (transfer ownership trước); xóa org membership + **cascade** xóa
   project_memberships trong toàn bộ workspace của org — không để lại quyền
   cấp project sống sót. Sentinel errors (`ErrRemoveOwner`,
   `ErrMemberNotFound`, `ErrOrgNotFound`) map 400/404/403 rõ ràng.
3. **Sweeper DROP role** (`internal/dynsecret/sweep.go`): expiry worker 60s
   giờ chạy thêm `SweepExpiredBackends` — lease hết hạn quá grace 5 phút và
   chưa swept → DROP backend credential rồi đánh dấu `backend_swept_at`.
   Idempotent + resume được qua restart; DROP lỗi để NULL cho tick sau retry
   (role không thể bị bỏ rơi âm thầm). Provider không có backend object
   (derived key) chỉ đánh dấu.
   **Bug thật bắt được nhờ test trên PG thật**: `DROP ROLE` fail
   `2BP01` vì `GRANT CONNECT` lúc Create tạo dependency trên role. Sửa
   `PostgresProvider.Revoke`: `REVOKE CONNECT` + `DROP OWNED BY` trước
   `DROP ROLE` (best-effort, DROP ROLE là chốt).
4. **Test**: sweeper integration 3 kịch bản trên instance thật (tạo role
   thật → hết hạn → sweep → role biến mất trong `pg_roles`; derived chỉ
   đánh dấu; grace window giữ nguyên); revoke-all e2e 2 user (target chết
   toàn bộ 2 lease + 3 session + 2 token + 1 agent; control user giữ nguyên
   toàn bộ); authz matrix HTTP 5 case (self/admin/other/unknown/anon);
   RemoveMember cascade + guards. Full suite 14 package pass song song.
