# Valt — the MCP credential gate for AI agents

[![CI/CD](https://github.com/ldphuong-vn/vaultsaas/actions/workflows/ci.yml/badge.svg)](https://github.com/ldphuong-vn/vaultsaas/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Your AI agent needs an API key. Today you paste a long-lived production key into its config — and it stays there, forever, on every machine the agent runs on, with no record of what the agent did with it.

**Valt flips that.** It is a self-hosted gate that sits between your AI agents and your credentials: agents *request* access, a human *approves*, the agent receives a **short-lived lease** that auto-expires, and every step lands in a **tamper-evident audit trail**. Like issuing a laptop to an employee — except for AI credentials.

```
Agent ──"I need this key for 30 min"──▶ Valt ──▶ Human approves (dashboard / Slack / email)
  ▲                                       │
  └────── short-lived credential ◀────────┘
              every request audited, revocable in one command
```

## Who is it for

- **Solo founders** shipping AI features: give your agents real credentials without leaving production keys scattered in config files and `.env` copies.
- **IT / platform teams**: onboarding an employee to AI tooling becomes provisioning — an agent identity, a policy, short leases. Offboarding is one command that kills every credential they (and their agents) hold.
- **Dev teams** building agent features: your agents talk to Valt through standard MCP tools (`request_access` → `get_credential`) instead of you building secret handling into each agent.

## Why Valt (and not just a secrets manager)

| | Static secret store | Valt |
|---|---|---|
| What the agent holds | The real, long-lived key | A lease that expires in minutes-to-hours |
| Getting access | Whoever has read access to the store | Per-request approval, policy-gated (reason, duration, cooldown, daily limits) |
| Revoking one person | Hunt for every copy | `POST /users/{id}/revoke-all` — leases, sessions, agent tokens die together |
| Audit | Who read the secret, maybe | Who asked, why, where from (IP + user agent), who approved, with a hash chain you can verify |

For **dynamic backends** Valt goes further: it mints throwaway credentials that never existed before the request — a temporary Postgres role (`CREATE ROLE ... VALID UNTIL`), or a derived API key (`valt_dk_…`) HMAC'd from your master key, which no upstream API accepts and only Valt understands — your real key never leaves the vault.

## How it works

```
                        ┌── dashboard / Slack / email / Telegram ──▶ Human (approves)
                        │
ZCode · Claude Code ·   │ 1. request_access(secret, reason, ttl)
Cursor ──MCP/stdio──▶ valt-mcp-server ──HTTPS──▶ Valt server
                        │ 2. check_status → approved          │  approval → lease minted
                        └─ 3. get_credential ────────────────┘  audit: who/what/when/where/why/how
```

One server, three ways to consume credentials:

1. **MCP tools** (agents): `request_access` → human approves → `get_credential`. Works with any MCP client — Claude Code, Claude Desktop, Cursor, ZCode.
2. **CLI injection** (humans & scripts): `valt run -- ./deploy.sh` runs your command with approved secrets injected as environment variables.
3. **Gateway proxy** (existing tooling): point tools at the proxy with a `valt_pk_` placeholder; the real credential is injected inline on the way out.

## Quick start

**1. Run the server** (Docker, self-hosted — no cloud dependency):

```bash
git clone https://github.com/ldphuong-vn/vaultsaas.git
cd vaultsaas
cp .env.example .env
docker compose up -d
make migrate-up
# API: http://localhost:8080 · Dashboard: http://localhost:3000
```

**2. Set up your machine** (one-time; installs the two clients):

```bash
valt setup                    # login, stores token in your OS keychain
valt mcp install --ide claude # wires valt-mcp-server into Claude Code / Cursor / VS Code
```

**3. First request** — from your AI tool, or from a terminal:

```
Agent: request_access(secret_id, reason="generate weekly report", duration_minutes=30)
You:   approve on Slack / dashboard
Agent: get_credential → usable for 30 min, then gone
```

```bash
valt request prod-db-api       # same flow, human-typed
valt run -- ./report.sh        # approved secrets injected as env vars
```

**4. Make a secret dynamically leased** — link it to a provider, and approvals mint fresh credentials instead of handing out the stored value:

```bash
# create a derived_api_key provider (your master key never leaves Valt),
# then link: PUT /secrets/{id}/dynamic-provider  {"provider_id": "..."}
```

## What's inside

| Component | Tech | What it does |
|---|---|---|
| `server/` | Go | Vault (envelope encryption), approval workflow + policy engine, dynamic lease providers, gateway proxy, audit hash-chain |
| `dashboard/` | Next.js | Approvals, secrets, agents, audit review |
| `mcp-server/` | Rust | The local MCP bridge agents talk to (stdio or HTTP transport) |
| `valt-cli/` | Go | The single entry point: setup, IDE wiring, request/status/run |
| `sdk/python` | Python | Client SDK for custom integrations |

### Feature status

Shipped and tested (integration tests run against real Postgres):

- **Dynamic leases** — Postgres temporary roles (auto-expiring, swept clean after expiry) and derived API keys (HMAC-based, validated by hash, swapped for the master key at the gateway)
- **Approval workflow** — dashboard, Slack, email action links, Telegram; policy engine per secret (max duration, reason required, cooldowns, daily limits, auto-approve tiers)
- **Revoke cascade** — one command kills all leases + credential sessions + agent tokens of a user; org member removal cascades project access
- **Audit 4W1H** — every event with IP/user-agent context, SHA-256 hash chain (covers all fields, survives restarts, concurrency-safe), `GET /audit/verify` with `?expected_head=` off-site anchoring, CSV export with formula-injection guard
- **Secret scanning** — local scans for leaked credentials, exposed through MCP

On the roadmap toward v1.0: cloud STS lease providers (start with Alibaba Cloud), SSH certificate issuance, Slack interactive approvals refinement, signed multi-platform releases (CLI pipeline ships 3 platforms; MCP server pipeline ships 6 targets).

## Security model, honestly

- Secrets are encrypted at rest (AES-256-GCM envelope encryption; blobs in MinIO, DEKs wrapped with the master key). **The server does decrypt** approved secrets to deliver them — Valt is not zero-knowledge; it is *least-knowledge*: the standing state is always ciphertext, plaintext exists only at approved delivery time.
- Credentials issued to agents are **leases with TTLs**; for derived keys the master key never leaves the server and the issued key is useless to anything but Valt's gateway.
- The audit log is a **hash chain** — editing any row (IP, metadata, timestamps) breaks verification. Verify against an off-site anchor hash to also detect tail truncation.
- Agent tokens live in the OS keychain, not in agent configs. On headless Linux, fall back to environment variables in a protected service unit.
- Self-hosted only. Your approval flow, your keys, your audit data — nothing leaves your infrastructure. Pure Apache-2.0, no `ee/` directory, no feature gates, no CLA.

See [docs/security-model.md](docs/security-model.md) for details and [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## Documentation

- [Security model](docs/security-model.md) — encryption, auth, audit chain
- [System architecture](docs/system-architecture.md)
- [Deployment guide](docs/deployment-guide.md) — dev + single-VPS production
- [Decision log](docs/decisions.md) — why Valt is what it is (and isn't)
- [Refactor plan](docs/refactor-plan.md) — living roadmap with change logs

## Development

```bash
make help    # all commands
make dev     # dev environment
make test    # all tests
make lint    # linters
make build   # build services
```

Status: **v0.x, hardening toward v1.0.** APIs may still change — pin versions and read the changelog in `docs/`.

## License

Apache License 2.0 — see [LICENSE](LICENSE). Contributions welcome; by contributing you agree your contributions are licensed under the same terms.
