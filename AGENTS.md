# AGENTS.md

Guidance for AI coding agents working in the Axion monorepo.

## What this repo is

Enterprise AI platform monorepo: **Turborepo + pnpm**, a **Next.js** frontend
(`apps/web`) and a **FastAPI** backend (`apps/api`) using **Beanie/PyMongo async** against
MongoDB, with Clerk for authentication. Product requirements live in
`docs/specs/srs-01-project-management.md` and `docs/specs/srs-02-project-secrets-management.md`.

## Commands

```powershell
# Frontend / monorepo
pnpm install
pnpm dev                 # turbo dev (web + api)
pnpm --filter web dev    # Next.js only
pnpm lint                # turbo lint
pnpm typecheck
pnpm generate:api        # regenerate OpenAPI types after API contract changes

# Backend (run from apps/api)
uv sync --extra dev                       # or: .\.venv\Scripts\python.exe -m pip list
.\.venv\Scripts\python.exe dev.py         # Windows-safe reload; watches app/ only
.\.venv\Scripts\python.exe -m pytest -q   # full suite, no live DB required
.\.venv\Scripts\python.exe -m ruff check app tests
```

The test suite mocks MongoDB, so it must pass without a running database. Never make a test
depend on a live Mongo instance or on network access to Clerk.

**Never add `--reload` back to the API dev script.** Uvicorn's Windows restart path uses
`CTRL_C_EVENT` + an unbounded `process.join()`, so reloads silently do not take effect or
leave the API dead behind a bound port. `apps/api/dev.py` supervises uvicorn instead — see
`docs/learnings.md` lesson 11.

## Backend architecture (do not bypass layers)

```
app/api/v1/endpoints  -> HTTP parsing, status codes, response envelope
app/services          -> business rules, FSM, authorization, orchestration
app/repositories      -> ALL MongoDB access (Beanie + raw PyMongo)
app/models            -> Beanie Document classes and indexes
app/schemas           -> Pydantic request/response models
app/core              -> config, exceptions, logging, crypto, security
app/middleware        -> request id, logging, rate limiting, CORS, security headers
```

- Endpoints never touch the database; services never build Mongo queries beyond what the
  repositories expose; repositories never raise HTTP exceptions — raise the domain errors
  from `app/core/exceptions.py` instead.
- Instantiate collaborators through the existing `get_*_repository()` / `get_*_service()`
  dependency providers, and keep constructor parameters optional so tests can inject fakes.
- Keep the response envelope and `error.code` values consistent with existing endpoints.

## Non-negotiable invariants

1. **Never set `is_root = True` on `BaseDocument`** (or any shared document base). Beanie
   would merge every model into one collection and combine their indexes, which produced
   false `409` conflicts across unrelated documents. Each model declares its own
   `class Settings: name = "..."`.
2. **Serialise values before raw PyMongo writes.** Any hand-written
   `find_one_and_update` / `update_one` / `insert_many` payload must pass through
   `app.repositories.base.serialize_for_mongo`. Pydantic models such as
   `EncryptedEnvelope` are not BSON-encodable and raise
   `bson.errors.InvalidDocument` otherwise.
3. **Translate `DuplicateKeyError` by index.** Inspect `exc.details["keyPattern"]`; only
   report the constraint that actually failed, and keep a generic fallback message.
4. **Use OCC for mutations.** Filter on the expected `version`/`revision`, use
   `ReturnDocument.AFTER`, and only on `None` reload to distinguish `404` / `409` /
   invalid state transition (`project_repository.update_with_version`,
   `.transition_status`, `secret_repository.update_with_revision`).
5. **Respect status scoping.** Slugs are reserved for every non-`PURGED` project. Listing
   flags are additive (`include_archived` never reveals `SOFT_DELETED`), and `PURGED`
   projects are never listed.
6. **Catch narrowly.** Do not turn infrastructure failures into `404`s; only `ValueError`
   for malformed ObjectIds is treated as "not found".
7. **Secrets stay opaque.** Never log or return plaintext outside the audited `/reveal`
   endpoint, and keep request bodies redacted in logs.
8. **Standalone MongoDB.** Local development has no replica set, so `session=` /
   transactions are unavailable. Use compensating actions and document any partial-failure
   window.

## Testing conventions

- `pytest` with `asyncio_mode = "auto"`; fixtures in `tests/conftest.py` disable rate
  limiting and mock DB init.
- Prefer in-memory repositories (see `tests/test_projects.py`) or `AsyncMock` specs over
  hitting MongoDB.
- When changing a repository signature, update its in-memory fake in `tests/` as well.
- Add a regression test for every bug fix; name it after the failure mode
  (e.g. `test_update_with_revision_persists_envelope_as_document`).
- Live end-to-end smoke test for secrets: `tests/e2e_secrets_test.py` (requires a running
  API and a `dev-token-*` bearer token).

## Database notes

- Collections: `users`, `projects`, `project_members`, `project_audit_logs`,
  `project_secrets`.
- MOD-07 (tools & integrations): `project_integrations`, `project_tools` (discovery-owned definitions),
  `project_tool_settings` (admin-owned, keyed by `tool_key`), `tool_bindings`, `project_end_users`,
  `tool_invocations` (30-day TTL). See `docs/specs/srs-07-tool-and-integration-management.md`.
- MOD-07 connections: `integration_connections` (one per `(integration, subject)`, AES-GCM envelopes bound to
  project/integration/subject), `integration_connect_sessions` (hashed link and state, TTL), `integration_oauth_clients`,
  `project_tool_policies`, `project_app_resources` (MCP App HTML, hash-pinned; never rendered unless an admin approved
  the current hash). Set `PUBLIC_API_BASE_URL` to the externally reachable API URL: it builds OAuth redirect URIs
  and connect links. Never log request paths or queries raw: connect-link tokens are in the path
  (`app/middleware/logging.py#sanitize_path`).
- Unique indexes: project `slug`; member `(project_id, user_id)`; secret
  `(project_id, environment, name)` with `is_deleted: False`.
- MCP sessions are pooled (`app/integrations/mcp_pool.py`). Never open an SDK session outside the connector: SDK
  sessions use `anyio` task groups that must be entered and exited in one task, which the pool guarantees with a
  dedicated owner task per session. Tunables: `MCP_POOL_ENABLED`, `MCP_POOL_IDLE_SECONDS`,
  `MCP_POOL_PER_USER_IDLE_SECONDS`, `MCP_POOL_MAX_PER_INTEGRATION`, `MCP_POOL_MAX_TOTAL`, `TOOL_MAX_CONCURRENT_CALLS`, `TOOL_CONCURRENCY_WAIT_SECONDS`,
  `MCP_LIST_CHANGED_DEBOUNCE_SECONDS`.
- MOD-07 layering: services depend on ports (`app/core/tools`), never on `app/repositories`, `app/integrations`,
  the MCP SDK, or HTTP libraries; only `app/services/tools/providers.py` wires concretes. Never branch on
  integration/auth type outside the registries. `tests/test_tools_architecture.py` enforces this.
- Toolset *listings* are cached (`ToolsetCache`, 30 s, invalidated by `ToolsetChanged`); invocation must always resolve
  fresh via `resolve_one`. Anything that changes what a subject may see must publish `ToolsetChanged`.
- Before dropping/altering a collection, check `docs/learnings.md` for migration context.

## Memory protocol

`docs/learnings.md` is the engineering memory for this repo. When you discover a
non-obvious bug, a framework pitfall (Beanie, PyMongo, FastAPI), or a workflow that cost
time, add a concise entry there: symptom, root cause, fix, file references, how it was
verified. When you fix or invalidate an item under "Known issues", move it to the fixed
section instead of deleting it silently. Keep this file (AGENTS.md) about rules and
commands; keep incident detail in `docs/learnings.md`.
