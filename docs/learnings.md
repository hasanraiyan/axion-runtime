# Learning

Engineering memory for the Axion API (`apps/api`). Every non-obvious bug fix should add a
lesson here so the same class of failure is not reintroduced. Keep entries factual, point at
files, and record how the fix was verified.

---

## How the backend is wired

- **4 layers**: `app/api/v1/endpoints` (HTTP + validation) → `app/services`
  (business rules, FSM, authorization) → `app/repositories` (all MongoDB access) →
  `app/models` (Beanie `Document` classes). Schemas live in `app/schemas`, cross-cutting
  code in `app/core` (config, exceptions, crypto, security).
- **Dependency injection**: every repository exposes `get_*_repository()`; every service
  exposes `get_*_service()` returning `Depends(...)`. Services accept repositories as
  optional constructor arguments so tests can inject fakes.
- **Responses** always use the envelope in `app/schemas/common.py`
  (`success`/`data`/`message`, errors as `error.code` + `error.message`), produced by the
  exception handlers in `app/main.py`.
- **Local MongoDB is standalone** (no replica set), so `session=` / multi-document
  transactions are not available in development. Compensating actions are used instead.

---

## Lessons learned

### 1. `BaseDocument.is_root = True` merges every collection

`apps/api/app/db/base.py` originally declared `is_root = True`. In Beanie, `is_root` means
"all subclasses share this document's collection", so `User`, `Project`, `ProjectMember`,
`ProjectAuditLog` and `ProjectSecret` were all written to a single `BaseDocument`
collection and **all of their index definitions were merged**. The partial unique index
`(project_id, user_id)` then collided across unrelated document types on missing fields
(`null` == `null`), and project creation returned
`409 CONFLICT: Project with slug '...' already exists` while the `projects` collection was
empty.

- Rule: never mark a shared base document as `is_root`. Each concrete model declares its
  own `class Settings: name = "..."`.
- Guarded by `tests/test_db.py::test_base_document_metadata`
  (`get_settings().is_root is False`, distinct collection names).

### 2. A `DuplicateKeyError` does not tell you which index failed

Repositories must inspect `exc.details["keyPattern"]` before mapping the error to a
domain conflict. The old code mapped _any_ duplicate key on `projects` to "slug already
exists", which hid the shared-collection problem. Handle an empty/missing `keyPattern`
separately (falls back to a generic 409 message). Applied in
`project_repository.create`, `project_member_repository.create`, `secret_repository.create`.

### 3. Slug uniqueness spans every non-purged state

The unique index on `Project.slug` covers all documents, so reserving a slug only while a
project is `ACTIVE` lets a new project take the slug of an `ARCHIVED`/`SOFT_DELETED` one.
Restoring/unarchiving the old project then fails at the database. `ProjectService`
therefore reserves slugs for everything except `PURGED`.

Consequence: creation is still a check-then-insert (TOCTOU). The repository's
`DuplicateKeyError` → 409 mapping is the authoritative defence; the service check only
produces nicer messages.

### 4. Multi-step writes need compensation, not transactions

`create_project` inserts the project and then its OWNER membership, and `purge_project`
updates the project, deletes members, deletes secrets and writes audit logs. With a
standalone MongoDB there is no transaction, so a failure in the middle leaves partial
state. `create_project` now deletes the freshly created project if the member insert fails
(so the slug is not orphaned); the purge path is still best-effort (see known issues).

### 5. Beanie serialization does not apply to raw PyMongo calls

`model_class.get_pymongo_collection()` returns the plain PyMongo collection. Anything put
into `$set` must already be BSON-encodable. Passing a Pydantic model crashed secret
rotation with:

```
bson.errors.InvalidDocument: cannot encode object: EncryptedEnvelope(...)
```

Fix: `app/repositories/base.py::serialize_for_mongo` recursively converts `BaseModel`,
`Enum`, `Mapping` and sequences. Use it in **every** hand-written `find_one_and_update` /
`update_one` / `insert_many` payload (`secret_repository.update_with_revision`,
`project_repository.update_with_version`, `project_repository.transition_status`).

Verified two ways: `tests/test_secrets_repository.py` inspects the payload sent to PyMongo,
and a live run against local MongoDB rotated → decrypted → soft-deleted → purged a secret,
plus the 13-step `tests/e2e_secrets_test.py` HTTP suite.

### 6. Optimistic concurrency control pattern

Atomic updates filter on the expected revision/version, use `ReturnDocument.AFTER`, and
only when the result is `None` load the document to distinguish
not-found / wrong-state / version-conflict. Keep that ordering so clients get `404`,
`409` or `InvalidStateTransitionError` instead of a generic 500.

### 7. Listing filters must be additive, not inclusive

`include_archived` must add `ARCHIVED` only; it must never reveal `SOFT_DELETED`
(a previous `if not include_archived and not include_deleted` branch did nothing when both
flags were set). `PURGED` projects are never listed. Implemented through
`list_by_ids(..., statuses=[...])`.

### 8. Repository error handling must be narrow

`BaseRepository.get_by_id` used to catch `Exception` and return `None`, turning database
outages into `404 Not Found`. It now only swallows `ValueError` for malformed ObjectIds.
Apply the same rule everywhere: translate expected domain errors, let infrastructure
errors bubble up.

### 9. In-memory test doubles must follow repository signature changes

`tests/test_projects.py` overrides `ProjectRepository`; adding `statuses=` to
`list_by_ids` required the fake to accept and filter on it. When changing a repository
signature, grep for subclasses/fakes in `tests/`.

### 10. Secrets are never returned in plaintext

Listing/detail responses expose metadata only; plaintext requires the `/reveal` endpoint,
which returns `Cache-Control: no-store` and emits a `SECRET_REVEALED` audit event. Request
bodies are redacted by the logging middleware. Nested `EncryptedEnvelope` values must stay
opaque in logs.

### 11. Uvicorn's `--reload` silently does nothing on Windows (and can strand the API)

**Symptom.** `pnpm dev` prints `WatchFiles detected changes in '...'. Reloading...` and then
the code change never takes effect — the same worker PID (and its start time) keeps serving.
Sometimes the log instead shows `Shutting down` → `Finished server process [N]` with **no**
following `Started server process`, and the API stops answering while the process tree is
still alive.

**Root cause.** In `uvicorn/supervisors/basereload.py::restart` the Windows branch does:

```python
if sys.platform == "win32":
    os.kill(self.process.pid, signal.CTRL_C_EVENT)   # cannot target a process group
self.process.join()                                  # unbounded wait
```

Windows only allows `CTRL_C_EVENT` to be broadcast to the whole console, not to a specific
process group, so the worker frequently never receives it and `join()` blocks. The old
worker keeps serving stale code; if the worker does exit while the supervisor is idle, the
supervisor never notices and never spawns a replacement, leaving the listening socket bound
but unserved ("the server is up but dead").

Not a crash: the shutdown handler runs normally (`Closing MongoDB client connections...`,
`MongoDB connections closed.`) and there is no traceback. Nothing in app code exits.

**Fix.** `apps/api/dev.py` replaces only the supervisor: it runs uvicorn as a plain child
(no `--reload`), watches `apps/api/app` with `watchfiles`, and restarts the child with
`terminate()` (`TerminateProcess`), which always works on Windows. `apps/api/package.json`
now runs `uv run python dev.py`. `tests/`, `.venv/`, caches and `openapi.json` are outside
the watch root, so tooling no longer triggers churn.

**Verified** three ways: (a) the stock reloader, asked to reload a scratch app, logged
`Reloading...` and kept the same worker PID serving stale code; (b) killing a worker under
the stock supervisor showed it cannot recover reliably; (c) `dev.py` on port 8001 restarted
the real app on a file touch, logged a new `Started server process [N]`, reused the port
with no `WinError 10048`, and `/api/v1/health` stayed `200`.

### 12. `partialFilterExpression` cannot express "field is not null", and one bad index kills every index

**Symptom.** Startup logged
`MongoDB connection could not be established: Error in specification { partialFilterExpression: { expires_at: { $ne: null }, ... } } :: caused by :: Expression not supported in partial index: $not / expires_at $eq null`,
`code 67 CannotCreateIndex`, and the API came up with DB endpoints dead. No traceback, no
crash — just one warning line.

**Root cause.** MongoDB rewrites `{"expires_at": {"$ne": None}}` into
`$not: {expires_at: {$eq: null}}`, and `$not` is not in the allowed partial-filter operator
set (`$eq`, `$exists`, `$gt/$gte/$lt/$lte`, `$type`, `$and`, `$or`, `$in`). Because
`util_models` index creation runs inside `init_beanie` (`app/db/client.py::init_db`), the
failure aborts initialization for **all** models, so `users`, `projects`, etc. also lose
their indexes until the offending specification is fixed.

**Fix.** `app/models/credential.py::idx_credentials_active_expiration` now filters on the
leading `status` key only: `partialFilterExpression={"status": "active"}`. The sweeper query
`{status: "active", expires_at: {"$lte": now}}` still gets an `IXSCAN` on the compound key
and the filter prunes revoked/expired credentials automatically.

**Why not `$type: "date"` or `$exists: true`?** Probed against the local MongoDB 9.0:
`{"expires_at": {"$type": "date"}}` builds successfully but the planner refuses to use that
index for `expires_at: {"$lte": ...}` (`index_used=False`, no rejected plans) — it is a
silent no-op index. `{"$exists": True}` is usable, but Beanie always writes
`expires_at: null`, so every document satisfies it and the filter does nothing.

**If the index already exists elsewhere** with different options under the same name,
`init_beanie` now fails with `IndexOptionsConflict` (code 85). Drop it once
(`db.project_credentials.dropIndex("idx_credentials_active_expiration")`) and restart;
the previous build never succeeded, so there should be nothing to drop.

**Verified.** `apps/api/tests/test_credentials_foundation.py::test_credential_partial_index_filters_use_supported_operators`
walks every `partialFilterExpression` on `ProjectCredential` and fails on any operator
outside the allowed set (`$ne`/`$not` regression). Startup was re-run against the local
MongoDB and the collection's indexes were created without warnings.

### 13. Model limits must come from the provider payload, and "unknown" must stay `NULL`

**Symptom.** The `/live-models` payload reported `max_input_tokens`/`max_output_tokens`/
`default_temperature` for every model even when nothing was known, and once a catalog row
was discovered, its limits were frozen forever. Users could not tell which numbers were
the provider's and which were ours.

**Ground truth.** `apps/api/sandbox/live_models.py` is a standalone probe (no DB, no Clerk)
that calls a provider's model endpoint and saves the untouched JSON under `sandbox/out/`
(`--normalize` also records what our mapper extracts). The captured Google
`GET /v1beta/models` response shows what the API really states per model:
`inputTokenLimit`, `outputTokenLimit`, `temperature`, `maxTemperature`, `thinking`,
`supportedGenerationMethods`. Google reports `gemini-2.5-flash` as 1,048,576 in / 65,536 out,
temperature 1 (range 0-2), `thinking: true`; `gemini-embedding-001` as 2,048 in and
`outputTokenLimit: 1`, which is **not** a generation cap.

**OpenAI publishes nothing.** The same probe against OpenAI's `GET /v1/models` returns only
`id`/`object`/`created`/`owned_by`/`shutdown_date` — no limits, no temperature, no
capabilities. So `provider_type=openai` legitimately yields `NULL` for all of them at every
token count; any non-null value there would be fabricated.

**Upstream field mapping (OpenAI-compatible `/v1/models`)**: `created`/`created_at` →
`created_at_upstream` (ISO-8601 accepted); `max_input_tokens`/`context_length`/`max_model_len`/
`max_context_length` → `max_input_tokens`; `max_output_tokens`/`max_completion_tokens`/
`top_provider.max_completion_tokens` → `max_output_tokens`; `temperature`/`default_temperature`/
`default_parameters.temperature` → `default_temperature`; `architecture.input_modalities` →
`supports_vision`; `supported_parameters` (+ OpenRouter's `reasoning` block) →
`supports_tools`/`supports_json_mode`/`supports_reasoning` (a capability is `null` when the
server publishes neither). Streaming is never inferred from a `/v1/models` payload.

**Verified against live OpenRouter** (435 models, `--provider openrouter`): 435/435 context
lengths, 429/435 completion caps, 93 default temperatures, and tool/vision/JSON/reasoning flags
where the listings state them; `supports_streaming` stays `null` because nothing in the payload
claims it.

**Fix.**
1. `infer_gemini_model()` (`app/services/provider_service.py`) maps only those fields:
   `thinking` → `supports_reasoning`, `supportedGenerationMethods` → `model_type` +
   `supports_streaming`, `maxTemperature` → `max_temperature`, and drops the bogus output
   cap for `embedContent` entries. Tools/vision/JSON-mode stay `None` because `models.list`
   never reports them.
2. `infer_openai_compatible_model()` handles every other provider type. It reads only what
   the server publishes: OpenAI itself states nothing, while OpenRouter adds
   `context_length`, `top_provider.max_completion_tokens`, `architecture.input_modalities`
   and `supported_parameters`, and vLLM adds `max_model_len`. Capabilities are derived from
   `supported_parameters` / `input_modalities` and stay `None` when those lists are absent
   (absent list = unknown, not "unsupported").
3. `discover_models` overwrites every attribute upstream states (a corrected limit now
   replaces a stale/fabricated one) and stores `NULL` for what upstream omits.
   `ProjectModel.supports_*`/`default_temperature` and the corresponding API schemas are
   `Optional` so "unknown" survives the round-trip instead of becoming `True`/`0.7`.

**Verified.** `tests/test_gemini_live_model_mapping.py` runs against a trimmed copy of the
captured payload (`tests/fixtures/gemini_models_live.json`) and asserts the real numbers,
the embedding suppression, and that no capability is invented;
`tests/test_openai_compatible_live_model_mapping.py` asserts that a real OpenAI entry
(`id`/`object`/`created`/`owned_by`/`shutdown_date`) maps to all-`NULL` limits, and that
OpenRouter/vLLM/Anthropic extras are consumed when present;
`test_rediscovery_overwrites_stale_limits_and_capabilities` proves a second discovery
replaces 1,000,000/8,192 with 1,048,576/65,536.

### 14. The MCP SDK 2.x hides HTTP status codes and uses `httpx2`

**Symptom.** A 401 from an MCP server surfaced as `MCPError(-32603, "Server returned an error response")`, so a
bad credential looked identical to an outage (wrong integration status, wrong retry advice).

**Root cause.** `mcp` 2.x builds on `httpx2` (not `httpx`), takes an `httpx2.AsyncClient`, renamed `FastMCP` to
`MCPServer`, and converts HTTP failures into JSON-RPC errors without the status.

**Fix.** `app/integrations/mcp_client.py` attaches a response event hook to the client, records statuses, and
maps them (`401/403` -> `UpstreamAuthError`, `429` -> `UpstreamRateLimited`, `404` -> session expired). The
Outbound Guard is an `httpx2.AsyncBaseTransport` (`guarded_transport.py`), so every request the SDK makes,
including redirect hops it follows itself, is validated and sent to the pinned IP.

**Verified.** `tests/test_mcp_adapter_sdk.py` runs a real SDK server in-process over `httpx2.ASGITransport`
(no sockets), including wrong-token, private-DNS, and metadata-IP cases.

### 15. Beanie initialization leaks across tests through the base classes

**Symptom.** Unrelated tests (`test_auth.py`) started failing only when a test using `init_beanie` ran earlier:
`GET /auth/me` returned role `admin` instead of `user`.

**Root cause.** `init_beanie` stamps `_document_settings` on every class in the MRO, including `BaseDocument` and
`Document`. Resetting only the concrete model leaves the stamp, so `User` still looked initialized (against a mock
DB whose `count_documents` is 0, making the first user an admin) instead of falling back as "DB offline".

**Fix.** The `tool_models` fixture in `tests/conftest.py` saves and restores `_document_settings` for the whole
hierarchy. Any new fixture that calls `init_beanie` must do the same.

### 16. `anyio` task groups cannot span a pytest-asyncio fixture

**Symptom.** `RuntimeError: Attempted to exit cancel scope in a different task than it was entered in` from
fixtures wrapping an MCP server.

**Root cause.** The SDK server's lifespan is an `anyio` task group; pytest-asyncio runs fixture setup and teardown
in different tasks.

**Fix.** Open such servers inside the test body (`CaseFactory.open()` in `tests/test_adapter_contract.py`,
`running_transport()` in `tests/mcp_test_server.py`), never in a yielding fixture.

### 17. Overlapping safety checks hide untested rules (found by mutation testing)

**Symptom.** Deleting the `per_user` credential guard, or the "drift" state check, left the whole suite green.

**Root cause.** Another earlier check (Gate 1 `auth_required`, hash-mismatch `drift`) already blocked the same
case, so the later one was never the deciding check in any test.

**Fix.** Each rule now has a unit test that exercises it alone (`tests/test_tools_core.py`). A throwaway mutation
script (16 security-critical mutants: locked args, deny precedence, end-user gate, per-user fallback, token
purpose, approval binding, drift, validation, default-deny, block re-check, dry run, redaction, erasure, breaker,
app-only visibility) now reports zero survivors. Re-run it after changing `access.py`, `gateway_stages.py`,
`credentials.py`, or `signing.py`.

### 18. OpenAPI/generated artifacts drift silently from the code

**Symptom.** `apps/api/openapi.json` and `packages/api-client/src/generated/schema.ts` described
46 operations while the app served 76: every MOD-07 router (`integrations`, `tools`,
`tool_runtime`, `end_users`) and `GET /projects/{id}/me` were missing. The spec also had one
security scheme while the app accepted three credentials.

**Root cause.** `openapi.json` is a committed artifact produced by
`python -m app.utils.export_openapi`; adding routers does not regenerate it. The end-user token
was read with a plain `Header(alias="X-Axion-End-User-Token")`, so FastAPI emitted it as an
ordinary parameter and the operation looked public.

**Fix.** Declare every credential as a named FastAPI scheme in `app/api/deps.py`
(`ClerkSession`, `AxionApiKey`, `EndUserSession`), reference them with `Security(...)` (not
`Depends(...)`, not a raw `Header`), and run `pnpm generate:api` after contract changes — it now
also refreshes `docs/api-routes.md`. `tests/test_openapi_security.py` fails if any operation
other than `/health` and `/api/v1/health` lacks a security requirement.

**Still open.** `apps/web` does not depend on `@platform/api-client` at all, so the generated
types/client have no consumers yet.

### 18. Rotating refresh tokens make unguarded refresh a self-inflicted outage

**Symptom.** Under concurrent tool calls with an expired access token, several callers each tried to refresh with
the same refresh token. Providers that rotate refresh tokens accept only the first, answer `invalid_grant` to the
rest, and the connection was then (correctly, but wrongly here) marked dead.

**Fix.** `ConnectionTokenService` refreshes under a per-connection lock (`KeyedLocks`, weakly held), re-reads the
connection inside the lock so a caller that lost the race uses the winner's token, and writes the result with a
revision compare-and-swap. A *transient* refresh failure (network, 5xx) raises a retryable upstream error and leaves
the grant intact; only `invalid_grant` / `invalid_client` mark it `needs_auth` and stop further attempts.

**Verified.** `test_concurrent_calls_trigger_exactly_one_refresh`. This test only works because the in-process
authorization server sleeps (`refresh_delay`): coroutines that never hit a real suspension point never interleave, so
a concurrency test without one passes even when the lock is deleted (mutation testing caught this).

### 19. Secrets in URL paths leak through access logs

**Symptom (found by review of NFR-S11).** The connect-link secret is a path segment (`/integrations/connect/{token}`)
and the app's request logger wrote the raw path. `uvicorn.access` is already silenced (it would also log the OAuth
`code`/`state` query), but the app logger was not.

**Fix.** `sanitize_path` masks the segment before logging; the credential-entry route is added to the redacted-body
paths. `test_connect_link_secrets_never_reach_the_access_log` fails without the fix. Assert on the server's own logger
(`app.http`): the TestClient's `httpx2` logs the URLs *it* requests and would mask a regression.

### 20. A state check and an atomic claim can both stop a replay, so test each alone

**Symptom.** Mutation testing showed removing the "session must be `started` and unexpired" check left the suite green,
because the atomic `started -> completed` claim still blocked replays. But the claim does not look at expiry, so an
expired-but-started session could have completed.

**Fix.** Separate tests for each: `test_a_started_session_cannot_complete_after_it_expires` (the status/expiry check)
and `test_the_atomic_claim_alone_stops_a_raced_callback` (a stale read must still lose the atomic transition).

### 21. Changing credentials must revoke connections (and per-user means *only* the user's own)

**Symptom.** Switching an integration from `project_shared` to `per_user` left the project's old connection in the
database. Nothing used it, but a mutation of the Gate 2 check (`own | shared`) was not caught.

**Fix.** `IntegrationService` now calls `IntegrationConnectionsPort.revoke_all` when the auth type, credential mode,
client id, secret, or endpoint changes, and when the integration is deleted (upstream revoke, then delete, then drop the
OAuth client). Gate 2 uses only the caller's own connections for `per_user`, and a test plants a stale project connection
to prove it is ignored.

### 22. An app origin the caller supplies is an app origin nobody checked

**Symptom.** Mutation testing: replacing the bridge's forced `origin = "app_widget"` with the caller's own principal left
the suite green, because every caller already passed `app_widget`. A caller that passed `runtime` would have let a widget
reach model-facing tools (the visibility rules key off the origin).

**Fix.** `McpAppService.call_tool` overrides the origin itself, and `test_the_bridge_forces_app_origin_even_if_the_caller_claims_another`
passes a hostile principal to prove it. General rule: when a security decision depends on a field, the component that owns
the decision must set it, not trust the caller to.

### 23. "No UI metadata" must mean "not callable by an app"

**Symptom.** The first gateway rule allowed an app to call any tool whose `ui_visibility` was unset, so a widget could
call model-facing tools such as a destructive `delete_everything`.

**Fix.** For `app_widget` origin the gateway now requires the tool to declare `visibility` including `app`; tools without
UI metadata are model-facing only. Covered by `test_apps_cannot_call_tools_that_do_not_declare_the_app_as_a_caller` and a
mutation that restores the old rule.

### 24. Approve the hash the admin reviewed, not "whatever is current"

**Symptom (design).** If approval simply stamped the current hash, a server could swap the HTML between the admin
opening the review screen and clicking Approve.

**Fix.** The approve request carries the `content_hash` that was reviewed; a mismatch is a `409 APP_CONTENT_CHANGED`.
Approval also lists the exact domains and permissions granted, each of which must be a subset of what the app declared;
anything unlisted is denied, and rendering returns only the approved set.

### 25. A pooled SDK session needs an owner task; callers only use it

**Problem.** The MCP SDK's `ClientSession` and Streamable HTTP transport use `anyio` task groups, which raise
"Attempted to exit cancel scope in a different task" if exited from a task other than the one that entered them. A pool
that opens a session inside whichever request asked first, and closes it from another, breaks (the same constraint as
learnings #16 for test fixtures).

**Design.** Each pooled session is owned by one background task that opens it, parks until told to close (or idle), and
closes it, all in that task. Callers use the session from their own tasks through a proxy, which the SDK allows. Idle
expiry runs inside the owner task, so no janitor is needed; `close_all` signals every owner and waits for them.
`test_the_session_is_always_entered_and_exited_in_one_owner_task` and the real-SDK pool tests guard this.

**Safety rules.** Keyed by `(integration, revision, keyed-hash of the credentials)`, so different users never share a
session; any failure evicts the session; only "session expired" is retried (once) because the server never saw the
request, so a tool call can never run twice; caps fall back to an unpooled session instead of blocking.

### 26. The standalone notification stream cannot be carried by an in-memory ASGI transport

**Limitation.** `notifications/tools/list_changed` arrives on a long-lived SSE `GET`. `httpx2.ASGITransport` buffers a
response until it completes, so that stream never delivers in-process, and a test cannot observe a real notification
end to end. What is verified instead: the SDK's real notification types (`ToolListChangedNotification`, ...) through the
real handler, and the subscriber through the whole container (discovery, drift, audit). Real delivery should be checked
once against a live MCP server that emits `list_changed` before relying on it in production.

### 27. Unsaved Beanie documents all have `id = None`

**Symptom.** A pool test that created several `Integration` objects without inserting them saw them all share one pool
entry, because the key used `str(integration.id)` and every unsaved document has `id = None`, so "a different
integration" was the same key.

**Fix.** Tests that need distinct identities set `PydanticObjectId()` explicitly. Production is unaffected (documents are
inserted before use), but any code keyed on `id` must never be exercised with unsaved documents.

---

## Bugs found and fixed (commit `5ea80d9`)

| Area                                        | Fix                                                                                                                                     |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Shared collection / merged indexes          | removed `BaseDocument.is_root`; per-model collections (`users`, `projects`, `project_members`, `project_audit_logs`, `project_secrets`) |
| Misleading 409 on project create            | duplicate-key mapping now checks `keyPattern` in project/member/secret repositories                                                     |
| Slug reuse after archive/delete             | slugs reserved for all non-`PURGED` projects                                                                                            |
| Orphaned project on membership failure      | compensating delete in `ProjectService.create_project`                                                                                  |
| Secret rotation 500                         | `serialize_for_mongo` for raw PyMongo `$set` payloads                                                                                   |
| Secret duplicate create 500                 | `ProjectSecretRepository.create` maps `DuplicateKeyError` to 409                                                                        |
| Restore/unarchive conflict surfacing as 500 | `transition_status` maps `DuplicateKeyError` to 409                                                                                     |
| Purge left child secrets                    | `purge_project` cascades `secret_repo.purge_by_project` (DI-injected)                                                                   |
| `include_archived` leaked deleted projects  | additive status filtering with `statuses`                                                                                               |
| Slug missing from project search            | `slug` added to the case-insensitive regex `$or`                                                                                        |
| Search regex injection                      | all search terms go through `re.escape`                                                                                                 |
| DB outage reported as 404                   | `get_by_id` only swallows `ValueError`                                                                                                  |

Test suite at time of writing: **137 passed** (`pytest -q` in `apps/api`).

Development tooling fixed separately:

| Area                            | Fix                                                                                    |
| ------------------------------- | -------------------------------------------------------------------------------------- |
| Dev reload broken on Windows    | `apps/api/dev.py` supervises uvicorn with `watchfiles` + `terminate()` (see lesson 11) |
| Reload churn from non-app files | watch root reduced from all of `apps/api` to `apps/api/app`                            |
| Duplicate `e2e_secrets_test.py` | single canonical copy at `apps/api/tests/e2e_secrets_test.py` (outside the watch root) |

---

## Known issues / risks (not yet fixed)

Ordered by risk. These are candidates for the next hardening pass.

1. **Deactivated users can still authenticate.** `app/api/deps.py::get_current_user`
   wraps the user sync in a broad `except Exception` and then returns the token identity.
   If the database lookup fails — or the user is `is_active=False` — the request still
   succeeds with the JWT's claims, and DB role changes are not enforced.
2. **First-user ADMIN race.** `UserService.sync_clerk_user` counts users and then inserts;
   two concurrent first requests can both become ADMIN. A unique `email` collision during
   insert can also make the sync fail (currently swallowed by the point above).
3. **No transactional boundaries.** `create_project` (compensated only for the member
   insert), `purge_project`, and role/ownership transfer are multiple independent writes.
   A crash mid-way leaves partial data.
4. **Purge is not idempotent/recoverable.** It is a `SOFT_DELETED → PURGED` transition plus
   cascades; audit logs stay in `project_audit_logs` with no archival policy, and a failure
   after the status update leaves members/secrets behind.
5. **Blocking Clerk SDK call in async code.** `app/core/security.py` calls
   `_clerk_client.users.get(...)` (synchronous HTTP) inside `async def verify_clerk_token`,
   blocking the event loop. Needs `run_in_threadpool`/`anyio.to_thread` or an async client.
6. **JWT audience is not verified** (`options={"verify_aud": False}` in
   `app/core/security.py`). Configure the Clerk audience and verify it in production.
7. **Rate limiter weaknesses.** `app/middleware/rate_limit.py` keeps per-IP timestamps in
   memory forever (no eviction of idle keys), trusts `request.client.host` only (ignores
   `X-Forwarded-For`/proxy headers), and is per-process so it does not enforce limits across
   workers. Move to Redis or a shared store before scaling out.
8. **Slug generation TOCTOU** (`_resolve_unique_slug`): concurrent creates can pick the
   same slug; the database 409 is correct but the client sees a hard failure instead of a
   retry. Consider retrying with a new suffix on `DuplicateKeyError`.
9. **Stale `BaseDocument` collection in the local dev database.** It still contains one
   duplicate `User` document written before the `is_root` fix. The same `clerk_id` exists
   in `users`, so the collection can be dropped after confirming nothing else is needed.

---

## Verification recipes

```powershell
# Full backend test suite (no live MongoDB needed)
cd apps/api
.\.venv\Scripts\python.exe -m pytest -q

# Run the API locally (Windows-safe reload, watches app/ only)
cd apps/api
.\.venv\Scripts\python.exe dev.py --port 8000

# End-to-end secrets lifecycle (needs a running server + dev token)
.\.venv\Scripts\python.exe tests\e2e_secrets_test.py `
  --url http://127.0.0.1:8000 --token dev-token-admin_super
```

`dev-token-<name>` works only when `ENVIRONMENT` is `development`/`test`; names containing
`admin` get the ADMIN role.

## Data model notes

- Collections: `users`, `projects`, `project_members`, `project_audit_logs`,
  `project_secrets`. MOD-07 adds `project_integrations`, `project_tools`,
  `project_tool_settings`, `tool_bindings`, `project_end_users`, `tool_invocations`.
- Unique indexes: project slug; `(project_id, user_id)` on members;
  `(project_id, environment, name)` on secrets filtered to `is_deleted: False`.
- Secrets store only an `EncryptedEnvelope` (AES-256-GCM + RFC 3394 wrapped DEK); the
  canonical AAD is `axion:v1:proj:{project_id}:env:{environment}:name:{name}`.
- Every document inherits `created_at`/`updated_at` (UTC) from `BaseDocument`.
