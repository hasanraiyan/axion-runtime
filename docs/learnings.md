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
  `project_secrets`.
- Unique indexes: project slug; `(project_id, user_id)` on members;
  `(project_id, environment, name)` on secrets filtered to `is_deleted: False`.
- Secrets store only an `EncryptedEnvelope` (AES-256-GCM + RFC 3394 wrapped DEK); the
  canonical AAD is `axion:v1:proj:{project_id}:env:{environment}:name:{name}`.
- Every document inherits `created_at`/`updated_at` (UTC) from `BaseDocument`.
