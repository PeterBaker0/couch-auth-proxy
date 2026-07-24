# couch-auth-proxy

Per-document read/write/delete ACL reverse proxy for **Apache CouchDB 3.5+**.

> Evolved from CoverCouch (Node/Express ACL proxy for CouchDB 1.6–1.7); this is a TypeScript rewrite for CouchDB 3.5+.

Clients talk to the proxy; it authenticates the same way Couch does (cookie / Basic / **JWT Bearer**), enforces document + bucket ACL, and proxies to CouchDB.

## Requirements

- **Node.js 24+** (see `.nvmrc` / `.node-version`)
- **pnpm 10+** (via Corepack)

```bash
# with nvm (https://github.com/nvm-sh/nvm)
nvm install        # reads .nvmrc → Node 24
nvm use
corepack enable
pnpm install
```

`fnm` / `asdf` / Volta pick up `.node-version` the same way.

## Quick start (Docker)

```bash
pnpm install
docker compose up -d --build
curl -s http://127.0.0.1:8000/_couch-auth-proxy/health | jq
curl -s http://127.0.0.1:8000/_couch-auth-proxy/ready | jq
```

| Service                 | URL                                                                                 |
| ----------------------- | ----------------------------------------------------------------------------------- |
| couch-auth-proxy        | `http://127.0.0.1:8000`                                                             |
| CouchDB (direct, admin) | only with `docker-compose.dev.yml` → `http://127.0.0.1:5985` — `admin` / `password` |

Demo DB: `acldemo`. Users: `alice` / `alice-pass` (role `readers`), `bob` / `bob-pass` (role `writers`).

CouchDB 3.x may default new databases to admin-only `_security`. For couch-auth-proxy, set membership so app users can reach the DB; document ACL is enforced by the proxy. Compose `init.sh` opens `acldemo` for the demo users/roles.

Publish Couch on the host for local admin/debug:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
```

Production-oriented overlay (rate limits on, read-only rootfs, Couch not published):

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

## Authentication (Couch-native)

couch-auth-proxy forwards `Authorization` and `Cookie` upstream and resolves the principal via Couch `GET /_session`. JWT validation stays in CouchDB (`[jwt_keys]` / `[jwt_auth]`).

Compose enables HMAC JWT with secret `couch-auth-proxy-dev-secret` (base64 in `docker/couchdb/local.ini`). Keep `JWT_HMAC_SECRET` in sync if you enable optional local verify for tests.

By default, identity is resolved through Couch `/_session`. To verify Bearer
JWTs locally instead, set `AUTH_RESOLVE_VIA_COUCH_SESSION=false`,
`JWT_LOCAL_VERIFY=true`, and `JWT_HMAC_SECRET`. Local mode accepts Bearer JWTs
only; invalid tokens fail closed as anonymous, and Couch still independently
validates the forwarded token.

```bash
# mint a token (Node), then:
curl -s http://127.0.0.1:8000/_session -H "Authorization: Bearer <jwt>"
```

Cookie and Basic work unchanged (`POST /_session`, then `Cookie: AuthSession=…`).

Spoofed `X-Auth-CouchDB-*` headers from clients are stripped.

## Document ACL

| Field     | Meaning                                                         |
| --------- | --------------------------------------------------------------- |
| `creator` | Full r/w/d (`"alice"` or `"u-alice"`); immutable for non-admins |
| `owners`  | r/w; cannot delete or change creator/owners                     |
| `acl`     | read only                                                       |
| `parent`  | inherit parent ACL (most permissive wins)                       |

Missing `creator` / `owners` / `acl` → open to `r-*` (**authenticated** DB users). Anonymous callers do not receive `r-*`. Design docs default read-only for `r-*`.
Present ACL fields are type-checked by the generated validation function and malformed values fail closed. An absent creator cannot later be claimed by a non-admin.

Bucket rules live on `_design/acl`:

- `restrict.*` — who may see the DB (`/_all_dbs` hides others)
- `restrict.get|post|…` — path/query ACL (`*` / `+` wildcards)
- `dbacl.{_r,_w,_d}` — overlay grants on every doc

## API coverage

ACL-filtered: single docs + attachments, same-database `COPY`, `_all_docs`, `_design_docs`, `_local_docs`, `_bulk_get`, views, `_changes` (incl. `continuous` / `live`), `_bulk_docs`, `_revs_diff` / `_missing_revs`, `_find`, partition `_all_docs`/`_find`/views, `_all_dbs`.

Admin-only: Fauxton `/_utils`, `/_node/*`, `/_scheduler/*`, `/_replicate`, `/_db_updates`, DB create/delete, `_security`, `_revs_limit`, compaction, Mango `_index` management, search/nouveau, other partition paths.

Unmapped endpoints return **404** for non-admins (default-deny). `_list`, `_show` without a doc id, and `_update` without a doc id return **501**. `_explain` and Mango index management are admin-only. Prefer filtered views or Mango.

### Caveats

- After ACL filtering, `limit` may under-deliver rows — prefer `key` / `keys` queries when counts matter.
- View `reduce` / `group` is **501** for non-admins (aggregates have no doc ids to ACL-filter), including when requested in a POST body. Use `reduce=false`, or call as admin. Non-admin view requests force `reduce=false` upstream.
- Targeted `_update` handlers require read, write, and delete on the document because a handler may emit arbitrary updates or tombstones. Handlers without a target document are **501**.
- Non-admin multipart document writes are **415** because tombstone metadata cannot be authorized safely without buffering the full MIME body. Use JSON document writes plus the attachment endpoints.
- Deletion tombstones stay visible on `_changes` to principals who could read the doc (last ACL retained / recovered from the pre-delete revision). Users who never had read access do not see tombstones (no existence leak).
- Keyed document-list queries such as `_all_docs` may return `not_found` placeholders for denied ids (the caller supplied those document ids). Custom view queries always drop denied rows because a view key does not prove knowledge of the matching document ids.
- Linked-view `include_docs` rows are authorized against both the source row and the embedded target document.
- Principal-dependent list responses disable shared validators and caching so an old authorized representation cannot survive an ACL or role change.
- Filtered row responses omit unfiltered `total_rows`, `offset`, and `update_seq`; Mango responses omit unfiltered execution statistics for non-admins.
- Continuous `_changes` sequences are opaque strings (Couch 2+/3); never treat them as integers.
- ACL cache is ~hundreds of bytes per doc per process; preload via `COUCH_PRELOAD_DBS`.
- Initial ACL view loads are paginated; the in-memory cache still contains one compact row per document.
- ACL view/admin failures and a down `_changes` follower fail closed (**503**), never serve on a stale cache.
- System databases are never auto-mutated with `_design/acl`; without a ddoc they pass through to Couch `_security` only.
- Compose sets Couch `[chttpd] admin_only_all_dbs = false` so non-admins can call `/_all_dbs` and the proxy can hide DBs via `restrict.*`.

## Ops

| Variable                                                         | Purpose                                                                                                                                                                                                                                                                |
| ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `COUCH_URL`                                                      | Upstream Couch (no creds)                                                                                                                                                                                                                                              |
| `COUCH_ADMIN_USER` / `COUCH_ADMIN_PASSWORD` or `COUCH_ADMIN_URL` | Admin for ACL maintenance + `_changes` follow                                                                                                                                                                                                                          |
| `COUCH_PRELOAD_DBS`                                              | Comma-separated DBs to warm on boot                                                                                                                                                                                                                                    |
| `ACL_AUTO_INSTALL`                                               | Auto-PUT `_design/acl` when missing on app DBs (default `true`). Never installs into `_users` / `_replicator` / `_global_changes`. Prefer `false` in production when ddocs are provisioned out-of-band.                                                                |
| `ACL_DB_INCLUDE` / `ACL_DB_EXCLUDE`                              | Opt-in database allow/deny lists (CSV). Entries are exact names or `/regex/flags`. Empty = historical behaviour. Exclude wins. Non-admins only; hidden DBs are omitted from `/_all_dbs` and return **404**. Example: `ACL_DB_INCLUDE=/^data-/`.                        |
| `ACL_ROUTE_INCLUDE` / `ACL_ROUTE_EXCLUDE`                        | Opt-in API surface allow/deny lists (CSV). Entries are feature/bundle names (`pouch-sync`, `session`, `changes`, …), `METHOD /restmap-path` templates, or `/regex/flags` over `METHOD pathname`. Empty = all restmap routes. Exclude wins. Non-admins get **403**.     |
| `AUTH_RESOLVE_VIA_COUCH_SESSION`                                 | Default `true`                                                                                                                                                                                                                                                         |
| `JWT_LOCAL_VERIFY` / `JWT_HMAC_SECRET`                           | Optional local Bearer JWT verification; required together when Couch session resolution is disabled                                                                                                                                                                    |
| `JWT_ROLES_CLAIM_PATH` / `JWT_REQUIRED_CLAIMS`                   | Local JWT role claim path and comma-separated required claims                                                                                                                                                                                                          |
| `COUCH_MAX_ID_LENGTH`                                            | Maximum accepted document-id length (default `200`)                                                                                                                                                                                                                    |
| `CORS_ORIGINS`                                                   | Comma allowlist (**required for browser CORS**; empty = no Origin reflection)                                                                                                                                                                                          |
| `TRUST_PROXY_HOPS`                                               | Trusted reverse-proxy hops for client IP (default `0` = ignore `X-Forwarded-For`)                                                                                                                                                                                      |
| `SESSION_CACHE_TTL_MS` / `SESSION_CACHE_MAX`                     | Session principal cache TTL (default `0`, disabled) + LRU size. Concurrent identical credentials are already coalesced into one `/_session` fetch with no TTL. Enabling a TTL further cuts sequential auth cost but delays role/admin revocation up to that window.    |
| `RATE_LIMIT_*`                                                   | Global + per-IP limits                                                                                                                                                                                                                                                 |
| `MAX_BODY_BYTES`                                                 | Request body ceiling (Content-Length + streamed bodies)                                                                                                                                                                                                                |
| `SHUTDOWN_TIMEOUT_MS`                                            | Drain timeout before force-exit                                                                                                                                                                                                                                        |
| `PORT` / `HOST`                                                  | Listen address                                                                                                                                                                                                                                                         |
| `LOG_LEVEL`                                                      | Minimum log level: `verbose`, `debug`, `info`, `warn`, `error` (aliases: `trace`→`verbose`, `warning`→`warn`). Default `debug` outside production, `info` in production. Use `verbose` to trace ACL allow/deny decisions (actors, resolvers, filters, session tokens). |
| `PROFILE`                                                        | Opt-in request phase profiling (`auth` / `acl` / `aclMiss` / `upstream` / `filter`). Adds phase ms to access logs and exposes `GET/POST /_couch-auth-proxy/profile[/reset]` for the perf harness. Default off — leave disabled in production.                          |

Structured JSON logs go to stdout/stderr (`ts`, `level`, `component`, `msg`, …). Secret-looking fields (`authorization`, `cookie`, `password`, `token`, `secret`, …) are redacted.

### Env access policy (opt-in)

Empty `ACL_DB_*` / `ACL_ROUTE_*` lists leave behaviour unchanged. When set, lists are compiled once at process start (exact `Set` lookups + precompiled `RegExp`s) so the hot path stays cheap under high QPS.

```bash
# Only expose data-* databases to non-admins (hide everything else as 404)
ACL_DB_INCLUDE=/^data-/

# Pouch-style sync APIs only (block Mango, Fauxton, admin endpoints, …)
ACL_ROUTE_INCLUDE=pouch-sync
ACL_ROUTE_EXCLUDE=admin
```

Route entries may be:

| Form                   | Example                                      | Matches                         |
| ---------------------- | -------------------------------------------- | ------------------------------- |
| Feature                | `changes`, `docs`, `session`                 | Tagged restmap routes           |
| Bundle                 | `pouch-sync`, `server`, `documents`, `query` | Expanded feature sets           |
| Method + path template | `GET /:db/_changes`                          | Exact restmap `method` + `path` |
| Regex                  | `/^GET \/data-[^/]+\/_changes$/`             | `METHOD` + request pathname     |

Feature catalog: `root`, `up`, `uuids`, `session`, `all_dbs`, `db`, `docs`, `attachments`, `design`, `local`, `all_docs`, `changes`, `bulk_docs`, `bulk_get`, `find`, `index`, `views`, `show`, `update`, `copy`, `revs`, `partition`, `admin`. Couch admins bypass both policies (same as `restrict.*`). Proxy probes under `/_couch-auth-proxy/*` are never gated.

Probes (bodies are non-sensitive `{ "ok": true|false }` only):

- `GET /_couch-auth-proxy/health` — liveness (always `{ "ok": true }` when the process is up)
- `GET /_couch-auth-proxy/ready` — `200` when Couch is reachable and preloaded ACL followers are up; else `503`

Terminate TLS at Caddy/Traefik/etc. in front of couch-auth-proxy. Set `TRUST_PROXY_HOPS=1` (or higher) only when that edge is trusted. Run as non-root (Docker image uses `USER node`); prod overlay uses a read-only root filesystem.

Graceful shutdown stops `_changes` followers and drains the HTTP server on `SIGINT`/`SIGTERM`.

### JWT key sync

If Couch and couch-auth-proxy both verify JWT locally, secrets/keys must match. Preferred production mode: only Couch verifies; couch-auth-proxy trusts `/_session`.

### Migrating generated `_design/acl`

couch-auth-proxy stamps map freshness with `_rev` (not `_local_seq`). On ensure,
generated legacy maps using `_local_seq` and v2.0 VDUs are upgraded. Existing
`dbacl`, `restrict`, ACL metadata, and non-ACL views are preserved.

## Local dev

```bash
nvm use                 # Node 24 from .nvmrc
corepack enable
pnpm install
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d couchdb couch-init
export COUCH_URL=http://127.0.0.1:5985
export COUCH_ADMIN_USER=admin
export COUCH_ADMIN_PASSWORD=password
export COUCH_PRELOAD_DBS=acldemo
pnpm dev
```

## Lint / format / tests

```bash
pnpm fmt                      # oxfmt
pnpm lint                     # oxlint
pnpm typecheck
pnpm test                     # unit
docker compose up -d --build
pnpm test:integration         # needs stack up

# ACL performance baseline (multi-client Pouch sync + HTTP r/w ops/sec)
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
pnpm test:perf                # writes test/perf/last-results.json; not in CI

# Same harness + server phase profiling (auth/acl/upstream/filter)
pnpm test:perf:profile        # compose profile overlay + scrape /_couch-auth-proxy/profile
# Host CPU profile (after pnpm build; Couch on :5985 via docker:up:dev):
#   PROFILE=true pnpm start:profile   # writes CPU profiles under ./profiles/
```

### Performance notes

Hot-path costs under the ACL harness are usually **upstream Couch RTT**, then **auth** (`GET /_session`), then **aclMiss** (ensure/refresh). In-process ACL filter CPU is typically negligible when the cache is warm.

Safe defaults (no revocation delay):

- Concurrent identical credentials share one in-flight `/_session` lookup
- Unknown-id ensure uses existence-first `_all_docs` (create path)
- Successful JSON writes on the shipped ACL map update the cache from the body (still refresh from the view for `new_edits:false` / custom maps)
- Multi-key ACL view refresh for bulk ensure/write paths

**Product decision — `SESSION_CACHE_TTL_MS`:** still default `0`. A short TTL (e.g. `5000`) removes most remaining per-request auth overhead on sequential traffic, but role/`_admin` changes from Couch can lag by up to that TTL. Prefer keeping `0` when immediate revocation matters; enable only when the deployment accepts that window.

```bash
# Optional experiment (not the default):
# SESSION_CACHE_TTL_MS=5000 pnpm test:perf:profile
```

Pre-commit runs `oxfmt` on staged files via husky + lint-staged (`pnpm prepare` after install).

Integration includes PouchDB in-memory sync (`test/integration/pouch-sync.test.ts`), a real CouchDB 3.5 partitioned database (`partitioned.test.ts`), env DB/route access policy (`env-access-policy.test.ts`), and fail-closed security edges (`security-edges.test.ts`, `security-deep.test.ts`): attachments (inline/`_bulk_get`/`_changes`/unicode/Range), linked views, custom-view key privacy, reduce/group rejection (query **and** POST body), creator-less and malformed ACL writes, deleted-parent revocation, filtered HEAD requests, keyed vs non-keyed list id-leak guards, deletion tombstones, design-doc filters + `style=all_docs`, `open_revs`/meta probes, filtered replica streams (`doc_ids` / selector / longpoll / continuous / live / eventsource), bulk `all_or_nothing` / `new_edits:false`, `_show`/`_update` controls, `_explain`/index admin-only, `_local` checkpoints, ACL revocation, and `restrict` rules.

# couch-auth-proxy
