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

Bucket rules live on `_design/acl`:

- `restrict.*` — who may see the DB (`/_all_dbs` hides others)
- `restrict.get|post|…` — path/query ACL (`*` / `+` wildcards)
- `dbacl.{_r,_w,_d}` — overlay grants on every doc

## API coverage

ACL-filtered: single docs + attachments, same-database `COPY`, `_all_docs`, `_design_docs`, `_local_docs`, `_bulk_get`, views, `_changes` (incl. continuous), `_bulk_docs`, `_revs_diff` / `_missing_revs`, `_find`, partition `_all_docs`/`_find`/views, `_all_dbs`.

Admin-only: Fauxton `/_utils`, `/_node/*`, `/_scheduler/*`, `/_replicate`, `/_db_updates`, DB create/delete, `_security`, `_revs_limit`, compaction, Mango `_index` management, search/nouveau, other partition paths.

Unmapped endpoints return **404** for non-admins (default-deny). `_list`, `_show` without a doc id, and `_update` without a doc id return **501**. `_explain` and Mango index management are admin-only. Prefer filtered views or Mango.

### Caveats

- After ACL filtering, `limit` may under-deliver rows — prefer `key` / `keys` queries when counts matter.
- View `reduce` / `group` is **501** for non-admins (aggregates have no doc ids to ACL-filter), including when requested in a POST body. Use `reduce=false`, or call as admin. Non-admin view requests force `reduce=false` upstream.
- Targeted `_update` handlers require read, write, and delete on the document because a handler may emit arbitrary updates or tombstones. Handlers without a target document are **501**.
- Non-admin multipart document writes are **415** because tombstone metadata cannot be authorized safely without buffering the full MIME body. Use JSON document writes plus the attachment endpoints.
- Deletion tombstones stay visible on `_changes` to principals who could read the doc (last ACL retained / recovered from the pre-delete revision). Users who never had read access do not see tombstones (no existence leak).
- Keyed `_all_docs` / view queries may return `not_found` placeholders for denied ids (positional alignment). Non-keyed listings **drop** denied rows — never emit placeholders that would leak foreign ids.
- Filtered row responses omit unfiltered `total_rows`, `offset`, and `update_seq`; Mango responses omit unfiltered execution statistics for non-admins.
- Continuous `_changes` sequences are opaque strings (Couch 2+/3); never treat them as integers.
- ACL cache is ~hundreds of bytes per doc per process; preload via `COUCH_PRELOAD_DBS`.
- Initial ACL view loads are paginated; the in-memory cache still contains one compact row per document.
- ACL view/admin failures and a down `_changes` follower fail closed (**503**), never serve on a stale cache.
- System databases are never auto-mutated with `_design/acl`; without a ddoc they pass through to Couch `_security` only.
- Compose sets Couch `[chttpd] admin_only_all_dbs = false` so non-admins can call `/_all_dbs` and the proxy can hide DBs via `restrict.*`.

## Ops

| Variable                                                         | Purpose                                                                                                                                                                                                 |
| ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `COUCH_URL`                                                      | Upstream Couch (no creds)                                                                                                                                                                               |
| `COUCH_ADMIN_USER` / `COUCH_ADMIN_PASSWORD` or `COUCH_ADMIN_URL` | Admin for ACL maintenance + `_changes` follow                                                                                                                                                           |
| `COUCH_PRELOAD_DBS`                                              | Comma-separated DBs to warm on boot                                                                                                                                                                     |
| `ACL_AUTO_INSTALL`                                               | Auto-PUT `_design/acl` when missing on app DBs (default `true`). Never installs into `_users` / `_replicator` / `_global_changes`. Prefer `false` in production when ddocs are provisioned out-of-band. |
| `AUTH_RESOLVE_VIA_COUCH_SESSION`                                 | Default `true`                                                                                                                                                                                          |
| `JWT_LOCAL_VERIFY` / `JWT_HMAC_SECRET`                           | Optional local Bearer JWT verification; required together when Couch session resolution is disabled                                                                                                     |
| `JWT_ROLES_CLAIM_PATH` / `JWT_REQUIRED_CLAIMS`                   | Local JWT role claim path and comma-separated required claims                                                                                                                                           |
| `COUCH_MAX_ID_LENGTH`                                            | Maximum accepted document-id length (default `200`)                                                                                                                                                     |
| `CORS_ORIGINS`                                                   | Comma allowlist (**required for browser CORS**; empty = no Origin reflection)                                                                                                                           |
| `TRUST_PROXY_HOPS`                                               | Trusted reverse-proxy hops for client IP (default `0` = ignore `X-Forwarded-For`)                                                                                                                       |
| `SESSION_CACHE_TTL_MS` / `SESSION_CACHE_MAX`                     | Session principal cache TTL + LRU size                                                                                                                                                                  |
| `RATE_LIMIT_*`                                                   | Global + per-IP limits                                                                                                                                                                                  |
| `MAX_BODY_BYTES`                                                 | Request body ceiling (Content-Length + streamed bodies)                                                                                                                                                 |
| `SHUTDOWN_TIMEOUT_MS`                                            | Drain timeout before force-exit                                                                                                                                                                         |
| `PORT` / `HOST`                                                  | Listen address                                                                                                                                                                                          |

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
```

Pre-commit runs `oxfmt` on staged files via husky + lint-staged (`pnpm prepare` after install).

Integration includes PouchDB in-memory sync (`test/integration/pouch-sync.test.ts`), a real CouchDB 3.5 partitioned database (`partitioned.test.ts`), and fail-closed security edges (`security-edges.test.ts`, `security-deep.test.ts`): attachments (inline/`_bulk_get`/`_changes`/unicode/Range), custom views + reduce/group rejection (query **and** POST body), keyed vs non-keyed list id-leak guards, deletion tombstones, design-doc filters + `style=all_docs`, `open_revs`/meta probes, filtered replica streams (`doc_ids` / selector / longpoll / eventsource), bulk `all_or_nothing` / `new_edits:false`, `_show`/`_update` without doc id, `_explain`/index admin-only, `_local` checkpoints, ACL revocation, and `restrict` rules.

# couch-auth-proxy
