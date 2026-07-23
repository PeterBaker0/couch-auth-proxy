# AGENTS.md

## Cursor Cloud specific instructions

This is `couch-auth-proxy`: a TypeScript (Hono) reverse proxy that enforces per-document ACLs in front of Apache CouchDB 3.5+. See `README.md` for the product model, `USER-GUIDE.md` for ACL modeling, and `package.json` for the full script list.

### Environment (already provisioned by the update script / VM snapshot)

- Node.js 24 is installed via `nvm` and made default; `~/.bashrc` prepends it so it wins over the system `/exec-daemon/node` (v22). Always run repo commands in a login shell (`bash -lc '...'`) so Node 24 + `pnpm` (via Corepack) are on `PATH`.
- Docker Engine + compose plugin are installed. `dockerd` is not managed by systemd here — start it manually if not running: `sudo dockerd &` (it logs to the foreground). The `ubuntu` user is in the `docker` group, so a fresh login shell can run `docker` without `sudo`; within an already-open shell that predates the group change, use `sg docker -c '<cmd>'`.

### Running the stack

- Full stack (built image, closest to prod): `docker compose up -d --build` starts CouchDB 3.5, a one-shot `couch-init` (creates `acldemo` DB + demo users), and the proxy on `http://127.0.0.1:8000`. Verify with `/_couch-auth-proxy/health` and `/_couch-auth-proxy/ready` (both return `{"ok":true}`).
- Host dev (hot reload): publish CouchDB first with `docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d couchdb couch-init` (exposes Couch on host `5985`), then run `pnpm dev` with `COUCH_URL=http://127.0.0.1:5985` and the admin creds (see the "Local dev" block in `README.md`). Running the docker proxy and `pnpm dev` at once requires different `PORT`s (proxy uses 8000).
- Demo users (created by `couch-init`): `alice`/`alice-pass` (role `readers`), `bob`/`bob-pass` (role `writers`), admin `admin`/`password`. A document with `creator: "<user>"` is private to that user; missing ACL fields make it readable by any authenticated DB member.

### Lint / test / build (commands in `package.json`)

- `pnpm lint`, `pnpm fmt:check`, `pnpm typecheck`, `pnpm test` (unit) need no running services.
- `pnpm test:integration` requires the docker stack up first (`docker compose up -d --build`); it hits the proxy at `http://127.0.0.1:8000`.

### Gotchas

- `pnpm install` prints an ignored-build-script warning for `leveldown` (a transitive PouchDB dep). This is harmless — integration tests use `pouchdb-adapter-memory`, so the native `leveldown` build is not needed.
- The proxy fails closed: a down CouchDB or ACL follower makes `/_couch-auth-proxy/ready` return `503`. If integration tests fail on readiness, confirm the compose stack is healthy (`docker compose ps`).
