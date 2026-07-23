# Application developer guide

How to model access with **couch-auth-proxy**: what Couch constructs mean at the ACL boundary, and how client apps should create, share, and sync documents through it.

For install, ops, and endpoint coverage, see [README.md](./README.md).

---

## How it works, in a nutshell

couch-auth-proxy sits in front of CouchDB and answers one question per request: **given who this caller is, may they read / write / delete this document (or see this row)?**

Identity comes from Couch (cookie, Basic, or **JWT Bearer**). The proxy does not invent its own user store—it asks Couch `GET /_session`, then turns that session into ACL **tokens**. Document grants (`acl`, `owners`, `creator`) and bucket rules (`dbacl`, `restrict`) match those tokens.

### The JWT → roles → ACL chain

If a document has `"acl": ["r-teamAMember"]`, any authenticated caller whose session includes the Couch role `teamAMember` gets **read** access to that doc—**provided they already pass Couch DB membership** (`_security`).

Concrete flow:

1. **Client** sends `Authorization: Bearer <jwt>`.
2. **Couch** validates the JWT (`[jwt_keys]` / `[jwt_auth]`) and maps a claim (demo: `_couchdb.roles`) into `userCtx.roles`.
3. **Proxy** expands each role into match tokens: `teamAMember` **and** `r-teamAMember` (same for every role).
4. **DB gate** — Couch `_security` must still allow the user or role as a member (otherwise Couch rejects before/at the membership boundary).
5. **Doc ACL** — `"acl": ["r-teamAMember"]` grants **read** to anyone holding that token. Use `owners` for read+write, `creator` for full r/w/d.

Cookie/Basic sessions work the same way: whatever roles Couch puts on `userCtx` become the same tokens. JWT is just how those roles often arrive in modern apps.

```
JWT roles: ["teamAMember"]
        ↓  Couch /_session
userCtx.roles: ["teamAMember"]
        ↓  proxy token expansion
aclTokens: […, "teamAMember", "r-teamAMember", "r-*", …]
        ↓  match against doc
{ "acl": ["r-teamAMember"] }  →  read ✓
```

### Case study: team-shared notes

**Setup**

- App DB `notes` with `_security.members.roles: ["teamAMember", "teamBMember"]` (both teams may talk to the DB).
- Alice’s JWT: `{ "sub": "alice", "_couchdb.roles": ["teamAMember"], … }`.
- Bob’s JWT: `{ "sub": "bob", "_couchdb.roles": ["teamBMember"], … }`.

**Docs**

```json
{ "_id": "note-private", "creator": "alice", "body": "only alice" }

{ "_id": "note-team-a", "creator": "alice", "acl": ["r-teamAMember"], "body": "team A" }

{ "_id": "note-open", "body": "any authenticated member" }
```

**What happens**

| Caller                                     | `note-private`           | `note-team-a` | `note-open`                    |
| ------------------------------------------ | ------------------------ | ------------- | ------------------------------ |
| Alice (role `teamAMember`)                 | read/write/delete        | read          | full (no grant fields → `r-*`) |
| Bob (role `teamBMember`)                   | **404** (not visible)    | **404**       | full                           |
| Carol (valid JWT, role not in `_security`) | blocked at DB membership | same          | same                           |

Sharing with a role is therefore: put **`r-<roleName>`** on the doc (or in `owners` / `dbacl`), ensure that role is a DB member (or the user is named in membership), and mint JWTs whose roles claim includes `<roleName>`. Always use the `r-` prefix on **grants**—a bare `"teamAMember"` in `acl` is treated as a **username** (`u-teamAMember`), not a role.

---

## Mental model

Treat the proxy as a **document-level ACL gate** in front of CouchDB.

```
App / PouchDB  →  couch-auth-proxy  →  CouchDB
                     │
                     ├─ auth (cookie / Basic / JWT → Couch /_session)
                     ├─ DB gate (membership + optional restrict)
                     └─ per-doc r/w/d (+ list/changes/find filters)
```

Two layers always apply:

| Layer                 | Where                      | What it controls                               |
| --------------------- | -------------------------- | ---------------------------------------------- |
| **Couch `_security`** | DB membership / admins     | Who may touch the DB at all                    |
| **Proxy ACL**         | Doc fields + `_design/acl` | Which docs a member may read, write, or delete |

**Rule of thumb:** open Couch membership wide enough for your app users/roles; enforce _sharing_ with document ACL. App users should only talk to the proxy—never to Couch directly.

Denied reads look like **missing** (`404`), not “forbidden,” so clients cannot probe foreign ids. Denied writes/deletes return **403**.

---

## Identity and ACL tokens

Auth is Couch-native (`POST /_session`, cookie, Basic, or Bearer JWT validated by Couch). Production path: the proxy forwards the credential, trusts Couch `/_session`, and expands `userCtx` into ACL tokens. It does **not** re-interpret JWT claims itself in the default mode.

| Token                      | Meaning                                                  |
| -------------------------- | -------------------------------------------------------- |
| `u-<name>` / bare `<name>` | That user (`sub` / session name)                         |
| `r-<role>` / bare `<role>` | That Couch role (from JWT roles claim or `_users` roles) |
| `r-*`                      | Any **authenticated** DB user (not anonymous)If          |
| `_admin` role              | Server admin — full bypass                               |

**JWT roles → doc grants:** a claim role `teamAMember` becomes principal tokens `teamAMember` and `r-teamAMember`. Matching against `"acl": ["r-teamAMember"]` therefore grants read to every JWT that carries that role—again, only after DB membership allows the caller in.

Prefer writing grants as `u-alice` / `r-teamAMember`. Bare names on docs/restrict/dbacl are normalized to **`u-…`** (unless already `u-` / `r-` prefixed)—so role grants **must** be written with the `r-` prefix.

Anonymous callers do **not** get `r-*`. Docs that are “open to authenticated users” stay closed to the public.
---

## Couch constructs at the ACL boundary

### Databases

A normal application DB (e.g. `acldemo`) is ACL-enabled when it has `_design/acl` (auto-installed by default on first access; never into `_users` / `_replicator` / `_global_changes`).

Without a usable ACL map, the DB is **`noacl`**: the proxy only applies `restrict` (if any) and otherwise passes through to Couch `_security`.

**`/_all_dbs`** is filtered: DBs with `restrict.*` only appear for principals who match that list.

### Couch `_security` vs proxy ACL

Couch still needs members (or roles) on the DB. Example for a shared app DB:

```json
{
  "admins": { "names": [], "roles": ["_admin"] },
  "members": { "names": ["alice", "bob"], "roles": ["readers", "writers"] }
}
```

Membership answers “may this user talk to this DB?” Document fields answer “may they see _this_ row?”

### Normal documents

Application data. ACL is derived from optional fields on the doc itself (see next section). Attachments inherit the parent document’s ACL.

### Permission fields (on normal docs)

These are ordinary JSON fields—not a separate doc type. The `_design/acl` map view indexes them into compact r/w/d grants.

| Field     | Capability                                                                                                                                    |
| --------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `creator` | Full **r / w / d**. Set at create time to the current user (`"alice"` or `"u-alice"`). Immutable for non-admins. Only the creator may delete. |
| `owners`  | **r / w** (not delete). May not change `creator` / `owners`. May change `acl` (readers).                                                      |
| `acl`     | **read** only. Also the capability checked for `_update` handlers (read, not write).                                                          |
| `parent`  | Doc id whose ACL is **unioned** (most permissive wins). One level of parent is used.                                                          |

**Defaults when none of `creator` / `owners` / `acl` are present:** open **r/w/d** to `r-*` (any authenticated member).

**Important:** `acl: []` _is_ a grant source (empty readers). That means **no one** gets read via the doc row—useful for hiding design docs. Omitting `acl` is not the same as `acl: []`.

### Design documents

| Doc                   | Role                                                                                                                                                                                                   |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`_design/acl`**     | Control plane: ACL view, `validate_doc_update`, optional `dbacl` / `restrict`. Typically `acl: []` so non-admins cannot read the body.                                                                 |
| **Other `_design/*`** | App views, filters, etc. With no grant fields → **read-only** for `r-*`. Non-admins cannot write/delete design docs through the proxy. Use `acl: []` (or explicit grants) if a ddoc must stay private. |

Unsupported / unsafe for non-admins: `_list`, `_show` / `_update` without a doc id, view `reduce`/`group` → **501**. Prefer filtered views or Mango `_find`.

### Local docs (`_local/…`)

Used for PouchDB sync checkpoints. After the DB gate, members can read/write `_local` docs (Couch checkpoint semantics). Do not put secrets you would not share among DB members there.

### System databases

`_users`, `_replicator`, `_global_changes` are never auto-mutated with `_design/acl`. Provision carefully; without a ddoc they pass through to Couch `_security` only.

---

## Capability cheat sheet

For a non-admin principal matching the listed grant:

| Standing                         | Read                         | Write / update | Delete | Change `acl` | Change `owners` / `creator`                  |
| -------------------------------- | ---------------------------- | -------------- | ------ | ------------ | -------------------------------------------- |
| `creator`                        | ✓                            | ✓              | ✓      | ✓            | creator only (owners/acl); creator immutable |
| `owners`                         | ✓                            | ✓              | ✗      | ✓            | ✗                                            |
| `acl` (reader)                   | ✓                            | ✗              | ✗      | ✗            | ✗                                            |
| `r-*` open doc (no grant fields) | ✓                            | ✓              | ✓      | —            | —                                            |
| via `parent` only                | union of parent’s grants     | same           | same   | —            | —                                            |
| via `dbacl` overlay              | extra flags on **every** doc | same           | same   | —            | —                                            |

Server admins always pass. Couch `validate_doc_update` on `_design/acl` also blocks forging `creator` on create and illegal ownership/acl edits even if a request slipped past the proxy.

---

## Bucket controls on `_design/acl`

Besides the map + VDU, the ddoc may carry:

### `dbacl` — overlay on every document

```json
{
  "dbacl": {
    "_r": ["r-writers"],
    "_w": [],
    "_d": []
  }
}
```

Matching tokens gain that flag on **all** docs in the DB (OR’d with per-doc grants). Useful for “staff can read everything” without tagging each doc.

### `restrict` — DB visibility and path/method ACL

```json
{
  "restrict": {
    "*": ["u-alice", "r-writers"],
    "get": {
      "*attachments=true": ["u-alice"]
    }
  }
}
```

- **`restrict.*`** — who may see/use the DB. Non-matches get **404** and the DB is omitted from `/_all_dbs`.
- **`restrict.get|post|put|delete|head`** — map of path+query fragments (after `/{db}`) → allowed tokens. Wildcards: `*` = any chars, `+` = any chars except `/`. If a URL matches one or more rules, the caller needs a token from the **union** of those rules; if nothing matches, the method is allowed.

Use restrict for coarse API fencing (e.g. hide a private DB, block attachment bulk-download queries). Prefer document ACL for sharing individual records.

---

## How the library interacts with Couch

1. **Ensures** `_design/acl` on app DBs (unless disabled / system DB).
2. **Indexes** every doc through `views.acl` into an in-memory cache (kept hot via `_changes`).
3. **Resolves** principal → tokens → r/w/d (doc + parent + `dbacl`).
4. **Filters** list-like APIs (`_all_docs`, views, `_changes`, `_find`, `_bulk_get`, …) so denied rows never leak.
5. Relies on Couch **`validate_doc_update`** so creator/owners/acl rules hold at write time.

If the ACL cache or follower is unhealthy, the proxy **fails closed** (`503`) rather than serving stale grants.

---

## Instrumenting an application

### 1. Point clients at the proxy

Use the proxy base URL for session, CRUD, views, Mango, and PouchDB sync. Keep admin/direct Couch off the public network.

### 2. Provision users and DB membership

Create Couch users with roles that match your product groups (`readers`, `editors`, …). Put those names/roles in `_security.members`. Document grants then use `r-<role>` / `u-<user>`.

### 3. Stamp every created doc

On create (PUT/POST/`_bulk_docs`/Pouch `put`):

```json
{
  "_id": "note-123",
  "creator": "alice",
  "title": "…",
  "body": "…"
}
```

- Always set `creator` to the **authenticated** user (VDU rejects spoofing).
- Private by default: `creator` alone → only that user (until you add `acl` / `owners`).
- Shared read: `"acl": ["u-bob", "r-readers"]`.
- Shared edit: `"owners": ["u-bob"]` (still cannot delete; only creator can).
- Hierarchy: child docs with `"parent": "folder-1"` inherit the folder’s grants (union).

Omit `creator`/`owners`/`acl` only when you intentionally want **any authenticated member** to fully control the doc.

### 4. Share by updating grants, not by copying data

Creators (and owners, for `acl`) update the same document:

```json
{ "creator": "alice", "acl": ["u-bob", "r-readers"], "body": "…" }
```

Revocation is the same write with a narrower list. Expect visibility to drop on the next filtered `_changes` / pull for removed readers.

### 5. Design your views for filtered clients

Non-admins never see denied docs in view/`_all_docs`/`_changes` results. Design indexes around keys you query (`key` / `keys`), not around assuming `limit=N` returns N visible rows—after ACL filtering, pages may under-deliver.

Avoid `reduce`/`group` for end-user traffic through the proxy.

### 6. PouchDB / offline sync

Sync against the proxy with the user’s session/JWT. The filtered `_changes` feed is the security boundary: the local DB only receives readable docs (and tombstones the user could previously read). Checkpoints use `_local` on the remote.

Do not assume a full replica; treat the device as a **partial, ACL-shaped** subset.

### 7. Hide control-plane design docs

Leave `_design/acl` with `acl: []`. For app ddocs that must not be downloadable by clients, set `acl: []` (or explicit admin-only style grants) instead of relying on the default `r-*` read.

### 8. Optional bucket policy

Admins edit `_design/acl` to set `dbacl` / `restrict` when you need DB-wide read overlays or to hide a DB from some members entirely. Prefer doc fields for day-to-day sharing.

---

## Worked patterns

**Personal note (private)**  
`{ "creator": "alice", … }` — only alice.

**Share read-only with a user**  
`{ "creator": "alice", "acl": ["u-bob"], … }`

**Share edit with a role**  
`{ "creator": "alice", "owners": ["r-editors"], … }` — role members may update; only alice deletes.

**Folder + children**  
Folder: `{ "_id": "folder-1", "creator": "alice", "acl": ["u-bob"] }`  
Child: `{ "creator": "carol", "parent": "folder-1", … }` — bob can read the child via parent union even if the child has no `acl`.

**Team-readable corpus**  
Either tag docs `"acl": ["r-readers"]`, or set `dbacl._r: ["r-readers"]` once on `_design/acl`.

**Invite-only database**  
`restrict: { "*": ["u-alice", "u-bob"] }` plus normal doc ACL inside.

---

## Client expectations checklist

- Authenticate through Couch session/JWT; send the same credentials to the proxy.
- On create, set `creator` to the current user; never trust client-supplied creator for others.
- Use `acl` for readers, `owners` for collaborators, `creator` for lifecycle/delete.
- Treat `404` on GET as “not visible or missing”; do not retry as a different privilege probe.
- Prefer keyed queries; tolerate shorter pages after ACL filtering.
- Sync clients: expect partial datasets and filtered live changes.
- Keep end-user traffic on mapped, filterable APIs (docs, views with `reduce=false`, `_find`, `_changes`)—not admin or unmapped endpoints (default-deny **404**).

---

## Quick reference: grant sources → flags

From the ACL map (same rules the proxy resolves):

1. **`creator`** → `_r` + `_w` + `_d` for that user token
2. **`acl[]`** → `_r` only for each token
3. **`owners[]`** → `_r` + `_w` for each token
4. **None of the above** → `r-*` gets `_r/_w/_d` (design docs: `_r` only)
5. **`parent`** → OR parent’s flags into the child
6. **`dbacl`** → OR bucket flags onto every doc

That is the entire per-document access model your application should design around.
