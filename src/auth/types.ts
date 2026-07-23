/**
 * Authentication / identity types shared by session resolution and ACL.
 *
 * couch-auth-proxy mirrors CouchDB's `userCtx` shape from `GET /_session`, then
 * expands it into a `Principal` with precomputed ACL match tokens.
 */

/** CouchDB `userCtx` from `/_session`. */
export type UserCtx = {
  name: string | null;
  roles: string[];
};

/** Full `/_session` JSON body (subset we care about). */
export type SessionInfo = {
  ok: boolean;
  userCtx: UserCtx;
  info?: {
    authenticated?: string;
    authentication_handlers?: string[];
    authentication_db?: string;
  };
};

/**
 * Resolved caller identity used for every ACL decision.
 *
 * `aclTokens` is the expanded set matched against document / restrict grants:
 * username, `u-<name>`, each role / `r-<role>`, and `r-*` when authenticated.
 */
export type Principal = {
  name: string | null;
  roles: string[];
  /** True when roles includes `_admin` (server admin). */
  admin: boolean;
  /** Principal tokens used for ACL matching: name, u-name, r-role, r-*. */
  aclTokens: string[];
  authenticatedBy: "jwt" | "cookie" | "basic" | "default" | "unknown" | null;
  raw: SessionInfo;
};
