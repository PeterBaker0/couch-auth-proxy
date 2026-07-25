/**
 * Optional local JWT verification (HS256).
 *
 * Prefer Couch `GET /_session` for production parity when clients may use
 * Basic/Cookie — Couch owns those handlers. Use this helper when:
 * - `AUTH_RESOLVE_VIA_COUCH_SESSION=false` (Bearer-only deployments), or
 * - both flags are on and Bearer tokens should skip the `/_session` RTT
 *   (keys must match Couch `[jwt_keys]` / `[jwt_auth]`).
 *
 * Upstream Couch still independently validates the forwarded Bearer token.
 */
import * as jose from "jose";
import type { AppConfig } from "../config.js";
import { createLogger, isLevelEnabled } from "../util/log.js";
import { buildPrincipal } from "./principal.js";
import type { Principal, SessionInfo } from "./types.js";

const log = createLogger("jwt");

/**
 * Verify a Bearer JWT locally and return a Principal.
 * Requires `config.auth.jwt.hmacSecret` and configured required claims.
 */
export async function verifyJwtLocally(token: string, config: AppConfig): Promise<Principal> {
  const secret = config.auth.jwt.hmacSecret;
  if (!secret) {
    throw new Error("JWT_HMAC_SECRET is required when local JWT verify is enabled");
  }

  const key = new TextEncoder().encode(secret);
  const { payload } = await jose.jwtVerify(token, key, {
    algorithms: ["HS256"],
  });

  for (const claim of config.auth.jwt.requiredClaims) {
    if (!(claim in payload)) {
      throw new Error(`JWT missing required claim: ${claim}`);
    }
  }

  const sub = payload.sub;
  if (!sub) throw new Error("JWT missing sub claim");

  const roles = extractRoles(payload, config.auth.jwt.rolesClaimPath);

  const session: SessionInfo = {
    ok: true,
    userCtx: { name: sub, roles },
    info: {
      authenticated: "jwt",
      authentication_handlers: ["jwt", "cookie", "default"],
    },
  };

  if (isLevelEnabled("verbose")) {
    log.verbose("verifyJwtLocally", { sub, roles, rolesClaimPath: config.auth.jwt.rolesClaimPath });
  }

  return buildPrincipal(session);
}

/**
 * Walk a Couch-style dotted claim path (dots in keys escaped as `\`).
 * Accepts array roles or a comma-separated string.
 */
function extractRoles(payload: jose.JWTPayload, path: string): string[] {
  const parts = path.split(/(?<!\\)\./).map((p) => p.replace(/\\./g, "."));
  let cur: unknown = payload;
  for (const part of parts) {
    if (cur == null || typeof cur !== "object") return [];
    cur = (cur as Record<string, unknown>)[part];
  }

  if (Array.isArray(cur)) return cur.map(String);
  if (typeof cur === "string") {
    return cur
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }
  return [];
}

/** Extract the raw token from an `Authorization: Bearer …` header. */
export function bearerToken(authorizationHeader: string | null): string | null {
  if (!authorizationHeader) return null;
  const match = /^Bearer\s+(.+)$/i.exec(authorizationHeader.trim());
  return match?.[1] ?? null;
}
