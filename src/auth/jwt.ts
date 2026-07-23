/**
 * Optional local JWT verification (HS256).
 *
 * Prefer `SessionResolver` (Couch `GET /_session`) for production parity —
 * Couch validates Bearer tokens with its `[jwt_keys]` / `[jwt_auth]` config
 * and couch-auth-proxy never forks JWT semantics. Use this helper only when keys are
 * guaranteed identical to Couch and a round-trip must be avoided (or in tests).
 */
import * as jose from "jose";
import type { AppConfig } from "../config.js";
import { buildPrincipal } from "./principal.js";
import type { Principal, SessionInfo } from "./types.js";

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
