/**
 * Resolve the caller identity the same way CouchDB would.
 *
 * Forwards `Authorization` (Basic / Bearer JWT) and `Cookie` to Couch
 * `GET /_session`, then builds a `Principal` from the response. This is the
 * preferred JWT strategy — Couch validates tokens with its own keys;
 * couch-auth-proxy never forks JWT semantics.
 *
 * Results are cached briefly (LRU + TTL) keyed by a hash of credentials so
 * hot paths avoid a session round-trip on every request.
 */
import { createHash } from "node:crypto";
import type { AppConfig } from "../config.js";
import { LruMap } from "../util/lru.js";
import { bearerToken, verifyJwtLocally } from "./jwt.js";
import { anonymousPrincipal, buildPrincipal } from "./principal.js";
import type { Principal, SessionInfo } from "./types.js";

type CacheEntry = { principal: Principal; expiresAt: number };

/**
 * Session / principal resolver backed by Couch `/_session`.
 */
export class SessionResolver {
  private readonly cache: LruMap<CacheEntry>;

  constructor(private readonly config: AppConfig) {
    this.cache = new LruMap(config.couch.sessionCacheMaxEntries);
  }

  /**
   * Resolve identity from incoming request headers.
   * Missing credentials → anonymous. Couch 401 → anonymous (upstream may still reject).
   */
  async resolve(headers: Headers): Promise<Principal> {
    const auth = headers.get("authorization") ?? "";
    const cookie = headers.get("cookie") ?? "";
    if (!auth && !cookie) return anonymousPrincipal();

    if (!this.config.auth.resolveViaCouchSession) {
      if (!this.config.auth.jwt.enabled) return anonymousPrincipal();
      const token = bearerToken(auth);
      if (!token) return anonymousPrincipal();
      try {
        return await verifyJwtLocally(token, this.config);
      } catch {
        // Invalid/expired JWTs are anonymous for ACL purposes. Couch will
        // independently reject the forwarded credential.
        return anonymousPrincipal();
      }
    }

    const cacheKey = hashCreds(auth, cookie);
    const cached = this.cache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) return cached.principal;

    const upstream = new Headers({ Accept: "application/json" });
    if (auth) upstream.set("Authorization", auth);
    if (cookie) upstream.set("Cookie", cookie);

    const res = await fetch(new URL("/_session", this.config.couch.url), {
      method: "GET",
      headers: upstream,
    });

    if (!res.ok) {
      // Couch returns 401 for bad creds; treat as anonymous for ACL purposes
      // and let upstream reject on proxy if needed.
      return anonymousPrincipal();
    }

    const body = (await res.json()) as SessionInfo;
    const principal = buildPrincipal(body);

    if (this.config.couch.sessionCacheTtlMs > 0) {
      this.cache.set(cacheKey, {
        principal,
        expiresAt: Date.now() + this.config.couch.sessionCacheTtlMs,
      });
    }

    return principal;
  }

  /** Drop all cached principals (logout, tests, credential rotation). */
  clear(): void {
    this.cache.clear();
  }

  /** Drop the cache entry for a specific Authorization/Cookie pair. */
  invalidate(headers: Headers): void {
    const auth = headers.get("authorization") ?? "";
    const cookie = headers.get("cookie") ?? "";
    if (!auth && !cookie) return;
    this.cache.delete(hashCreds(auth, cookie));
  }
}

/** SHA-256 of auth+cookie so secrets are not stored as map keys. */
function hashCreds(auth: string, cookie: string): string {
  return createHash("sha256").update(`${auth}\n${cookie}`).digest("hex");
}
