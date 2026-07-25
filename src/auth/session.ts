/**
 * Resolve the caller identity the same way CouchDB would.
 *
 * Preferred path: forward `Authorization` (Basic / Bearer JWT) and `Cookie`
 * to Couch `GET /_session`, then build a `Principal` from the response so
 * JWT/cookie/basic semantics stay owned by Couch.
 *
 * Optional fast path: when `JWT_LOCAL_VERIFY=true` and the request carries a
 * Bearer token, verify HS256 locally with the same secret Couch trusts
 * (`JWT_HMAC_SECRET`). With `AUTH_RESOLVE_VIA_COUCH_SESSION=true` this skips
 * the `/_session` RTT for Bearer clients only (Basic/Cookie still use Couch).
 * With session resolve disabled, Bearer local-verify is the sole resolver.
 *
 * Couch `/_session` results (and successful local JWT principals) are cached
 * briefly (LRU + TTL, default 5000ms) keyed by a hash of credentials.
 * Concurrent identical lookups also coalesce in-flight. Set
 * `SESSION_CACHE_TTL_MS=0` to re-resolve on every request.
 */
import { createHash } from "node:crypto";
import type { AppConfig } from "../config.js";
import { LruMap } from "../util/lru.js";
import { createLogger, isLevelEnabled } from "../util/log.js";
import { bearerToken, verifyJwtLocally } from "./jwt.js";
import { anonymousPrincipal, buildPrincipal } from "./principal.js";
import type { Principal, SessionInfo } from "./types.js";

type CacheEntry = { principal: Principal; expiresAt: number };
const log = createLogger("session");

/**
 * Session / principal resolver backed by Couch `/_session`.
 */
export class SessionResolver {
  private readonly cache: LruMap<CacheEntry>;
  /**
   * In-flight `/_session` lookups keyed by credential hash. Concurrent requests
   * with the same Authorization/Cookie share one upstream round-trip without
   * introducing a TTL-based revocation window.
   */
  private readonly inflight = new Map<string, Promise<Principal>>();

  constructor(private readonly config: AppConfig) {
    this.cache = new LruMap(config.couch.sessionCacheMaxEntries);
  }

  /**
   * Compact size counters for opt-in PROFILE memory scrapes.
   * Session cache is LRU-bounded (`SESSION_CACHE_MAX`); inflight should stay near 0 at rest.
   */
  resourceStats(): { sessionCacheEntries: number; sessionInflight: number } {
    return {
      sessionCacheEntries: this.cache.size,
      sessionInflight: this.inflight.size,
    };
  }

  /**
   * Resolve identity from incoming request headers.
   * Missing credentials → anonymous. Couch 401 / invalid JWT → anonymous
   * (upstream may still reject the forwarded credential).
   */
  async resolve(headers: Headers): Promise<Principal> {
    const auth = headers.get("authorization") ?? "";
    const cookie = headers.get("cookie") ?? "";
    if (!auth && !cookie) {
      if (isLevelEnabled("verbose")) {
        log.verbose("resolve", { reason: "no-credentials", user: null, admin: false });
      }
      return anonymousPrincipal();
    }

    const cacheKey = hashCreds(auth, cookie);
    const cached = this.cache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      if (isLevelEnabled("verbose")) {
        log.verbose("resolve", {
          reason: "cache-hit",
          user: cached.principal.name,
          admin: cached.principal.admin,
          roles: cached.principal.roles,
          aclTokenCount: cached.principal.aclTokens.length,
        });
      }
      return cached.principal;
    }

    // Bearer + local verify: skip Couch `/_session` when keys match Couch.
    // Used as sole resolver when session resolve is off, or as a Bearer
    // fast-path when both are enabled (Basic/Cookie still hit Couch).
    if (this.config.auth.jwt.enabled) {
      const token = bearerToken(auth);
      if (token) {
        try {
          const principal = await verifyJwtLocally(token, this.config);
          this.storeCache(cacheKey, principal);
          if (isLevelEnabled("verbose")) {
            log.verbose("resolve", {
              reason: "local-jwt",
              user: principal.name,
              admin: principal.admin,
              roles: principal.roles,
              aclTokenCount: principal.aclTokens.length,
            });
          }
          return principal;
        } catch (err) {
          // Invalid/expired JWTs are anonymous for ACL purposes. Couch will
          // independently reject the forwarded credential on the upstream hop.
          log.debug("resolve local-jwt failed; anonymous", { err: String(err) });
          return anonymousPrincipal();
        }
      }
      if (!this.config.auth.resolveViaCouchSession) {
        if (isLevelEnabled("verbose")) {
          log.verbose("resolve", { reason: "local-jwt-missing-bearer", user: null });
        }
        return anonymousPrincipal();
      }
    } else if (!this.config.auth.resolveViaCouchSession) {
      log.debug("resolve local-jwt disabled; anonymous");
      return anonymousPrincipal();
    }

    const pending = this.inflight.get(cacheKey);
    if (pending) {
      if (isLevelEnabled("verbose")) {
        log.verbose("resolve", {
          reason: "inflight-coalesce",
          cacheKeyPrefix: cacheKey.slice(0, 8),
        });
      }
      return pending;
    }

    const lookup = this.resolveCouchSession(auth, cookie, cacheKey).finally(() => {
      this.inflight.delete(cacheKey);
    });
    this.inflight.set(cacheKey, lookup);
    return lookup;
  }

  /** Store a principal when `SESSION_CACHE_TTL_MS > 0`. */
  private storeCache(cacheKey: string, principal: Principal): void {
    if (this.config.couch.sessionCacheTtlMs > 0) {
      this.cache.set(cacheKey, {
        principal,
        expiresAt: Date.now() + this.config.couch.sessionCacheTtlMs,
      });
    }
  }

  /** One Couch `/_session` fetch + optional TTL cache store. */
  private async resolveCouchSession(
    auth: string,
    cookie: string,
    cacheKey: string,
  ): Promise<Principal> {
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
      log.debug("resolve couch-session not ok; anonymous", { status: res.status });
      return anonymousPrincipal();
    }

    const body = (await res.json()) as SessionInfo;
    const principal = buildPrincipal(body);
    this.storeCache(cacheKey, principal);

    if (isLevelEnabled("verbose")) {
      log.verbose("resolve", {
        reason: "couch-session",
        user: principal.name,
        admin: principal.admin,
        roles: principal.roles,
        aclTokens: principal.aclTokens,
        authenticatedBy: principal.authenticatedBy,
      });
    } else if (isLevelEnabled("debug")) {
      log.debug("resolve", {
        reason: "couch-session",
        user: principal.name,
        admin: principal.admin,
        roleCount: principal.roles.length,
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
