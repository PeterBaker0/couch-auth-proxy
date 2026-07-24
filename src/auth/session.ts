/**
 * Resolve the caller identity the same way CouchDB would.
 *
 * Forwards `Authorization` (Basic / Bearer JWT) and `Cookie` to Couch
 * `GET /_session`, then builds a `Principal` from the response. This is the
 * preferred JWT strategy — Couch validates tokens with its own keys;
 * couch-auth-proxy never forks JWT semantics.
 *
 * Results are cached briefly (LRU + TTL, default 5000ms) keyed by a hash of
 * credentials so hot paths avoid a session round-trip on every request.
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
   * Missing credentials → anonymous. Couch 401 → anonymous (upstream may still reject).
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

    if (!this.config.auth.resolveViaCouchSession) {
      if (!this.config.auth.jwt.enabled) {
        log.debug("resolve local-jwt disabled; anonymous");
        return anonymousPrincipal();
      }
      const token = bearerToken(auth);
      if (!token) {
        if (isLevelEnabled("verbose")) {
          log.verbose("resolve", { reason: "local-jwt-missing-bearer", user: null });
        }
        return anonymousPrincipal();
      }
      try {
        const principal = await verifyJwtLocally(token, this.config);
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
        // independently reject the forwarded credential.
        log.debug("resolve local-jwt failed; anonymous", { err: String(err) });
        return anonymousPrincipal();
      }
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

    if (this.config.couch.sessionCacheTtlMs > 0) {
      this.cache.set(cacheKey, {
        principal,
        expiresAt: Date.now() + this.config.couch.sessionCacheTtlMs,
      });
    }

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
