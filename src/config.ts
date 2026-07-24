/**
 * Environment → typed runtime configuration (Zod).
 *
 * All tunables for the proxy, Couch URLs, auth strategy, CORS, and rate limits
 * are defined here. Prefer env vars in Docker/ops; defaults suit local compose.
 *
 * Notable knobs:
 * - `ACL_AUTO_INSTALL` — whether missing `_design/acl` is installed on app DBs
 * - `ACL_DB_INCLUDE` / `ACL_DB_EXCLUDE` — opt-in database allow/deny lists
 * - `ACL_ROUTE_INCLUDE` / `ACL_ROUTE_EXCLUDE` — opt-in API surface allow/deny lists
 * - `AUTH_RESOLVE_VIA_COUCH_SESSION` — forward creds to Couch `/_session` (preferred)
 * - `TRUST_PROXY_HOPS` — how many reverse-proxy hops to trust for client IP
 */
import { z } from "zod";
import { assertDbPatterns, assertRoutePatterns } from "./acl/envAccessPolicy.js";

/** Accept boolean or common truthy env strings (`1`, `true`, `yes`, `on`). */
const boolFromEnv = z
  .union([z.boolean(), z.string()])
  .transform((v) =>
    typeof v === "boolean" ? v : ["1", "true", "yes", "on"].includes(v.toLowerCase()),
  );

const ConfigSchema = z
  .object({
    server: z.object({
      host: z.string().default("0.0.0.0"),
      port: z.coerce.number().int().positive().default(8000),
      maxBodyBytes: z.coerce
        .number()
        .int()
        .positive()
        .default(50 * 1024 * 1024),
      /** Graceful shutdown drain before force-exit (ms). */
      shutdownTimeoutMs: z.coerce.number().int().positive().default(10_000),
      /**
       * Number of trusted reverse-proxy hops for client IP (rate limit).
       * 0 = ignore X-Forwarded-For / X-Real-IP (recommended unless behind a known proxy).
       */
      trustProxyHops: z.coerce.number().int().nonnegative().default(0),
    }),
    couch: z.object({
      /** Public Couch URL used for proxying client requests (no credentials). */
      url: z.string().url(),
      /** Admin-capable URL for ACL views, ddoc install, _users follow, etc. */
      adminUrl: z.string().url(),
      usersDb: z.string().default("_users"),
      maxIdLength: z.coerce.number().int().positive().default(200),
      sessionCacheTtlMs: z.coerce.number().int().nonnegative().default(30_000),
      /** Max hashed session-cache entries (LRU). */
      sessionCacheMaxEntries: z.coerce.number().int().positive().default(10_000),
      preloadDbs: z.array(z.string()).default([]),
      /**
       * When true, missing `_design/acl` on app DBs is auto-installed.
       * System DBs (`_users`, etc.) are never auto-installed.
       * Set false in production if ddocs are provisioned out-of-band.
       */
      aclAutoInstall: boolFromEnv.default(true),
    }),
    auth: z.object({
      /**
       * Prefer resolving identity via CouchDB GET /_session with forwarded
       * Authorization/Cookie headers (JWT/cookie/basic parity with Couch).
       */
      resolveViaCouchSession: boolFromEnv.default(true),
      /**
       * Optional local JWT verification using the same keys Couch trusts.
       * Only used when resolveViaCouchSession is false, or as a future cache.
       */
      jwt: z
        .object({
          enabled: boolFromEnv.default(false),
          /** HS256 secret (raw string). Prefer env; keep in sync with Couch [jwt_keys]. */
          hmacSecret: z.string().optional(),
          /** Claim path for roles; escaped dot matches Couch's `_couchdb.roles` key. */
          rolesClaimPath: z.string().default("_couchdb\\.roles"),
          requiredClaims: z.array(z.string()).default(["exp"]),
        })
        .default({}),
    }),
    cors: z.object({
      /** Empty allowlist disables CORS reflection (same-origin only). */
      origins: z.array(z.string()).default([]),
      allowCredentials: boolFromEnv.default(true),
    }),
    rateLimit: z.object({
      enabled: boolFromEnv.default(true),
      windowMs: z.coerce.number().int().positive().default(1000),
      maxRequests: z.coerce.number().int().positive().default(100),
      perIpWindowMs: z.coerce.number().int().positive().default(10_000),
      perIpMaxRequests: z.coerce.number().int().positive().default(100),
    }),
    /**
     * Opt-in env access policy. Empty include+exclude lists preserve historical
     * behaviour (all typical DBs / restmap routes remain reachable subject to
     * per-doc ACL and `restrict.*`).
     */
    access: z.object({
      dbInclude: z.array(z.string()).default([]),
      dbExclude: z.array(z.string()).default([]),
      routeInclude: z.array(z.string()).default([]),
      routeExclude: z.array(z.string()).default([]),
    }),
  })
  .superRefine((config, ctx) => {
    if (!config.auth.resolveViaCouchSession && !config.auth.jwt.enabled) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["auth", "jwt", "enabled"],
        message: "JWT_LOCAL_VERIFY must be enabled when AUTH_RESOLVE_VIA_COUCH_SESSION is false",
      });
    }
    if (config.auth.jwt.enabled && !config.auth.jwt.hmacSecret) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["auth", "jwt", "hmacSecret"],
        message: "JWT_HMAC_SECRET is required when JWT_LOCAL_VERIFY is enabled",
      });
    }
    try {
      assertDbPatterns(config.access.dbInclude, "ACL_DB_INCLUDE");
    } catch (err) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["access", "dbInclude"],
        message: err instanceof Error ? err.message : String(err),
      });
    }
    try {
      assertDbPatterns(config.access.dbExclude, "ACL_DB_EXCLUDE");
    } catch (err) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["access", "dbExclude"],
        message: err instanceof Error ? err.message : String(err),
      });
    }
    try {
      assertRoutePatterns(config.access.routeInclude, "ACL_ROUTE_INCLUDE");
    } catch (err) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["access", "routeInclude"],
        message: err instanceof Error ? err.message : String(err),
      });
    }
    try {
      assertRoutePatterns(config.access.routeExclude, "ACL_ROUTE_EXCLUDE");
    } catch (err) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["access", "routeExclude"],
        message: err instanceof Error ? err.message : String(err),
      });
    }
  });

export type AppConfig = z.infer<typeof ConfigSchema>;

/** Split a comma-separated env value into trimmed non-empty parts. */
function splitCsv(value: string | undefined): string[] {
  if (!value?.trim()) return [];
  return value
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Load and validate config from `process.env` (or a test override).
 *
 * If `COUCH_ADMIN_URL` is unset, embeds `COUCH_ADMIN_USER`/`PASSWORD` into the
 * public Couch URL. Credentials are stripped from logged URLs by AdminClient.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const couchUrl = env.COUCH_URL ?? "http://127.0.0.1:5984";
  const adminUser = env.COUCH_ADMIN_USER ?? "admin";
  const adminPass = env.COUCH_ADMIN_PASSWORD ?? "password";
  const adminUrl =
    env.COUCH_ADMIN_URL ??
    couchUrl.replace(
      /^(https?:\/\/)/,
      `$1${encodeURIComponent(adminUser)}:${encodeURIComponent(adminPass)}@`,
    );

  return ConfigSchema.parse({
    server: {
      host: env.HOST ?? "0.0.0.0",
      port: env.PORT ?? 8000,
      maxBodyBytes: env.MAX_BODY_BYTES ?? 50 * 1024 * 1024,
      shutdownTimeoutMs: env.SHUTDOWN_TIMEOUT_MS ?? 10_000,
      trustProxyHops: env.TRUST_PROXY_HOPS ?? 0,
    },
    couch: {
      url: couchUrl,
      adminUrl,
      usersDb: env.COUCH_USERS_DB ?? "_users",
      maxIdLength: env.COUCH_MAX_ID_LENGTH ?? 200,
      sessionCacheTtlMs: env.SESSION_CACHE_TTL_MS ?? 30_000,
      sessionCacheMaxEntries: env.SESSION_CACHE_MAX ?? 10_000,
      preloadDbs: splitCsv(env.COUCH_PRELOAD_DBS),
      aclAutoInstall: env.ACL_AUTO_INSTALL ?? true,
    },
    auth: {
      resolveViaCouchSession: env.AUTH_RESOLVE_VIA_COUCH_SESSION ?? true,
      jwt: {
        enabled: env.JWT_LOCAL_VERIFY ?? false,
        hmacSecret: env.JWT_HMAC_SECRET,
        rolesClaimPath: env.JWT_ROLES_CLAIM_PATH ?? "_couchdb\\.roles",
        requiredClaims: splitCsv(env.JWT_REQUIRED_CLAIMS ?? "exp"),
      },
    },
    cors: {
      origins: splitCsv(env.CORS_ORIGINS),
      allowCredentials: env.CORS_ALLOW_CREDENTIALS ?? true,
    },
    rateLimit: {
      enabled: env.RATE_LIMIT_ENABLED ?? true,
      windowMs: env.RATE_LIMIT_WINDOW_MS ?? 1000,
      maxRequests: env.RATE_LIMIT_MAX ?? 100,
      perIpWindowMs: env.RATE_LIMIT_IP_WINDOW_MS ?? 10_000,
      perIpMaxRequests: env.RATE_LIMIT_IP_MAX ?? 100,
    },
    access: {
      dbInclude: splitCsv(env.ACL_DB_INCLUDE),
      dbExclude: splitCsv(env.ACL_DB_EXCLUDE),
      routeInclude: splitCsv(env.ACL_ROUTE_INCLUDE),
      routeExclude: splitCsv(env.ACL_ROUTE_EXCLUDE),
    },
  });
}
