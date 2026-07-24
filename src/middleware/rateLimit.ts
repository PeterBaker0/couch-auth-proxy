/**
 * In-process rate limiting middleware (global + per-IP sliding windows).
 *
 * Global overload returns 503 (`service_unavailable`); per-IP excess returns
 * 429. Client IP resolution respects `TRUST_PROXY_HOPS` (0 = ignore spoofable
 * forwarding headers). Suitable for single-process deployments; use an edge
 * limiter when running multiple replicas.
 */
import { createMiddleware } from "hono/factory";
import type { AppEnv } from "./context.js";
import { resolveClientIp } from "../util/clientIp.js";
import { createLogger } from "../util/log.js";

const log = createLogger("rate-limit");

type Bucket = { count: number; resetAt: number };

/**
 * Simple in-process rate limiter (global + per-IP).
 * Returns 503 for global overload and 429 for per-IP (legacy used 420).
 */
export function rateLimit() {
  const globalBucket: Bucket = { count: 0, resetAt: 0 };
  const ipBuckets = new Map<string, Bucket>();

  return createMiddleware<AppEnv>(async (c, next) => {
    const cfg = c.get("config").rateLimit;
    if (!cfg.enabled) {
      await next();
      return;
    }

    const now = Date.now();
    if (now >= globalBucket.resetAt) {
      globalBucket.count = 0;
      globalBucket.resetAt = now + cfg.windowMs;
    }
    globalBucket.count += 1;
    if (globalBucket.count > cfg.maxRequests) {
      log.warn("global rate limit exceeded", {
        count: globalBucket.count,
        maxRequests: cfg.maxRequests,
        path: c.req.path,
      });
      return c.json({ error: "service_unavailable", reason: "rate limit" }, 503);
    }

    const ip = resolveClientIp(c.req.raw.headers, c.get("config").server.trustProxyHops);
    let bucket = ipBuckets.get(ip);
    if (!bucket || now >= bucket.resetAt) {
      bucket = { count: 0, resetAt: now + cfg.perIpWindowMs };
      ipBuckets.set(ip, bucket);
    }
    bucket.count += 1;
    const remaining = Math.max(0, cfg.perIpMaxRequests - bucket.count);
    c.header("X-RateLimit-Limit", String(cfg.perIpMaxRequests));
    c.header("X-RateLimit-Remaining", String(remaining));
    if (bucket.count > cfg.perIpMaxRequests) {
      log.warn("per-IP rate limit exceeded", {
        ip,
        count: bucket.count,
        maxRequests: cfg.perIpMaxRequests,
        path: c.req.path,
      });
      return c.json({ error: "too_many_requests", reason: "rate limit" }, 429);
    }

    // Opportunistic cleanup so the map cannot grow without bound.
    if (ipBuckets.size > 10_000) {
      for (const [key, value] of ipBuckets) {
        if (now >= value.resetAt) ipBuckets.delete(key);
      }
    }

    await next();
  });
}
