/**
 * Structured access logging middleware.
 *
 * Assigns / echoes `X-Request-Id`, then logs method, path, status, duration,
 * and principal identity after the handler completes. Secrets are redacted by
 * the logger's field sanitizer.
 */
import { createMiddleware } from "hono/factory";
import type { AppEnv } from "./context.js";
import { createLogger, isLevelEnabled, requestId } from "../util/log.js";

const log = createLogger("http");

/** Log one structured line per request after the response is produced. */
export function requestLog() {
  return createMiddleware<AppEnv>(async (c, next) => {
    const id = c.req.header("x-request-id") || requestId();
    c.header("X-Request-Id", id);
    const start = Date.now();
    if (isLevelEnabled("verbose")) {
      log.verbose("request start", {
        requestId: id,
        method: c.req.method,
        path: c.req.path,
        query: c.req.url.includes("?") ? c.req.url.slice(c.req.url.indexOf("?")) : undefined,
      });
    }
    await next();
    const principal = c.get("principal");
    const fields: Record<string, unknown> = {
      requestId: id,
      method: c.req.method,
      path: c.req.path,
      status: c.res.status,
      durationMs: Date.now() - start,
      user: principal?.name ?? null,
      auth: principal?.authenticatedBy ?? null,
    };
    if (isLevelEnabled("verbose") && principal) {
      fields.admin = principal.admin;
      fields.roles = principal.roles;
      fields.aclTokens = principal.aclTokens;
    }
    const status = c.res.status;
    if (status >= 500) log.error("request", fields);
    else if (status >= 400) log.warn("request", fields);
    else log.info("request", fields);
  });
}
