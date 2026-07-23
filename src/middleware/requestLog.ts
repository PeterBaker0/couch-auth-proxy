/**
 * Structured access logging middleware.
 *
 * Assigns / echoes `X-Request-Id`, then logs method, path, status, duration,
 * and principal identity after the handler completes. Secrets are redacted by
 * the logger's field sanitizer.
 */
import { createMiddleware } from "hono/factory";
import type { AppEnv } from "./context.js";
import { createLogger, requestId } from "../util/log.js";

const log = createLogger("http");

/** Log one structured line per request after the response is produced. */
export function requestLog() {
  return createMiddleware<AppEnv>(async (c, next) => {
    const id = c.req.header("x-request-id") || requestId();
    c.header("X-Request-Id", id);
    const start = Date.now();
    await next();
    const principal = c.get("principal");
    log.info("request", {
      requestId: id,
      method: c.req.method,
      path: c.req.path,
      status: c.res.status,
      durationMs: Date.now() - start,
      user: principal?.name ?? null,
      auth: principal?.authenticatedBy ?? null,
    });
  });
}
