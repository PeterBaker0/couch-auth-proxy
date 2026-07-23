/**
 * Early reject for oversized request bodies via Content-Length.
 *
 * Streamed bodies without Content-Length are still bounded later in
 * `fetchFromCouch` / `readJsonLimited` via `limitBytes`.
 */
import { createMiddleware } from "hono/factory";
import type { AppEnv } from "./context.js";
import { couchError } from "../proxy/forward.js";

/**
 * Reject requests whose Content-Length exceeds `maxBodyBytes` (413).
 */
export function bodyLimit() {
  return createMiddleware<AppEnv>(async (c, next) => {
    const maxBytes = c.get("config").server.maxBodyBytes;
    const contentLength = c.req.header("content-length");
    if (contentLength) {
      const length = Number(contentLength);
      if (Number.isFinite(length) && length > maxBytes) {
        return couchError("bad_request", "Request body too large", 413);
      }
    }
    await next();
  });
}
