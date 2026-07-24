/**
 * Bind the declarative `ROUTES` table onto a Hono app.
 *
 * Each route's actor names are resolved to functions, composed into a chain,
 * and mounted for the HTTP method. Actors may return a `Response` (short-circuit)
 * or call `next()`. If the chain ends without a Response, the request is piped
 * to Couch.
 *
 * When an env route policy is active, a precompiled per-route gate runs before
 * the actor chain (O(1) for feature/template-only policies; regexes are
 * compiled once at startup).
 *
 * Unmapped paths are default-denied for non-admins (403 for `/_*`, else 404).
 * Admins may pipe anything unmapped.
 */
import type { Hono } from "hono";
import type { AppEnv } from "../middleware/context.js";
import { compileRouteGate, type CompiledAccessPolicy } from "../acl/envAccessPolicy.js";
import { ROUTES, type ActorName, type HttpMethod } from "./restmap.js";
import { actors, type Actor } from "./actors.js";
import { couchError, forwardToCouch } from "../proxy/forward.js";
import { createLogger, isLevelEnabled } from "../util/log.js";

const log = createLogger("routes");

/**
 * Register all restmap routes plus the default-deny catch-all.
 */
export function registerRoutes(app: Hono<AppEnv>, accessPolicy?: CompiledAccessPolicy): void {
  for (const route of ROUTES) {
    const chain = route.actors.map((name) => resolveActor(name));
    const gate = accessPolicy ? compileRouteGate(accessPolicy, route) : null;
    const gated: Actor[] = gate
      ? [
          async (c, next) => {
            const principal = c.get("principal");
            if (!gate.allowed(principal, c.req.method, c.req.path)) {
              if (isLevelEnabled("debug")) {
                log.debug("route policy deny", {
                  method: c.req.method,
                  path: c.req.path,
                  user: principal.name,
                  features: route.features,
                });
              }
              return couchError("forbidden", "Endpoint not allowed.", 403);
            }
            await next();
          },
          ...chain,
        ]
      : chain;
    const handler = compose(gated);
    mount(app, route.method, route.path, handler);
  }

  // Default-deny: unmapped paths never silently pipe for non-admins.
  app.all("*", async (c) => {
    const principal = c.get("principal");
    if (principal.admin) {
      log.debug("default-deny admin pipe", { method: c.req.method, path: c.req.path });
      return forwardToCouch(c, c.get("config"));
    }
    const path = c.req.path;
    if (path.startsWith("/_") && !path.startsWith("/_couch-auth-proxy")) {
      log.debug("default-deny forbidden", {
        method: c.req.method,
        path,
        user: principal.name,
      });
      return couchError("forbidden", "Access denied.", 403);
    }
    log.debug("default-deny not_found", {
      method: c.req.method,
      path,
      user: principal.name,
    });
    return couchError("not_found", "Unsupported endpoint.", 404);
  });
}

/** Look up an actor by name; unknown names become a 500 responder. */
function resolveActor(name: ActorName): Actor {
  const actor = actors[name];
  if (!actor) {
    return async () => couchError("error", `Unknown actor: ${name}`, 500);
  }
  return actor;
}

/**
 * Compose actors into a single handler.
 * Each actor's `next` advances the index; falling through without `next` also advances.
 */
function compose(chain: Actor[]): Actor {
  return async (c, _next) => {
    let index = 0;
    const next = async (): Promise<void> => {
      index += 1;
    };
    while (index < chain.length) {
      const actor = chain[index]!;
      const current = index;
      const result = await actor(c, next);
      if (result instanceof Response) return result;
      // Actor called next() → index advanced; or fell through without next.
      if (index === current) index += 1;
    }
    // Chain ended without Response — pipe.
    return forwardToCouch(c, c.get("config"));
  };
}

/** Mount a composed handler on the Hono app for the given method. */
function mount(app: Hono<AppEnv>, method: HttpMethod, path: string, handler: Actor): void {
  const h = async (c: Parameters<Actor>[0]) => {
    const res = await handler(c, async () => {});
    return res ?? forwardToCouch(c, c.get("config"));
  };
  switch (method) {
    case "get":
      app.get(path, h);
      break;
    case "post":
      app.post(path, h);
      break;
    case "put":
      app.put(path, h);
      break;
    case "delete":
      app.delete(path, h);
      break;
    case "head":
      app.on("HEAD", path, h);
      break;
    case "copy":
      app.on("COPY", path, h);
      break;
  }
}
