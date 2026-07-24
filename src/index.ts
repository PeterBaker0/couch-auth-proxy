/**
 * Process entrypoint for couch-auth-proxy.
 *
 * Loads config, builds the Hono app + ACL services, optionally preloads ACL
 * caches for configured databases, then serves HTTP until SIGINT/SIGTERM.
 * On shutdown the ACL changes followers are stopped and the server is closed
 * with a forced exit after `shutdownTimeoutMs`.
 */
import { serve } from "@hono/node-server";
import { loadConfig } from "./config.js";
import { createApp, createServices } from "./app.js";
import { createLogger, getLogLevel } from "./util/log.js";

const log = createLogger("main");
const config = loadConfig();
const services = createServices(config);
const app = createApp(services);

/** Start listening and install signal handlers for graceful shutdown. */
async function boot() {
  log.info("boot", {
    logLevel: getLogLevel(),
    preloadDbs: config.couch.preloadDbs,
    aclAutoInstall: config.couch.aclAutoInstall,
    resolveViaCouchSession: config.auth.resolveViaCouchSession,
    profile: config.server.profile,
  });

  if (config.couch.preloadDbs.length) {
    log.info("preloading ACL caches", { dbs: config.couch.preloadDbs });
    await services.aclCache.preload(config.couch.preloadDbs);
  }

  const server = serve(
    {
      fetch: app.fetch,
      hostname: config.server.host,
      port: config.server.port,
    },
    (info) => {
      log.info("listening", {
        address: `http://${info.address}:${info.port}`,
        couch: config.couch.url,
        logLevel: getLogLevel(),
      });
    },
  );

  let shuttingDown = false;
  const shutdown = (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    log.info("shutdown", { signal });
    services.aclCache.stop();

    // Force-exit if drain hangs (open _changes streams, slow clients, etc.).
    const forceTimer = setTimeout(() => {
      log.warn("shutdown force exit", { afterMs: config.server.shutdownTimeoutMs });
      process.exit(1);
    }, config.server.shutdownTimeoutMs);
    forceTimer.unref?.();

    try {
      const closer = server as { close?: (cb?: (err?: Error) => void) => void };
      if (typeof closer.close === "function") {
        closer.close(() => {
          clearTimeout(forceTimer);
          process.exit(0);
        });
      } else {
        clearTimeout(forceTimer);
        process.exit(0);
      }
    } catch {
      clearTimeout(forceTimer);
      process.exit(0);
    }
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

boot().catch((err) => {
  log.error("boot failed", { err: String(err) });
  process.exit(1);
});
