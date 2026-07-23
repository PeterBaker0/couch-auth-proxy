/**
 * Structured JSON logging to stdout/stderr.
 *
 * Lines include `ts`, `level`, `component`, `msg`, plus optional fields.
 * Field names that look like secrets (authorization, cookie, password, token,
 * secret, AuthSession) are replaced with `[redacted]`.
 *
 * Level defaults: `debug` outside production, `info` in production; override
 * with `LOG_LEVEL`.
 */
type Level = "debug" | "info" | "warn" | "error";

const LEVEL_ORDER: Record<Level, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

const minLevel: Level =
  (process.env.LOG_LEVEL as Level | undefined) ??
  (process.env.NODE_ENV === "production" ? "info" : "debug");

function emit(level: Level, component: string, msg: string, fields?: Record<string, unknown>) {
  if (LEVEL_ORDER[level] < LEVEL_ORDER[minLevel]) return;
  const line = {
    ts: new Date().toISOString(),
    level,
    component,
    msg,
    ...sanitize(fields),
  };
  const out = level === "error" ? console.error : level === "warn" ? console.warn : console.log;
  out(JSON.stringify(line));
}

/** Strip secrets from structured log fields. */
function sanitize(fields?: Record<string, unknown>): Record<string, unknown> | undefined {
  if (!fields) return undefined;
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(fields)) {
    const lowerKey = key.toLowerCase();
    if (
      lowerKey.includes("authorization") ||
      lowerKey.includes("cookie") ||
      lowerKey.includes("password") ||
      lowerKey.includes("token") ||
      lowerKey.includes("secret") ||
      lowerKey === "authsession"
    ) {
      out[key] = "[redacted]";
    } else {
      out[key] = value;
    }
  }
  return out;
}

/** Create a component-scoped logger (`acl-cache`, `http`, …). */
export function createLogger(component: string) {
  return {
    debug: (msg: string, fields?: Record<string, unknown>) => emit("debug", component, msg, fields),
    info: (msg: string, fields?: Record<string, unknown>) => emit("info", component, msg, fields),
    warn: (msg: string, fields?: Record<string, unknown>) => emit("warn", component, msg, fields),
    error: (msg: string, fields?: Record<string, unknown>) => emit("error", component, msg, fields),
  };
}

/** Generate a short opaque request id when the client did not send one. */
export function requestId(): string {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}
