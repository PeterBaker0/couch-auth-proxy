/**
 * Structured JSON logging to stdout/stderr.
 *
 * Lines include `ts`, `level`, `component`, `msg`, plus optional fields.
 * Field names that look like secrets (authorization, cookie, password, token,
 * secret, AuthSession) are replaced with `[redacted]`.
 *
 * Levels (most → least verbose): `verbose`, `debug`, `info`, `warn`, `error`.
 *
 * Defaults: `debug` outside production, `info` in production. Override with
 * `LOG_LEVEL` (case-insensitive). Aliases: `trace`→`verbose`, `warning`→`warn`,
 * `fatal`→`error`.
 *
 * Set `LOG_LEVEL=verbose` when debugging ACL / permission decisions — actors,
 * resolvers, and filters emit detailed allow/deny trails at that level.
 */

/** Supported log levels, ordered from most to least chatty. */
export type LogLevel = "verbose" | "debug" | "info" | "warn" | "error";

const LEVEL_ORDER: Record<LogLevel, number> = {
  verbose: 5,
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

const LEVEL_ALIASES: Record<string, LogLevel> = {
  verbose: "verbose",
  trace: "verbose",
  debug: "debug",
  info: "info",
  warn: "warn",
  warning: "warn",
  error: "error",
  fatal: "error",
};

/** Component-scoped logger returned by {@link createLogger}. */
export type Logger = {
  verbose: (msg: string, fields?: Record<string, unknown>) => void;
  debug: (msg: string, fields?: Record<string, unknown>) => void;
  info: (msg: string, fields?: Record<string, unknown>) => void;
  warn: (msg: string, fields?: Record<string, unknown>) => void;
  error: (msg: string, fields?: Record<string, unknown>) => void;
  /** Bind extra fields onto every subsequent line from this logger. */
  child: (fields: Record<string, unknown>) => Logger;
};

let minLevel: LogLevel = resolveInitialLevel();

/** Parse a level string (env / CLI); returns undefined when unrecognized. */
export function parseLogLevel(raw: string | undefined | null): LogLevel | undefined {
  if (raw == null || !String(raw).trim()) return undefined;
  return LEVEL_ALIASES[String(raw).trim().toLowerCase()];
}

/** Effective minimum level currently applied. */
export function getLogLevel(): LogLevel {
  return minLevel;
}

/**
 * Override the minimum level at runtime (tests, dynamic reconfigure).
 * Pass `undefined` / empty to re-read `LOG_LEVEL` / `NODE_ENV` defaults.
 */
export function setLogLevel(level?: LogLevel | string | null): LogLevel {
  if (level == null || level === "") {
    minLevel = resolveInitialLevel();
    return minLevel;
  }
  const parsed = typeof level === "string" ? parseLogLevel(level) : level;
  if (!parsed) {
    throw new Error(`Invalid log level: ${String(level)}`);
  }
  minLevel = parsed;
  return minLevel;
}

/** True when messages at `level` would be emitted under the current threshold. */
export function isLevelEnabled(level: LogLevel): boolean {
  return LEVEL_ORDER[level] >= LEVEL_ORDER[minLevel];
}

function resolveInitialLevel(): LogLevel {
  const fromEnv = parseLogLevel(process.env.LOG_LEVEL);
  if (fromEnv) return fromEnv;
  return process.env.NODE_ENV === "production" ? "info" : "debug";
}

function emit(
  level: LogLevel,
  component: string,
  msg: string,
  fields?: Record<string, unknown>,
  bound?: Record<string, unknown>,
) {
  if (!isLevelEnabled(level)) return;
  const line = {
    ts: new Date().toISOString(),
    level,
    component,
    msg,
    ...sanitize(bound),
    ...sanitize(fields),
  };
  const out = level === "error" ? console.error : level === "warn" ? console.warn : console.log;
  out(JSON.stringify(line));
}

/**
 * True when a field name looks like a credential secret.
 *
 * ACL principal-token lists (`aclTokens`, `starTokens`, `tokens`, …) are kept —
 * they are required to debug permission decisions under `LOG_LEVEL=verbose`.
 * Credential-bearing names (`authorization`, `jwtToken`, `password`, …) stay redacted.
 */
function isSecretField(key: string): boolean {
  const lowerKey = key.toLowerCase();
  if (
    lowerKey.includes("authorization") ||
    lowerKey.includes("cookie") ||
    lowerKey.includes("password") ||
    lowerKey.includes("secret") ||
    lowerKey === "authsession"
  ) {
    return true;
  }
  if (!lowerKey.includes("token")) return false;
  // Keep ACL / restrict token sets used in verbose permission trails.
  if (
    lowerKey === "tokens" ||
    lowerKey.endsWith("tokens") ||
    lowerKey.includes("acltoken") ||
    lowerKey.includes("matched")
  ) {
    return false;
  }
  return true;
}

/** Strip secrets from structured log fields. */
function sanitize(fields?: Record<string, unknown>): Record<string, unknown> | undefined {
  if (!fields) return undefined;
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(fields)) {
    out[key] = isSecretField(key) ? "[redacted]" : value;
  }
  return out;
}

function buildLogger(component: string, bound?: Record<string, unknown>): Logger {
  return {
    verbose: (msg, fields) => emit("verbose", component, msg, fields, bound),
    debug: (msg, fields) => emit("debug", component, msg, fields, bound),
    info: (msg, fields) => emit("info", component, msg, fields, bound),
    warn: (msg, fields) => emit("warn", component, msg, fields, bound),
    error: (msg, fields) => emit("error", component, msg, fields, bound),
    child: (fields) => buildLogger(component, { ...bound, ...fields }),
  };
}

/** Create a component-scoped logger (`acl-cache`, `http`, `acl-resolve`, …). */
export function createLogger(component: string): Logger {
  return buildLogger(component);
}

/** Generate a short opaque request id when the client did not send one. */
export function requestId(): string {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

/**
 * List principal tokens that intersect a grant set (for ACL decision logs).
 * Accepts a token Record (`AclRow._r`), a `Set`, or an array. Caps output so
 * verbose dumps stay readable on large grant sets.
 */
export function matchingTokens(
  principalTokens: Iterable<string>,
  grants: Record<string, 1 | true> | ReadonlySet<string> | readonly string[],
  limit = 32,
): string[] {
  const grantSet =
    grants instanceof Set
      ? grants
      : Array.isArray(grants)
        ? new Set(grants)
        : new Set(Object.keys(grants));
  const matched: string[] = [];
  for (const token of principalTokens) {
    if (grantSet.has(token)) {
      matched.push(token);
      if (matched.length >= limit) break;
    }
  }
  return matched;
}
