/**
 * Process-wide access policy from `ACL_DB_*` / `ACL_ROUTE_*` environment lists.
 *
 * Opt-in: empty include + empty exclude preserves historical behaviour.
 * Regex entries (`/pattern/flags`) are compiled once at startup; exact strings
 * use Set lookup. Admins bypass both DB and route gates (same as `restrict.*`).
 */
import type { Principal } from "../auth/types.js";
import {
  allowedByIncludeExclude,
  compileMatchList,
  parsePatternEntry,
  type CompiledMatchList,
} from "./matchList.js";
import { expandRouteAlias } from "./routeFeatures.js";
import type { HttpMethod, RouteDef } from "../routes/restmap.js";

export type AccessPolicyConfig = {
  dbInclude: string[];
  dbExclude: string[];
  routeInclude: string[];
  routeExclude: string[];
};

export type CompiledDbPolicy = {
  enabled: boolean;
  include: CompiledMatchList;
  exclude: CompiledMatchList;
};

export type CompiledRoutePolicy = {
  enabled: boolean;
  includeEmpty: boolean;
  excludeEmpty: boolean;
  includeFeatures: Set<string>;
  excludeFeatures: Set<string>;
  /** Uppercase method + restmap path, e.g. `GET /:db/_changes`. */
  includeTemplates: Set<string>;
  excludeTemplates: Set<string>;
  /** Match against `METHOD pathname` (actual request path). */
  includeRegexes: RegExp[];
  excludeRegexes: RegExp[];
};

export type CompiledAccessPolicy = {
  db: CompiledDbPolicy;
  route: CompiledRoutePolicy;
};

export type RouteGate = {
  /**
   * Fast checker for a single restmap route.
   * When the policy can be fully decided from features/templates, this is a
   * constant function (no per-request regex work).
   */
  allowed: (principal: Principal, method: string, pathname: string) => boolean;
};

function templateKey(method: HttpMethod | string, path: string): string {
  return `${String(method).toUpperCase()} ${path}`;
}

/**
 * Parse route policy entries into features, method/path templates, and regexes.
 *
 * Accepted forms:
 * - feature / bundle alias: `session`, `pouch-sync`
 * - method + restmap path: `GET /:db/_changes`
 * - regex over `METHOD pathname`: `/^GET \\/data-[^/]+\\/_changes$/`
 */
export function parseRoutePolicyEntries(entries: string[]): {
  features: Set<string>;
  templates: Set<string>;
  regexes: RegExp[];
} {
  const features = new Set<string>();
  const templates = new Set<string>();
  const regexes: RegExp[] = [];

  for (const raw of entries) {
    const entry = raw.trim();
    if (!entry) continue;

    if (entry.startsWith("/")) {
      const parsed = parsePatternEntry(entry);
      if (!("regex" in parsed)) {
        throw new Error(`route pattern '${entry}' must be a /regex/ literal`);
      }
      regexes.push(parsed.regex);
      continue;
    }

    const aliases = expandRouteAlias(entry);
    if (aliases) {
      for (const feature of aliases) features.add(feature);
      continue;
    }

    // METHOD /path form (path may contain spaces only if quoted — we don't support that).
    const match = /^([A-Za-z]+)\s+(\/\S*)$/.exec(entry);
    if (!match) {
      throw new Error(
        `unknown route feature '${entry}' (use a feature/bundle name, 'METHOD /path', or /regex/)`,
      );
    }
    templates.add(templateKey(match[1]!, match[2]!));
  }

  return { features, templates, regexes };
}

/** Compile validated access-policy config into hot-path matchers. */
export function compileAccessPolicy(config: AccessPolicyConfig): CompiledAccessPolicy {
  const dbInclude = compileMatchList(config.dbInclude);
  const dbExclude = compileMatchList(config.dbExclude);
  const db: CompiledDbPolicy = {
    enabled: !dbInclude.empty || !dbExclude.empty,
    include: dbInclude,
    exclude: dbExclude,
  };

  const includeParsed = parseRoutePolicyEntries(config.routeInclude);
  const excludeParsed = parseRoutePolicyEntries(config.routeExclude);
  const route: CompiledRoutePolicy = {
    enabled:
      config.routeInclude.length > 0 ||
      config.routeExclude.length > 0 ||
      includeParsed.features.size > 0 ||
      excludeParsed.features.size > 0,
    includeEmpty: config.routeInclude.length === 0,
    excludeEmpty: config.routeExclude.length === 0,
    includeFeatures: includeParsed.features,
    excludeFeatures: excludeParsed.features,
    includeTemplates: includeParsed.templates,
    excludeTemplates: excludeParsed.templates,
    includeRegexes: includeParsed.regexes,
    excludeRegexes: excludeParsed.regexes,
  };
  // enabled should be true whenever either list was non-empty in config
  route.enabled = !route.includeEmpty || !route.excludeEmpty;

  return { db, route };
}

/**
 * Database visibility under env policy.
 * Admins always allowed. Missing/disabled policy allows all names.
 */
export function isDbAllowedByPolicy(
  policy: CompiledAccessPolicy,
  db: string,
  principal: Principal,
): boolean {
  if (principal.admin || !policy.db.enabled) return true;
  return allowedByIncludeExclude(policy.db.include, policy.db.exclude, db);
}

function routeExcludedStatic(policy: CompiledRoutePolicy, route: RouteDef): boolean {
  const key = templateKey(route.method, route.path);
  if (policy.excludeTemplates.has(key)) return true;
  for (const feature of route.features ?? []) {
    if (policy.excludeFeatures.has(feature)) return true;
  }
  return false;
}

function routeIncludedStatic(policy: CompiledRoutePolicy, route: RouteDef): boolean {
  if (policy.includeEmpty) return true;
  const key = templateKey(route.method, route.path);
  if (policy.includeTemplates.has(key)) return true;
  for (const feature of route.features ?? []) {
    if (policy.includeFeatures.has(feature)) return true;
  }
  return false;
}

/**
 * Build a per-route gate used by `registerRoutes`.
 * Prefers a constant allow/deny when no request-path regexes apply.
 */
export function compileRouteGate(policy: CompiledAccessPolicy, route: RouteDef): RouteGate {
  if (!policy.route.enabled) {
    return { allowed: () => true };
  }

  const excludedStatic = routeExcludedStatic(policy.route, route);
  const includedStatic = routeIncludedStatic(policy.route, route);
  const needsExcludeRe = policy.route.excludeRegexes.length > 0;
  const needsIncludeRe = !policy.route.includeEmpty && policy.route.includeRegexes.length > 0;

  if (!needsExcludeRe && !needsIncludeRe) {
    const allowed = !excludedStatic && includedStatic;
    return {
      allowed: (principal) => principal.admin || allowed,
    };
  }

  const excludeRegexes = policy.route.excludeRegexes;
  const includeRegexes = policy.route.includeRegexes;
  const includeEmpty = policy.route.includeEmpty;

  return {
    allowed: (principal, method, pathname) => {
      if (principal.admin) return true;
      const probe = `${method.toUpperCase()} ${pathname}`;
      if (excludedStatic) return false;
      for (const re of excludeRegexes) {
        if (re.test(probe)) return false;
      }
      if (includeEmpty || includedStatic) return true;
      for (const re of includeRegexes) {
        if (re.test(probe)) return true;
      }
      return false;
    },
  };
}

/** Validate raw DB pattern entries (throws with entry context). */
export function assertDbPatterns(entries: string[], label: string): void {
  for (const entry of entries) {
    try {
      parsePatternEntry(entry);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(`${label}: ${message}`);
    }
  }
}

/** Validate raw route policy entries (throws on unknown aliases / bad regex). */
export function assertRoutePatterns(entries: string[], label: string): void {
  try {
    parseRoutePolicyEntries(entries);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`${label}: ${message}`);
  }
}
