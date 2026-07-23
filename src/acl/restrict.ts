/**
 * Compile and evaluate `_design/acl.restrict` path/method rules.
 *
 * `restrict.*` controls who may see the DB at all (and hides it from `_all_dbs`).
 * Per-method maps match the path+query after `/{db}` with `*` / `+` wildcards
 * and require the principal to hold at least one listed token.
 */
import type { Principal } from "../auth/types.js";
import type { RestrictMap } from "./types.js";

/** One compiled path/query rule and the tokens that may use it. */
export type CompiledRestrictRule = {
  pattern: RegExp;
  tokens: Set<string>;
};

/** Precompiled restrict map for fast per-request checks. */
export type CompiledRestrict = {
  /** `restrict.*` — who may see/use the DB at all */
  star?: Set<string>;
  /** HTTP method (uppercase) → path/query rules */
  methods: Map<string, CompiledRestrictRule[]>;
};

/**
 * Convert a restrict path fragment with `*` / `+` wildcards into a RegExp.
 * `*` = one or more chars; `+` = one or more chars other than `/`.
 *
 * Placeholders are swapped to private-use code points before escaping regex
 * metacharacters, then expanded to the real wildcard patterns.
 */
export function restrictPatternToRegExp(fragment: string): RegExp {
  const escaped = fragment
    .replace(/\*/g, "\u1D25")
    .replace(/\+/g, "\u1D23")
    .replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    .replace(/\u1D25/g, ".+")
    .replace(/\u1D23/g, "[^\\/]+");
  return new RegExp(escaped);
}

/**
 * Normalize a token list: bare names become `u-<name>`; `u-` / `r-` kept as-is.
 */
export function unwindTokens(list: string[] | undefined): Set<string> {
  const out = new Set<string>();
  if (!list?.length) return out;
  for (const raw of list) {
    if (typeof raw !== "string" || !raw) continue;
    if (/^[ru]-/.test(raw)) out.add(raw);
    else out.add(`u-${raw}`);
  }
  return out;
}

/** Compile a raw `restrict` object from `_design/acl` into regex/token sets. */
export function compileRestrict(restrict?: RestrictMap): CompiledRestrict {
  const methods = new Map<string, CompiledRestrictRule[]>();
  if (!restrict || typeof restrict !== "object") {
    return { methods };
  }

  let star: Set<string> | undefined;
  const starRaw = restrict["*"];
  if (Array.isArray(starRaw)) {
    star = unwindTokens(starRaw);
  }

  for (const [method, rules] of Object.entries(restrict)) {
    if (method === "*") continue;
    if (!rules || typeof rules !== "object" || Array.isArray(rules)) continue;
    const compiledRules: CompiledRestrictRule[] = [];
    for (const [fragment, tokens] of Object.entries(rules)) {
      if (!Array.isArray(tokens)) continue;
      try {
        compiledRules.push({
          pattern: restrictPatternToRegExp(fragment),
          tokens: unwindTokens(tokens),
        });
      } catch {
        // Skip invalid patterns rather than failing the whole DB load.
      }
    }
    if (compiledRules.length) methods.set(method.toUpperCase(), compiledRules);
  }

  return { star, methods };
}

/**
 * Database visibility / access level for `_all_dbs` and the `db` actor.
 *
 * - `0` = hidden (restricted and principal not listed)
 * - `1` = allowed under restrict (or ACL DB with no `restrict.*`)
 * - `2` = fully open (admin, or `noacl` without `restrict.*`)
 */
export function dbAccessLevel(
  principal: Principal,
  compiled: CompiledRestrict | undefined,
  noacl: boolean,
): 0 | 1 | 2 {
  if (principal.admin) return 2;
  if (!compiled?.star) {
    return noacl ? 2 : 1;
  }
  for (const token of principal.aclTokens) {
    if (compiled.star.has(token)) return 1;
  }
  return 0;
}

/**
 * Check method/path restrict rules.
 * `urlAfterDb` is the path+query after `/{db}`, e.g. `/_all_docs?limit=10`.
 *
 * If no rule matches the URL, the method is allowed. If one or more rules match,
 * the principal must hold a token from the union of those rules' token sets.
 */
export function methodAllowed(
  principal: Principal,
  compiled: CompiledRestrict | undefined,
  method: string,
  urlAfterDb: string,
): boolean {
  if (principal.admin) return true;
  if (!compiled) return true;
  const rules = compiled.methods.get(method.toUpperCase());
  if (!rules?.length) return true;

  let matchedTokens: Set<string> | null = null;
  for (const rule of rules) {
    if (rule.pattern.test(urlAfterDb)) {
      if (!matchedTokens) matchedTokens = new Set();
      for (const token of rule.tokens) matchedTokens.add(token);
    }
  }
  if (!matchedTokens) return true;
  for (const token of principal.aclTokens) {
    if (matchedTokens.has(token)) return true;
  }
  return false;
}
