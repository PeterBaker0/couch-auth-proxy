/**
 * Compile include/exclude pattern lists from env CSV entries.
 *
 * Each entry is either:
 * - an exact string match, or
 * - a JavaScript regex literal `/pattern/flags` (compiled once at startup).
 *
 * Empty lists are inert (opt-in). Matching is intentionally allocation-light
 * for the hot path: exact hits use a Set; regexes are precompiled.
 */

export type CompiledMatchList = {
  /** True when the configured list had no entries. */
  empty: boolean;
  exact: Set<string>;
  regexes: RegExp[];
};

/**
 * Parse a single pattern entry.
 * `/foo/i` → RegExp; anything else → exact string (including bare `foo`).
 */
export function parsePatternEntry(entry: string): { exact: string } | { regex: RegExp } {
  const trimmed = entry.trim();
  if (!trimmed) {
    throw Object.assign(new Error("empty pattern entry"), { entry });
  }
  if (!trimmed.startsWith("/")) {
    return { exact: trimmed };
  }

  // Closing delimiter is the last `/` so bodies may contain `/` (e.g. `[^/]+`).
  const closing = trimmed.lastIndexOf("/");
  if (closing <= 0) {
    throw Object.assign(new Error("unterminated regex pattern (missing closing /)"), {
      entry: trimmed,
    });
  }
  const body = trimmed.slice(1, closing);
  const flags = trimmed.slice(closing + 1);
  if (flags && !/^[gimsuy]*$/.test(flags)) {
    throw Object.assign(new Error(`invalid regex flags '${flags}'`), {
      entry: trimmed,
    });
  }
  try {
    return { regex: new RegExp(body, flags) };
  } catch (err) {
    throw Object.assign(new Error(`invalid regex: ${err instanceof Error ? err.message : err}`), {
      entry: trimmed,
    });
  }
}

/** Compile a list of raw pattern strings into exact + regex matchers. */
export function compileMatchList(entries: string[] | undefined): CompiledMatchList {
  const exact = new Set<string>();
  const regexes: RegExp[] = [];
  if (!entries?.length) {
    return { empty: true, exact, regexes };
  }
  for (const entry of entries) {
    const parsed = parsePatternEntry(entry);
    if ("exact" in parsed) exact.add(parsed.exact);
    else regexes.push(parsed.regex);
  }
  return { empty: exact.size === 0 && regexes.length === 0, exact, regexes };
}

/** True when `value` matches any exact entry or precompiled regex. */
export function matchListHits(list: CompiledMatchList, value: string): boolean {
  if (list.empty) return false;
  if (list.exact.has(value)) return true;
  for (const re of list.regexes) {
    if (re.test(value)) return true;
  }
  return false;
}

/**
 * Standard include/exclude evaluation (exclude wins).
 *
 * - exclude hit → deny
 * - include empty → allow (opt-in off)
 * - include non-empty → allow only on include hit
 */
export function allowedByIncludeExclude(
  include: CompiledMatchList,
  exclude: CompiledMatchList,
  value: string,
): boolean {
  if (matchListHits(exclude, value)) return false;
  if (include.empty) return true;
  return matchListHits(include, value);
}
