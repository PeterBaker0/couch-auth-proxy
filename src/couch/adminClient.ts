/**
 * Privileged CouchDB HTTP client for couch-auth-proxy internals.
 *
 * Used for ACL view reads, `_design/acl` install/migrate, continuous `_changes`
 * follow, and readiness probes. Client-facing traffic must use `proxy/forward`
 * with the caller's credentials — never this client.
 *
 * Admin credentials from `adminUrl` are sent only as an Authorization header
 * so they never appear in structured log URLs.
 */
import type { AppConfig } from "../config.js";

/**
 * CouchDB client using admin credentials (ACL views, ddoc install, _changes follow).
 */
export class AdminClient {
  /** Origin only (`protocol://host[:port]`), no userinfo. */
  private readonly base: string;
  /** Precomputed `Basic …` header, or null when adminUrl has no userinfo. */
  private readonly authHeader: string | null;

  constructor(config: AppConfig) {
    const url = new URL(config.couch.adminUrl);
    this.base = `${url.protocol}//${url.host}`;
    if (url.username) {
      const token = Buffer.from(
        `${decodeURIComponent(url.username)}:${decodeURIComponent(url.password)}`,
      ).toString("base64");
      this.authHeader = `Basic ${token}`;
    } else {
      this.authHeader = null;
    }
  }

  /** Merge Accept + admin Authorization with optional extra headers. */
  headers(extra?: Headers): Headers {
    const h = new Headers({ Accept: "application/json" });
    if (extra) {
      extra.forEach((v, k) => h.set(k, v));
    }
    if (this.authHeader) h.set("Authorization", this.authHeader);
    return h;
  }

  /** Absolute URL under the Couch origin, with optional query params. */
  url(path: string, query?: Record<string, string>): URL {
    const u = new URL(path.startsWith("/") ? path : `/${path}`, this.base);
    if (query) {
      for (const [k, v] of Object.entries(query)) u.searchParams.set(k, v);
    }
    return u;
  }

  /** Low-level fetch with admin auth applied. */
  async fetch(
    path: string,
    init?: RequestInit & { query?: Record<string, string> },
  ): Promise<Response> {
    const url = this.url(path, init?.query);
    const headers = this.headers(new Headers(init?.headers));
    const { query: _query, ...rest } = init ?? {};
    return fetch(url, { ...rest, headers });
  }

  /**
   * JSON helper: on success returns parsed body; on failure returns status + raw text
   * (callers decide how to surface errors without throwing on every 404).
   */
  async json<T>(
    path: string,
    init?: RequestInit & { query?: Record<string, string> },
  ): Promise<{ ok: true; status: number; body: T } | { ok: false; status: number; text: string }> {
    const res = await this.fetch(path, init);
    if (!res.ok) {
      return { ok: false, status: res.status, text: await res.text() };
    }
    return { ok: true, status: res.status, body: (await res.json()) as T };
  }

  /** Probe Couch reachability for readiness (`GET /_up`). */
  async ping(): Promise<boolean> {
    try {
      const res = await this.fetch("/_up");
      return res.ok;
    } catch {
      return false;
    }
  }
}
