/**
 * Transparent reverse-proxy helpers to upstream CouchDB.
 *
 * Preserves client `Authorization` (incl. Bearer JWT) and `Cookie` so Couch
 * applies the same auth handlers couch-auth-proxy resolved against. Strips hop-by-hop
 * and spoofable proxy-auth headers. Used both for full passthrough (`forwardToCouch`)
 * and for fetch-then-filter actors (`fetchFromCouch` + `toClientResponse`).
 */
import type { Context } from "hono";
import type { AppConfig } from "../config.js";
import { BodyTooLargeError, limitBytes } from "../util/limitStream.js";

/** Headers that must not be forwarded (hop-by-hop / framing). */
const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailers",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
]);

/** Spoofable Couch proxy-auth headers — stripped from clients by default. */
const STRIP_FROM_CLIENT = new Set([
  "x-auth-couchdb-username",
  "x-auth-couchdb-roles",
  "x-auth-couchdb-token",
  "forwarded",
  "x-forwarded-host",
  "x-forwarded-port",
  "x-forwarded-proto",
]);

export type ForwardOptions = {
  /** Override method (used to obtain a filterable representation for HEAD). */
  method?: string;
  /** Override path (default: incoming path) */
  path?: string;
  /** Optional query string including `?` */
  query?: string;
  /** Optional body override after ACL write filtering */
  body?: ArrayBuffer | Blob | string | ReadableStream<Uint8Array> | null;
  /** Extra request headers to set/override */
  headers?: Record<string, string>;
  /** Incoming headers that must not reach Couch for this request. */
  stripRequestHeaders?: string[];
  /** Upstream response headers that must not reach the client. */
  stripResponseHeaders?: string[];
  /** When true, do not strip content-encoding (raw pipe of compressed bodies) */
  keepEncoding?: boolean;
};

/** An untrusted request path attempted to resolve outside the Couch origin. */
export class UnsafeUpstreamUrlError extends Error {
  constructor() {
    super("Upstream URL must stay on the configured CouchDB origin");
    this.name = "UnsafeUpstreamUrlError";
  }
}

/**
 * Proxy the request to Couch and return a client-facing Response.
 * Maps `BodyTooLargeError` to Couch-shaped 413.
 */
export async function forwardToCouch(
  c: Context,
  config: AppConfig,
  options?: ForwardOptions,
): Promise<Response> {
  try {
    const upstream = await fetchFromCouch(c, config, options);
    return toClientResponse(upstream, {
      keepEncoding: options?.keepEncoding,
      stripHeaders: options?.stripResponseHeaders,
      rewriteLocation: {
        fromOrigin: new URL(config.couch.url).origin,
      },
    });
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return couchError("bad_request", "Request body too large", 413);
    }
    if (err instanceof UnsafeUpstreamUrlError) {
      return couchError("bad_request", "Invalid request path", 400);
    }
    throw err;
  }
}

/**
 * Fetch upstream without wrapping as a client Response (for filtering).
 * Applies body size limits to streamed request bodies.
 */
export async function fetchFromCouch(
  c: Context,
  config: AppConfig,
  options?: ForwardOptions,
): Promise<Response> {
  const incoming = c.req.raw;
  const path = options?.path ?? c.req.path;
  const query = options?.query ?? (c.req.url.includes("?") ? `?${c.req.url.split("?")[1]}` : "");
  const couchBase = new URL(config.couch.url);
  const url = new URL(path + query, couchBase);
  // WHATWG URL resolution treats `//host/path` as protocol-relative. Never let
  // an admin catch-all request forward credentials to a caller-selected host.
  if (url.origin !== couchBase.origin) {
    throw new UnsafeUpstreamUrlError();
  }

  const headers = new Headers();
  const stripRequestHeaders = new Set(
    (options?.stripRequestHeaders ?? []).map((header) => header.toLowerCase()),
  );
  incoming.headers.forEach((value, key) => {
    const lowerKey = key.toLowerCase();
    if (HOP_BY_HOP.has(lowerKey)) return;
    if (STRIP_FROM_CLIENT.has(lowerKey)) return;
    if (stripRequestHeaders.has(lowerKey)) return;
    headers.set(key, value);
  });
  if (options?.headers) {
    for (const [key, value] of Object.entries(options.headers)) headers.set(key, value);
  }

  const method = options?.method ?? incoming.method;
  const hasBody = !["GET", "HEAD"].includes(method);
  const bodyOverridden = options?.body !== undefined;
  let body: ArrayBuffer | Blob | string | ReadableStream<Uint8Array> | null | undefined = hasBody
    ? bodyOverridden
      ? options.body
      : incoming.body
    : undefined;

  // When ACL rewriting replaces the body, drop the client's Content-Length so
  // fetch recalculates — stale lengths truncate replication bulk payloads.
  if (bodyOverridden) {
    headers.delete("content-length");
  }

  // Bound streamed request bodies even when Content-Length is absent.
  if (body instanceof ReadableStream) {
    body = limitBytes(body, config.server.maxBodyBytes);
  }

  const init: RequestInit & { duplex?: "half" } = {
    method,
    headers,
    body,
    redirect: "manual",
  };
  if (body) init.duplex = "half";

  const response = await fetch(url, init);
  const location = response.headers.get("location");
  if (!location) return response;

  // Couch commonly emits absolute redirects using its private upstream
  // origin. Exposing that URL can let a client leave the ACL proxy when Couch
  // is also reachable on an internal or development network. Preserve
  // same-origin redirects as origin-relative client locations.
  try {
    const target = new URL(location, url);
    if (target.origin !== couchBase.origin) return response;
    const headers = new Headers(response.headers);
    headers.set("Location", `${target.pathname}${target.search}${target.hash}`);
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  } catch {
    return response;
  }
}

/**
 * Convert an upstream Response into a client Response, stripping hop-by-hop
 * headers and (by default) content-encoding so Node can re-encode if needed.
 */
export function toClientResponse(
  upstream: Response,
  options?: {
    keepEncoding?: boolean;
    body?: ReadableStream<Uint8Array> | string | null;
    stripHeaders?: string[];
    rewriteLocation?: { fromOrigin: string };
  },
): Response {
  const responseHeaders = new Headers();
  const stripHeaders = new Set((options?.stripHeaders ?? []).map((header) => header.toLowerCase()));
  const decoded = !options?.keepEncoding && upstream.headers.has("content-encoding");
  upstream.headers.forEach((value, key) => {
    const lowerKey = key.toLowerCase();
    if (HOP_BY_HOP.has(lowerKey)) return;
    if (stripHeaders.has(lowerKey)) return;
    if (decoded && (lowerKey === "content-encoding" || lowerKey === "content-length")) return;
    if (lowerKey === "content-length" && options?.body !== undefined) return;
    responseHeaders.set(key, value);
  });

  const location = responseHeaders.get("location");
  if (location && options?.rewriteLocation && /^[a-z][a-z\d+.-]*:\/\//i.test(location)) {
    try {
      const parsed = new URL(location);
      if (parsed.origin === options.rewriteLocation.fromOrigin) {
        // Resolve against the caller's public origin (including TLS
        // termination) without trusting forwarded host/proto headers.
        responseHeaders.set("location", `${parsed.pathname}${parsed.search}${parsed.hash}`);
      }
    } catch {
      // Preserve malformed upstream values; clients can handle them as Couch sent them.
    }
  }

  const body = options?.body !== undefined ? options.body : upstream.body;
  return new Response(body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: responseHeaders,
  });
}

/** JSON response with Couch-friendly Content-Type. */
export function jsonResponse(
  data: unknown,
  status = 200,
  extraHeaders?: Record<string, string>,
): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...extraHeaders,
    },
  });
}

/** Couch-shaped `{ error, reason }` error response. */
export function couchError(error: string, reason: string, status: number): Response {
  return jsonResponse({ error, reason }, status);
}
