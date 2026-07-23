/**
 * Request body size limiting helpers.
 *
 * Used when Content-Length is missing or unreliable: stream through a
 * TransformStream that errors once more than `maxBytes` are seen, and when
 * reading JSON for ACL write filtering (`_bulk_docs`, `_revs_diff`, …).
 */

/**
 * Pass-through TransformStream that errors once more than `maxBytes` are seen.
 */
export function limitBytes(
  upstream: ReadableStream<Uint8Array>,
  maxBytes: number,
): ReadableStream<Uint8Array> {
  let count = 0;
  return upstream.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        count += chunk.byteLength;
        if (count > maxBytes) {
          controller.error(new BodyTooLargeError(maxBytes));
          return;
        }
        controller.enqueue(chunk);
      },
    }),
  );
}

/** Thrown when a request body exceeds the configured ceiling. */
export class BodyTooLargeError extends Error {
  constructor(public readonly maxBytes: number) {
    super(`Request body exceeds ${maxBytes} bytes`);
    this.name = "BodyTooLargeError";
  }
}

/** Read a request body into a string, enforcing a byte ceiling. */
export async function readTextLimited(req: Request, maxBytes: number): Promise<string> {
  const contentLength = req.headers.get("content-length");
  if (contentLength) {
    const length = Number(contentLength);
    if (Number.isFinite(length) && length > maxBytes) {
      throw new BodyTooLargeError(maxBytes);
    }
  }
  if (!req.body) return "";
  const limited = limitBytes(req.body, maxBytes);
  return new Response(limited).text();
}

/** `readTextLimited` + `JSON.parse` (throws on invalid JSON). */
export async function readJsonLimited<T>(req: Request, maxBytes: number): Promise<T> {
  const text = await readTextLimited(req, maxBytes);
  return JSON.parse(text) as T;
}

/** Read an upstream Response body into a string, enforcing a byte ceiling. */
export async function readResponseTextLimited(res: Response, maxBytes: number): Promise<string> {
  const contentLength = res.headers.get("content-length");
  if (contentLength) {
    const length = Number(contentLength);
    if (Number.isFinite(length) && length > maxBytes) {
      throw new BodyTooLargeError(maxBytes);
    }
  }
  if (!res.body) return "";
  return new Response(limitBytes(res.body, maxBytes)).text();
}
