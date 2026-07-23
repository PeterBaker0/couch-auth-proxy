/**
 * Resolve client IP for rate limiting.
 *
 * Spoofing model:
 * - `trustProxyHops === 0`: ignore forwarding headers; bucket everyone as `"direct"`.
 * - `trustProxyHops >= 1`: prefer `X-Real-IP`, else take the X-Forwarded-For hop
 *   at `parts[parts.length - hops]` (address seen by the outermost trusted proxy).
 *
 * Only enable hops when couch-auth-proxy sits behind a known reverse proxy that
 * overwrites/appends these headers correctly.
 */

/**
 * Resolve the client IP string used as a rate-limit bucket key.
 */
export function resolveClientIp(headers: Headers, trustProxyHops: number): string {
  if (trustProxyHops <= 0) return "direct";

  const realIp = headers.get("x-real-ip")?.trim();
  if (realIp && !realIp.includes(",")) return realIp;

  const xff = headers.get("x-forwarded-for");
  if (!xff) return "direct";

  const parts = xff
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (!parts.length) return "direct";

  const index = parts.length - trustProxyHops;
  if (index < 0) return parts[0]!;
  return parts[index]!;
}
