/**
 * Unit tests for trusted-proxy client IP resolution (rate limiting).
 */
import { describe, expect, it } from "vitest";
import { resolveClientIp } from "../../src/util/clientIp.js";

describe("resolveClientIp", () => {
  it("ignores forwarding headers when trustProxyHops is 0", () => {
    const h = new Headers({
      "x-forwarded-for": "1.2.3.4",
      "x-real-ip": "5.6.7.8",
    });
    expect(resolveClientIp(h, 0)).toBe("direct");
  });

  it("prefers X-Real-IP when trusting proxies", () => {
    const h = new Headers({
      "x-forwarded-for": "1.2.3.4, 9.9.9.9",
      "x-real-ip": "5.6.7.8",
    });
    expect(resolveClientIp(h, 1)).toBe("5.6.7.8");
  });

  it("uses XFF hop based on trustProxyHops", () => {
    const h = new Headers({
      "x-forwarded-for": "client, mid, edge",
    });
    expect(resolveClientIp(h, 1)).toBe("edge");
    expect(resolveClientIp(h, 2)).toBe("mid");
    expect(resolveClientIp(h, 3)).toBe("client");
  });
});
