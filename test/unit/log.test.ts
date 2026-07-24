/**
 * Unit tests for the structured logging helper (`LOG_LEVEL`, levels, redaction).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createLogger,
  getLogLevel,
  isLevelEnabled,
  matchingTokens,
  parseLogLevel,
  setLogLevel,
} from "../../src/util/log.js";

afterEach(() => {
  setLogLevel(null);
  vi.restoreAllMocks();
});

describe("parseLogLevel", () => {
  it("accepts canonical levels and aliases case-insensitively", () => {
    expect(parseLogLevel("verbose")).toBe("verbose");
    expect(parseLogLevel("TRACE")).toBe("verbose");
    expect(parseLogLevel("Debug")).toBe("debug");
    expect(parseLogLevel("info")).toBe("info");
    expect(parseLogLevel("warning")).toBe("warn");
    expect(parseLogLevel("WARN")).toBe("warn");
    expect(parseLogLevel("fatal")).toBe("error");
    expect(parseLogLevel("nope")).toBeUndefined();
    expect(parseLogLevel("")).toBeUndefined();
  });
});

describe("setLogLevel / isLevelEnabled", () => {
  it("filters messages below the configured threshold", () => {
    setLogLevel("warn");
    expect(getLogLevel()).toBe("warn");
    expect(isLevelEnabled("verbose")).toBe(false);
    expect(isLevelEnabled("debug")).toBe(false);
    expect(isLevelEnabled("info")).toBe(false);
    expect(isLevelEnabled("warn")).toBe(true);
    expect(isLevelEnabled("error")).toBe(true);
  });

  it("enables the full ACL decision trail at verbose", () => {
    setLogLevel("verbose");
    expect(isLevelEnabled("verbose")).toBe(true);
    expect(isLevelEnabled("debug")).toBe(true);
    expect(isLevelEnabled("info")).toBe(true);
  });

  it("rejects unknown levels", () => {
    expect(() => setLogLevel("loud")).toThrow(/Invalid log level/);
  });
});

describe("createLogger", () => {
  it("emits JSON lines with level, component, and redacted secrets", () => {
    setLogLevel("info");
    const infoSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const log = createLogger("acl-resolve");
    log.debug("hidden", { docId: "d1" });
    log.info("resolve", {
      docId: "d1",
      authorization: "Bearer secret",
      cookie: "AuthSession=abc",
      password: "x",
      jwtToken: "y",
      secretKey: "z",
      aclTokens: ["u-alice", "r-*"],
      starTokens: ["u-bob"],
    });
    log.warn("denied", { docId: "d1" });
    log.error("boom", { err: "nope" });

    expect(infoSpy).toHaveBeenCalledTimes(1);
    const line = JSON.parse(String(infoSpy.mock.calls[0]?.[0]));
    expect(line.level).toBe("info");
    expect(line.component).toBe("acl-resolve");
    expect(line.msg).toBe("resolve");
    expect(line.docId).toBe("d1");
    expect(line.authorization).toBe("[redacted]");
    expect(line.cookie).toBe("[redacted]");
    expect(line.password).toBe("[redacted]");
    expect(line.jwtToken).toBe("[redacted]");
    expect(line.secretKey).toBe("[redacted]");
    expect(line.aclTokens).toEqual(["u-alice", "r-*"]);
    expect(line.starTokens).toEqual(["u-bob"]);
    expect(typeof line.ts).toBe("string");

    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(errorSpy).toHaveBeenCalledTimes(1);
  });

  it("supports verbose and child loggers with bound fields", () => {
    setLogLevel("verbose");
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    const log = createLogger("actors").child({ requestId: "req-1" });
    log.verbose("doc", { decision: "allow", docId: "note-1" });

    expect(spy).toHaveBeenCalledTimes(1);
    const line = JSON.parse(String(spy.mock.calls[0]?.[0]));
    expect(line.level).toBe("verbose");
    expect(line.component).toBe("actors");
    expect(line.requestId).toBe("req-1");
    expect(line.decision).toBe("allow");
    expect(line.docId).toBe("note-1");
  });
});

describe("matchingTokens", () => {
  it("intersects principal tokens with grant records and sets", () => {
    expect(matchingTokens(["u-alice", "r-readers", "r-*"], { "u-alice": 1, "u-bob": 1 })).toEqual([
      "u-alice",
    ]);
    expect(matchingTokens(["u-alice", "r-writers"], new Set(["r-writers", "r-*"]))).toEqual([
      "r-writers",
    ]);
    expect(matchingTokens(["a", "b", "c"], ["b", "c", "d"], 1)).toEqual(["b"]);
  });
});
