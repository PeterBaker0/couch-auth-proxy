/**
 * Unit tests for opt-in PROFILE phase timers + scrape endpoint.
 */
import { describe, expect, it, vi } from "vitest";
import { createApp, createServices } from "../../src/app.js";
import { loadConfig } from "../../src/config.js";
import { anonymousPrincipal } from "../../src/auth/principal.js";
import {
  ProfileAggregator,
  addProfileMs,
  createRequestProfile,
  currentProfile,
  formatProfileSnapshot,
  profileAsync,
  profileSync,
  runWithProfile,
} from "../../src/util/profile.js";

describe("profile util", () => {
  it("is a no-op outside runWithProfile", async () => {
    expect(currentProfile()).toBeUndefined();
    addProfileMs("auth", 5);
    expect(await profileAsync("upstream", async () => 42)).toBe(42);
    expect(profileSync("filter", () => "ok")).toBe("ok");
  });

  it("accumulates phase ms inside runWithProfile", async () => {
    const profile = createRequestProfile();
    await runWithProfile(profile, async () => {
      addProfileMs("auth", 1.5);
      await profileAsync("upstream", async () => {
        await new Promise((r) => setTimeout(r, 5));
        return true;
      });
      profileSync("filter", () => {
        // busy-ish enough to register
        let x = 0;
        for (let i = 0; i < 10_000; i++) x += i;
        return x;
      });
    });
    expect(profile.phases.auth).toBeGreaterThanOrEqual(1.5);
    expect(profile.counts.auth).toBe(1);
    expect(profile.phases.upstream).toBeGreaterThan(0);
    expect(profile.phases.filter).toBeGreaterThan(0);
  });

  it("coalesces concurrent nested spans of the same phase", async () => {
    const profile = createRequestProfile();
    await runWithProfile(profile, async () => {
      await Promise.all([
        profileAsync("aclMiss", async () => {
          await new Promise((r) => setTimeout(r, 20));
        }),
        profileAsync("aclMiss", async () => {
          await new Promise((r) => setTimeout(r, 20));
        }),
      ]);
    });
    // Two parallel 20ms spans should attribute ~20ms wall, not ~40ms.
    expect(profile.counts.aclMiss).toBe(2);
    expect(profile.phases.aclMiss).toBeGreaterThan(15);
    expect(profile.phases.aclMiss).toBeLessThan(35);
  });

  it("aggregator snapshot reports per-request means", () => {
    const agg = new ProfileAggregator();
    const a = createRequestProfile();
    a.phases.auth = 10;
    a.counts.auth = 1;
    a.phases.upstream = 30;
    a.counts.upstream = 1;
    agg.record(a, 50);
    const b = createRequestProfile();
    b.phases.auth = 20;
    b.counts.auth = 1;
    agg.record(b, 40);
    const snap = agg.snapshot();
    expect(snap.requests).toBe(2);
    expect(snap.meanDurationMs).toBe(45);
    expect(snap.phases.auth.perRequestMeanMs).toBe(15);
    expect(snap.phases.upstream.perRequestMeanMs).toBe(15);
    expect(formatProfileSnapshot(snap)).toContain("auth");
    agg.reset();
    expect(agg.snapshot().requests).toBe(0);
  });
});

describe("profile probes", () => {
  it("returns 404 when PROFILE is off", async () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      RATE_LIMIT_ENABLED: "false",
    });
    expect(config.server.profile).toBe(false);
    const services = createServices(config);
    services.sessions.resolve = async () => anonymousPrincipal();
    const app = createApp(services);

    const get = await app.request("http://localhost/_couch-auth-proxy/profile");
    expect(get.status).toBe(404);
    const reset = await app.request("http://localhost/_couch-auth-proxy/profile/reset", {
      method: "POST",
    });
    expect(reset.status).toBe(404);
  });

  it("exposes snapshot + reset when PROFILE is on", async () => {
    const config = loadConfig({
      COUCH_URL: "http://127.0.0.1:5984",
      RATE_LIMIT_ENABLED: "false",
      PROFILE: "true",
    });
    expect(config.server.profile).toBe(true);
    const services = createServices(config);
    expect(services.profileAggregator).toBeTruthy();
    services.sessions.resolve = async () => anonymousPrincipal();
    // Avoid ready-path Couch calls; hit a simple DB-less route that still
    // exercises auth profiling via withPrincipal.
    services.aclCache.adminClient.ping = vi.fn(async () => true);
    const app = createApp(services);

    const health = await app.request("http://localhost/_couch-auth-proxy/health");
    expect(health.status).toBe(200);

    // Probe traffic is excluded from the aggregator.
    let snap = await (await app.request("http://localhost/_couch-auth-proxy/profile")).json();
    expect(snap.enabled).toBe(true);
    expect(snap.requests).toBe(0);

    // Non-probe request should be recorded (404 catch-all still runs principal).
    const miss = await app.request("http://localhost/no-such-db-for-profile");
    expect([403, 404, 503]).toContain(miss.status);

    snap = await (await app.request("http://localhost/_couch-auth-proxy/profile")).json();
    expect(snap.requests).toBeGreaterThanOrEqual(1);
    expect(snap.phases.auth.perRequestMeanMs).toBeGreaterThanOrEqual(0);

    const reset = await app.request("http://localhost/_couch-auth-proxy/profile/reset", {
      method: "POST",
    });
    expect(reset.status).toBe(200);
    expect(await reset.json()).toEqual({ ok: true });
    snap = await (await app.request("http://localhost/_couch-auth-proxy/profile")).json();
    expect(snap.requests).toBe(0);
  });
});
