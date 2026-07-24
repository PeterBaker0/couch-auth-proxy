/**
 * Helpers for scraping `/_couch-auth-proxy/profile` from the perf harness.
 */
import { PROXY } from "../integration/helpers.js";
import { formatProfileSnapshot, type ProfileSnapshot } from "../../src/util/profile.js";

export type { ProfileSnapshot };

/** True when the proxy was started with PROFILE=true. */
export async function profileEndpointAvailable(baseUrl = PROXY): Promise<boolean> {
  try {
    const res = await fetch(`${baseUrl}/_couch-auth-proxy/profile`);
    return res.ok;
  } catch {
    return false;
  }
}

export async function resetServerProfile(baseUrl = PROXY): Promise<boolean> {
  try {
    const res = await fetch(`${baseUrl}/_couch-auth-proxy/profile/reset`, { method: "POST" });
    return res.ok;
  } catch {
    return false;
  }
}

export async function fetchServerProfile(baseUrl = PROXY): Promise<ProfileSnapshot | null> {
  try {
    const res = await fetch(`${baseUrl}/_couch-auth-proxy/profile`);
    if (!res.ok) return null;
    return (await res.json()) as ProfileSnapshot;
  } catch {
    return null;
  }
}

/** Reset → run work → scrape snapshot; always runs `work`, returns null if profiling off. */
export async function measureServerProfile(
  label: string,
  work: () => Promise<void>,
  baseUrl = PROXY,
): Promise<ProfileSnapshot | null> {
  const enabled = await profileEndpointAvailable(baseUrl);
  if (enabled) await resetServerProfile(baseUrl);
  await work();
  if (!enabled) return null;
  const snap = await fetchServerProfile(baseUrl);
  if (snap) {
    console.log(`\n${formatProfileSnapshot(snap, label)}\n`);
  }
  return snap;
}
