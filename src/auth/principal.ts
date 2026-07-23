/**
 * Build a `Principal` from Couch `/_session` (or equivalent) session info.
 *
 * Token expansion rules:
 * - Authenticated users get `r-*` ("any DB user"), bare name, and `u-<name>`
 * - Each role is added both raw and as `r-<role>` when not already prefixed
 * - Anonymous principals get neither `r-*` nor username tokens
 */
import type { Principal, SessionInfo, UserCtx } from "./types.js";

/** Expand `userCtx` into ACL tokens and admin flag. */
export function buildPrincipal(session: SessionInfo): Principal {
  const userCtx: UserCtx = session.userCtx ?? { name: null, roles: [] };
  const roles = Array.isArray(userCtx.roles) ? userCtx.roles : [];
  const admin = roles.includes("_admin");
  const name = userCtx.name ?? null;

  // r-* means "any authenticated DB user" — do not grant to anonymous.
  const aclTokens = new Set<string>();
  if (name) {
    aclTokens.add("r-*");
    aclTokens.add(name);
    aclTokens.add(name.startsWith("u-") ? name : `u-${name}`);
  }
  for (const role of roles) {
    aclTokens.add(role);
    aclTokens.add(role.startsWith("r-") ? role : `r-${role}`);
  }

  const authenticatedBy = (session.info?.authenticated as Principal["authenticatedBy"]) ?? null;

  return {
    name,
    roles,
    admin,
    aclTokens: [...aclTokens],
    authenticatedBy,
    raw: session,
  };
}

/** Unauthenticated principal (no name, no roles, no `r-*`). */
export function anonymousPrincipal(): Principal {
  return buildPrincipal({
    ok: true,
    userCtx: { name: null, roles: [] },
    info: { authenticated: "default", authentication_handlers: [] },
  });
}
