// The server's configuration checks. PUBLIC_ORIGIN is the trust anchor of everything web: the phone
// app's origin, the passkeys' relying party and the device-link page. It is fixed by the operator,
// never derived from a request.
import type { Env } from "./env";

const LOCAL = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * PUBLIC_ORIGIN as a URL when it is exactly an origin: https, no path, query, fragment or
 * credentials (http only for localhost with MIBLO_RELAY_DEV=1). Null otherwise.
 */
export function publicOrigin(env: { PUBLIC_ORIGIN?: string; MIBLO_RELAY_DEV?: string }): URL | null {
  const raw = env.PUBLIC_ORIGIN ?? "";
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (u.username || u.password || u.search || u.hash || (u.pathname !== "/" && u.pathname !== "")) return null;
  if (raw.replace(/\/$/, "") !== u.origin) return null;
  if (u.protocol === "https:") return u;
  if (u.protocol === "http:" && env.MIBLO_RELAY_DEV === "1" && LOCAL.has(u.hostname)) return u;
  return null;
}

/** What is missing or wrong in the configuration (empty: ready). Names only, never values. */
export function configProblems(env: Partial<Env>): string[] {
  const out: string[] = [];
  if (!publicOrigin(env)) out.push("PUBLIC_ORIGIN must be your server's https origin, like https://relay.example.com");
  if (!env.SESSION_SECRET || env.SESSION_SECRET.length < 32) out.push("SESSION_SECRET must be at least 32 characters");
  if (!env.MFA_KEY || !/^[A-Za-z0-9_-]{43}$/.test(env.MFA_KEY.replace(/=+$/, ""))) out.push("MFA_KEY must be 32 random bytes, base64url");
  if (!env.SERVER_IDENTITY_KEY) out.push("SERVER_IDENTITY_KEY is missing");
  if (env.TRUSTED_PROXY && !/^[0-9A-Fa-f:.\/,\s]+$/.test(env.TRUSTED_PROXY)) out.push("TRUSTED_PROXY must list your proxy's addresses or CIDRs (like 172.30.247.0/24)");
  if (env.TRUSTED_PROXY === "1") out.push("TRUSTED_PROXY=1 is no longer accepted: list your proxy's addresses or CIDRs (like 172.30.247.0/24)");
  if (!env.RELAY_VAPID_PUBLIC_KEY || !env.RELAY_VAPID_PRIVATE_KEY) out.push("RELAY_VAPID_PUBLIC_KEY / RELAY_VAPID_PRIVATE_KEY are missing (push alerts stay off)");
  return out;
}

/** Problems that stop the server (push keys are optional: without them there are no alerts). */
export function fatalProblems(env: Partial<Env>): string[] {
  return configProblems(env).filter((p) => !p.startsWith("RELAY_VAPID"));
}
