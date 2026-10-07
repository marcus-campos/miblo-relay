// HTTP entry of the phone relay, called by the server (server/core/app.ts) before anything else:
//   GET    /api/relay/vapid           -> {"publicKey": "<VAPID public key>"}
//   GET    /api/relay/<room>?role=…   -> WebSocket upgrade, handed to the room's Durable Object
//                                        (the writer adds X-Read-Hash: base64url(SHA-256(readToken)))
//   DELETE /api/relay/<room>          -> wipes the room (Authorization: Bearer <writeToken>)
import { bearerToken, isRole, isRoom } from "./protocol";
import { clientNetwork, isIpv6, limited } from "../http";
import type { RelayEnv } from "./room";
import type { RoomNamespace } from "../env";

export const RELAY_PREFIX = "/api/relay/";

export type RelayRouterEnv = RelayEnv & {
  RELAY: RoomNamespace;
  /** Upgrades and deletes per minute and client network (default 30; the test suite raises it). */
  RELAY_RATE_LIMIT?: string;
  /** The key of the daily network hash (clientKey); optional. */
  RELAY_IP_KEY?: string;
};

/**
 * The client's network (clientNetwork: an IPv6 /64) as the room may count it: HMAC-SHA256 over a
 * 30-day period and it, keyed with RELAY_IP_KEY (or, without it, a key derived from the VAPID private
 * key), 22 characters. It changes every period and cannot be turned back into an IP without the key.
 */
export async function clientKey(env: RelayRouterEnv, ip: string, now: number): Promise<string> {
  const enc = new TextEncoder();
  const secret = env.RELAY_IP_KEY ?? `vapid|${env.RELAY_VAPID_PRIVATE_KEY ?? "dev"}`;
  const raw = await crypto.subtle.digest("SHA-256", enc.encode(`miblo-relay-ip-key|${secret}`));
  const key = await crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(`${Math.floor(now / (30 * 86_400_000))}|${ip}`)));
  let s = "";
  for (const b of mac.subarray(0, 16)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * The networks the room counts a client in, as "<tier>:<key>" pairs: an IPv6 client by its /64,
 * /56 and /48 (a home gets a /56, a free tunnel a /48), an IPv4 client by its address ("4").
 */
export async function clientKeys(env: RelayRouterEnv, ip: string, now: number): Promise<string> {
  if (!isIpv6(ip)) return `4:${await clientKey(env, clientNetwork(ip), now)}`;
  const tiers = [64, 56, 48] as const;
  return (await Promise.all(tiers.map(async (b) => `${b}:${await clientKey(env, clientNetwork(ip, b), now)}`))).join(",");
}

function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store", ...extra } });
}

/** The relay's response, or null when the path is not a relay route. */
export async function handleRelay(request: Request, env: RelayRouterEnv): Promise<Response | null> {
  const url = new URL(request.url);
  if (!url.pathname.startsWith(RELAY_PREFIX)) return null;
  const rest = url.pathname.slice(RELAY_PREFIX.length);

  if (rest === "vapid") {
    if (request.method !== "GET" && request.method !== "HEAD") return json({ error: "method_not_allowed" }, 405, { Allow: "GET" });
    if (!env.RELAY_VAPID_PUBLIC_KEY) return json({ error: "push_unavailable" }, 503);
    return json({ publicKey: env.RELAY_VAPID_PUBLIC_KEY }, 200, { "Cache-Control": "public, max-age=3600" });
  }

  if (!isRoom(rest)) return json({ error: "bad_room" }, 404);
  if (!env.RELAY) return json({ error: "relay_unavailable" }, 503);

  if (request.method === "DELETE") {
    if (!bearerToken(request.headers.get("Authorization"))) return json({ error: "unauthorized" }, 401);
  } else if (request.method === "GET") {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return json({ error: "upgrade_required" }, 426);
    if (!isRole(url.searchParams.get("role"))) return json({ error: "bad_role" }, 400);
  } else {
    return json({ error: "method_not_allowed" }, 405, { Allow: "GET, DELETE" });
  }

  {
    // An IPv6 host counts by its /64: it could pick a new address for every request.
    const ip = clientNetwork(request.headers.get("CF-Connecting-IP") ?? "unknown");
    // Per-IP limit on upgrades and deletes. The IP is only the limiter key, never stored.
    if (limited(`relay:${ip}`, Number(env.RELAY_RATE_LIMIT) || 30)) return json({ error: "rate_limited" }, 429, { "Retry-After": "60" });
  }

  // Only what the room needs travels on: the role, the bearer token, the writer's read-token hash
  // and enrolled phones, and a keyed hash of the client's network for the day (the new-room limit;
  // no IP, no cookies).
  const headers = new Headers();
  for (const name of ["Upgrade", "Connection", "Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Extensions", "Authorization", "X-Read-Hash", "X-Phones"]) {
    const v = request.headers.get(name);
    if (v) headers.set(name, v);
  }
  if (request.method === "GET") {
    const ip = request.headers.get("CF-Connecting-IP");
    if (ip) headers.set("X-Client-Keys", await clientKeys(env, ip, Date.now()));
  }
  const inner = new URL(`https://relay.internal/${rest}`);
  const role = url.searchParams.get("role");
  if (role) inner.searchParams.set("role", role);
  const stub = env.RELAY.get(env.RELAY.idFromName(rest));
  return stub.fetch(new Request(inner, { method: request.method, headers }));
}
