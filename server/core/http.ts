// Shared request handling for the JSON API: CSRF-safe parsing, validation, rate limits.
import type { z } from "zod";

const MAX_BODY_BYTES = 32 * 1024;

export function json(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return Response.json(data, { status, headers: { "Cache-Control": "no-store", ...headers } });
}

export function error(code: string, status: number, extra: Record<string, unknown> = {}): Response {
  return json({ error: code, ...extra }, status);
}

/**
 * Rejects cross-site requests. Browsers only send `Content-Type: application/json` cross-origin
 * after a CORS preflight (which these routes never answer), and same-origin fetches carry a
 * matching Origin / Sec-Fetch-Site, so a form on another site cannot post here.
 */
export function crossSiteError(request: Request): Response | null {
  const type = request.headers.get("content-type") ?? "";
  if (!type.toLowerCase().startsWith("application/json")) return error("unsupported_media_type", 415);
  const site = request.headers.get("sec-fetch-site");
  if (site && site !== "same-origin" && site !== "none") return error("forbidden", 403);
  const origin = request.headers.get("origin");
  if (origin) {
    const host = request.headers.get("x-forwarded-host") ?? request.headers.get("host") ?? new URL(request.url).host;
    let originHost = "";
    try {
      originHost = new URL(origin).host;
    } catch {
      return error("forbidden", 403);
    }
    if (originHost !== host) return error("forbidden", 403);
  }
  return null;
}

export type Parsed<T> = { ok: true; data: T } | { ok: false; response: Response };

/**
 * Guards against cross-site posts, limits the body size (32 KB, or `maxBytes` for the few routes
 * that take a picture) and validates it with a zod schema.
 */
export async function readJson<S extends z.ZodType>(request: Request, schema: S, maxBytes = MAX_BODY_BYTES): Promise<Parsed<z.infer<S>>> {
  const blocked = crossSiteError(request);
  if (blocked) return { ok: false, response: blocked };
  const length = Number(request.headers.get("content-length") ?? "0");
  if (length > maxBytes) return { ok: false, response: error("payload_too_large", 413) };
  let raw: string;
  try {
    raw = await request.text();
  } catch {
    return { ok: false, response: error("invalid_json", 400) };
  }
  if (raw.length > maxBytes) return { ok: false, response: error("payload_too_large", 413) };
  let body: unknown;
  try {
    body = JSON.parse(raw);
  } catch {
    return { ok: false, response: error("invalid_json", 400) };
  }
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    // Field paths only: values may hold personal data and are never echoed or logged.
    const fields = [...new Set(parsed.error.issues.map((i) => i.path.join(".")))];
    return { ok: false, response: error("invalid_request", 400, { fields }) };
  }
  return { ok: true, data: parsed.data };
}

/** The 8 groups of an IPv6 address (numbers), or null when `v` is not one. */
function ipv6Groups(v: string): number[] | null {
  const [head, tail = ""] = v.split("::");
  if (v.split("::").length > 2) return null;
  const h = head ? head.split(":") : [];
  const t = v.includes("::") ? (tail ? tail.split(":") : []) : [];
  if (!v.includes("::") && h.length !== 8) return null;
  const groups = v.includes("::") ? [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill("0"), ...t] : h;
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;
  return groups.map((g) => parseInt(g, 16));
}

/**
 * The network an address belongs to, as rate limits count it: an IPv6 address by its first `bits`
 * (64 by default: one subscriber's prefix, inside which a host can pick any address; 56 and 48 are
 * what one home or one free tunnel gets), an IPv4 address as is (NAT and shared ISP ranges make
 * anything wider unfair). Unparseable input comes back as is.
 */
export function clientNetwork(ip: string, bits: 48 | 56 | 64 = 64): string {
  const v = ip.trim().toLowerCase().replace(/^\[|\]$/g, "").split("%")[0];
  if (!v.includes(":")) return v;
  // A v4-mapped address (::ffff:1.2.3.4) is the IPv4 address.
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(v);
  if (mapped) return mapped[1];
  const g = ipv6Groups(v);
  if (!g) return v;
  const keep = g.slice(0, 4);
  if (bits <= 56) keep[3] = bits === 56 ? keep[3] & 0xff00 : 0;
  if (bits === 48) keep.splice(3, 1, 0);
  return `${keep.map((n) => n.toString(16)).join(":")}::/${bits}`;
}

/** Whether `ip` is an IPv6 address (not a v4-mapped one). */
export function isIpv6(ip: string): boolean {
  const n = clientNetwork(ip);
  return n.endsWith("/64");
}

/**
 * The client's address. On Cloudflare, CF-Connecting-IP is set by Cloudflare itself; the Node
 * runtime removes whatever a client sent under that name and sets it from the socket (or, with
 * TRUSTED_PROXY=1, from your reverse proxy's X-Forwarded-For). Used only as a rate-limit key.
 */
export function clientIp(request: Request): string {
  return request.headers.get("cf-connecting-ip") ?? "unknown";
}

// The rate limiter: a fixed window per key, in memory.
const windows = new Map<string, { start: number; count: number }>();

export function memoryLimit(key: string, limit: number, periodMs = 60_000, now = Date.now()): boolean {
  const w = windows.get(key);
  if (!w || now - w.start >= periodMs) {
    // Never cleared wholesale (a flood of new keys would reset everyone's count): expired windows
    // go first, then the oldest ones.
    if (windows.size > 5000) {
      for (const [k, v] of windows) if (now - v.start >= periodMs) windows.delete(k);
      if (windows.size > 5000) for (const k of [...windows.keys()].slice(0, windows.size - 4500)) windows.delete(k);
    }
    windows.set(key, { start: now, count: 1 });
    return true;
  }
  w.count += 1;
  return w.count <= limit;
}

/**
 * True when `key` is over `limit` requests a minute. In memory: exact on Node (one process), per
 * isolate on Cloudflare Workers (a single-person server never comes near these limits; they only
 * slow down guessing and floods).
 */
export function limited(key: string, limit: number, periodMs = 60_000): boolean {
  return !memoryLimit(key, limit, periodMs);
}

export function tooMany(): Response {
  return error("rate_limited", 429);
}
