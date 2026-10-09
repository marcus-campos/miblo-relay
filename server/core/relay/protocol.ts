// Phone relay protocol v5 (docs/phone-relay-protocol.md): constants and input validation shared
// by the router (worker.ts) and the room Durable Object. The relay never sees keys or plaintext.
import { base64url } from "../crypto";

/** room: the first 22 base64url characters of SHA-256("miblo-room-v2|" + writeToken). */
export const ROOM_RE = /^[A-Za-z0-9_-]{22}$/;
/** Prefix of the room derivation; the relay recomputes it to verify the writer. */
export const ROOM_DERIVATION_PREFIX = "miblo-room-v2|";
/** writeToken / readToken: 256-bit random, base64url without padding. */
export const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
/** AES-GCM iv: 12 bytes, base64url without padding. */
export const IV_RE = /^[A-Za-z0-9_-]{16}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;

/** v5: an enrolled phone's id (16 random bytes, base64url). */
export const PHONE_RE = /^[A-Za-z0-9_-]{22}$/;
/** v5: a content key wrapped for one phone: base64url(iv 12 || key 32 || tag 16). */
export const WRAP_RE = /^[A-Za-z0-9_-]{80}$/;
/** v5: the most enrolled phones a writer registers. */
export const MAX_PHONES = 8;

export type Role = "writer" | "reader";
/** Per-room plan. "plus" (Miblo+) unlocks the other channels and reader "up" frames. */
export type Plan = "free" | "plus";
/** Frame channels: "status" (default, the only one on the free plan) and the Miblo+ ones (v3). */
export const CHANNELS = ["status", "history", "chat", "reply", "approval"] as const;
export type Channel = (typeof CHANNELS)[number];

/**
 * v3: the largest `ct` (base64url characters) per channel and direction. The relay cannot read
 * frames, so these caps bound what a compromised peer can push through it. "status" writer frames
 * are bounded by the frame limit alone; "status" never travels up.
 */
export const CT_MAX: { msg: Record<Channel, number>; up: Partial<Record<Channel, number>> } = {
  msg: { status: 64 * 1024, history: 60 * 1024, chat: 16 * 1024, reply: 2 * 1024, approval: 48 * 1024 },
  up: { history: 1024, reply: 8 * 1024, approval: 4 * 1024 },
};

/** v3: reader "up" frames per minute per reader and channel (on top of the 1/s limit). */
export const UP_PER_MINUTE: Partial<Record<Channel, number>> = { history: 12, reply: 20, approval: 30 };
export type PushLang = "pt-BR" | "en";

export const LIMITS = {
  /** Any frame larger than this closes the socket (1009). */
  frameBytes: 64 * 1024,
  /** Readers send auth, push subscriptions and (v1.1, Miblo+) "up" frames. */
  readerFrameBytes: 16 * 1024,
  /** Writer frames per second; extra ones are dropped. */
  writerPerSecond: 2,
  readerPerSecond: 2,
  /** v1.1 reader -> writer "up" frames per second. */
  upPerSecond: 1,
  /** Phones connected at once: Miblo+ rooms (the oldest goes past it) and free rooms (a second is refused). */
  maxReaders: 5,
  maxReadersFree: 1,
  /** v5: sockets one enrolled phone may hold at once (its oldest goes past it, never another phone's). */
  maxSocketsPerPhone: 2,
  /** v5: Miblo+ sockets without a phone identity (status only, or enrolling); the oldest goes past it. */
  maxGuests: 2,
  /** v5: "up" frames per minute from a socket without a phone identity (enrollments only). */
  guestUpPerMinute: 6,
  /**
   * Sockets that have not authenticated yet, per role; more are refused (HTTP 429). Header-auth
   * connections (the plugin's writer) are verified before the upgrade and never count.
   */
  maxPendingWriters: 2,
  maxPendingReaders: 10,
  authTimeoutMs: 5_000,
  frameTtlMs: 10 * 60 * 1000,
  /** The last frame lives in memory; it is written to storage at most this often. */
  persistIntervalMs: 60 * 1000,
  /** A room no reader ever joined is deleted this long after it was created. */
  noReaderTtlMs: 24 * 60 * 60 * 1000,
  /** Otherwise it is deleted after this long without writer activity (readers do not count). */
  idleMs: 30 * 24 * 60 * 60 * 1000,
  pushIntervalMs: 60 * 1000,
  /**
   * A phone that said the app is on its screen ({"t":"fg","on":true}, re-sent every minute while it
   * stays there) gets no push for this long after it last said so: it sees the card already.
   */
  foregroundFreshMs: 150 * 1000,
  /** Push events per room per UTC day. */
  pushesPerRoomPerDay: 30,
  /**
   * Push deliveries (one per subscription) per UTC day, in two pools: free rooms share one, Miblo+
   * rooms (paid, linked to an account) have their own, so anonymous rooms cannot spend it. Only
   * deliveries the push service accepted count (the rest are given back).
   */
  pushesFreePerDay: 50_000,
  /** Miblo+: a runaway guard only; what bounds Miblo+ pushes is each paying account's own quota. */
  pushesPlusPerDay: 1_000_000,
  /** Push deliveries per UTC day charged to one Miblo+ account (all its rooms together). */
  pushesPerAccountPerDay: 1_000,
  /** Push deliveries per UTC day charged to the network that created a free room (keyed hash). */
  pushesPerNetworkPerDay: 600,
  /** Deliveries per UTC day to one push endpoint, whatever the rooms it was subscribed in. */
  pushesPerEndpointPerDay: 40,
  /** A subscription no phone re-sent for this long gets no more pushes (and is dropped). */
  subscriptionFreshMs: 30 * 24 * 60 * 60 * 1000,
  /** A pool past this share of its day logs a warning (once a day), and again when it runs out. */
  pushAlertShare: 0.8,
  /** Push subscriptions a room keeps (the newest): about one per phone it allows. */
  maxSubscriptions: 5,
  maxSubscriptionsFree: 2,
  /** New rooms per network (a keyed hash of the IP or IPv6 /64; never the IP itself) per UTC day... */
  newRoomsPerNetworkPerDay: 10,
  /**
   * ...and rooms a phone really joined, per 30-day period (rooms live up to 30 days without their
   * writer). A room no phone ever joined never counts here.
   */
  newRoomsPerNetworkPerPeriod: 30,
  /**
   * The same for an IPv4 address, much higher: one address is often shared by a whole carrier
   * (CGNAT) or an office. The day cap and each room's own limits (one writer, rates) do the rest.
   */
  newRoomsPerIpv4PerPeriod: 300,
} as const;

/** WebSocket close codes the relay uses. */
export const CLOSE = {
  badFrame: 4400,
  unauthorized: 4401,
  /** v1.1: a channel or frame type the room's plan does not include. */
  plan: 4402,
  /** A reader came before the writer registered the read-token hash; retry later. */
  notReady: 4403,
  roomDeleted: 4404,
  /** A newer writer (or, past the reader cap, a newer reader) took this socket's place. */
  replaced: 4409,
  tooMany: 4429,
  /** v3: the room's plan allows no more phones at once (free: 1); the phone retries later. */
  readerLimit: 4406,
  /** v5: this phone was revoked on the computer (the writer no longer lists it). */
  revoked: 4411,
  tooLarge: 1009,
} as const;

export function isRoom(value: unknown): value is string {
  return typeof value === "string" && ROOM_RE.test(value);
}

export function isToken(value: unknown): value is string {
  return typeof value === "string" && TOKEN_RE.test(value);
}

/** A SHA-256 digest, base64url without padding (the writer's X-Read-Hash). */
export function isDigest(value: unknown): value is string {
  return isToken(value);
}

/** base64url(SHA-256(UTF-8 bytes of `value`)), 43 characters. */
export async function sha256B64url(value: string): Promise<string> {
  return base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))));
}

/** The room a write token owns: base64url(SHA-256("miblo-room-v2|" + writeToken))[:22]. */
export async function deriveRoom(writeToken: string): Promise<string> {
  return (await sha256B64url(ROOM_DERIVATION_PREFIX + writeToken)).slice(0, 22);
}

/** Constant-time comparison of two equal-length ASCII strings (false on a length mismatch). */
export function sameString(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const enc = new TextEncoder();
  const subtle = crypto.subtle as SubtleCrypto & { timingSafeEqual?: (x: BufferSource, y: BufferSource) => boolean };
  if (subtle.timingSafeEqual) return subtle.timingSafeEqual(enc.encode(a), enc.encode(b));
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function isRole(value: unknown): value is Role {
  return value === "writer" || value === "reader";
}

/** The token from "Authorization: Bearer <token>", when well-formed. */
export function bearerToken(header: string | null): string | null {
  const m = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(header?.trim() ?? "");
  return m ? m[1] : null;
}

export type MsgFrame = { t: "msg" | "up"; iv: string; ct: string; ch?: Channel; to?: Record<string, string>; g?: 1 };

/**
 * v5: the phones a sealed frame goes to ({phone id: its wrap of the content key}), when well formed
 * (1 to MAX_PHONES entries); null otherwise.
 */
export function sealedTo(value: unknown): Record<string, string> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const entries = Object.entries(value as Record<string, unknown>);
  if (!entries.length || entries.length > MAX_PHONES) return null;
  const out: Record<string, string> = {};
  for (const [id, wrap] of entries) {
    if (!PHONE_RE.test(id) || typeof wrap !== "string" || !WRAP_RE.test(wrap)) return null;
    out[id] = wrap;
  }
  return out;
}

/**
 * v5: the enrolled phones a writer registers, from its X-Phones header ("id.hash,id.hash") or a
 * {"t":"phones","list":[{id,h}]} frame: {phone id: SHA-256 of its reader token}. null when malformed.
 */
export function parsePhones(value: unknown): Record<string, string> | null {
  let list: { id: unknown; h: unknown }[];
  if (typeof value === "string") {
    if (!value.trim()) return {};
    list = value.split(",").map((pair) => {
      const [id, h] = pair.trim().split(".");
      return { id, h };
    });
  } else if (Array.isArray(value)) {
    list = value.map((x) => (x && typeof x === "object" ? (x as { id: unknown; h: unknown }) : { id: null, h: null }));
  } else {
    return null;
  }
  if (list.length > MAX_PHONES) return null;
  const out: Record<string, string> = {};
  for (const { id, h } of list) {
    if (typeof id !== "string" || !PHONE_RE.test(id) || !isDigest(h)) return null;
    out[id] = h;
  }
  return out;
}

/** A P-256 public key (65-byte uncompressed point) that is really on the curve. */
export async function validPushKey(p256dh: string): Promise<boolean> {
  try {
    const raw = Uint8Array.from(atob(p256dh.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (p256dh.length % 4)) % 4)), (c) => c.charCodeAt(0));
    if (raw.length !== 65 || raw[0] !== 4) return false;
    await crypto.subtle.importKey("raw", raw, { name: "ECDH", namedCurve: "P-256" }, false, []);
    return true;
  } catch {
    return false;
  }
}

/** v3: whether a frame of type `t` on `ch` fits its channel's cap ("up" frames must name a Miblo+ channel). */
export function fitsChannel(frame: MsgFrame): boolean {
  const ch = frame.ch ?? "status";
  const max = frame.t === "up" ? CT_MAX.up[ch] : CT_MAX.msg[ch];
  return max !== undefined && frame.ct.length <= max;
}

export function isChannel(value: unknown): value is Channel {
  return typeof value === "string" && (CHANNELS as readonly string[]).includes(value);
}

/** A well-formed encrypted frame of type `t` ("msg" writer -> readers, "up" reader -> writer). */
export function isMsgFrame(value: unknown, t: "msg" | "up" = "msg"): value is MsgFrame {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  return (
    v.t === t &&
    (v.ch === undefined || isChannel(v.ch)) &&
    (v.to === undefined || sealedTo(v.to) !== null) &&
    (v.g === undefined || v.g === 1) &&
    typeof v.iv === "string" &&
    IV_RE.test(v.iv) &&
    typeof v.ct === "string" &&
    // At least the 16-byte GCM tag.
    v.ct.length >= 22 &&
    B64URL_RE.test(v.ct)
  );
}

export type PushSubscriptionJson = { endpoint: string; keys: { p256dh: string; auth: string } };

/**
 * Push services the relay is willing to POST to. A subscription endpoint is attacker-supplied
 * input, so it is limited to the browsers' push services instead of any https URL.
 */
const PUSH_HOST_SUFFIXES = [
  "fcm.googleapis.com",
  "android.googleapis.com",
  "updates.push.services.mozilla.com",
  "push.services.mozilla.com",
  "push.apple.com",
  "notify.windows.com",
];

export function isPushEndpoint(value: string): boolean {
  return canonicalEndpoint(value) !== null;
}

/**
 * v5: the one spelling of a push endpoint the relay stores, counts and sends to, or null. A push
 * service sees the same subscription behind "E", "E#1", "E?x=2", "E:443" or an uppercase host, so
 * none of those may count as another endpoint: anything but https, the default port, a lowercase
 * known push host and a plain path made of URL-safe characters is refused. Windows' push service is
 * the only one whose endpoint carries a query, exactly one `token`.
 */
export function canonicalEndpoint(value: string): string | null {
  if (typeof value !== "string" || value.length > 1024 || /[\s#]/.test(value)) return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" || url.username || url.password || url.port || url.hash) return null;
  const host = url.hostname;
  if (!PUSH_HOST_SUFFIXES.some((s) => host === s || host.endsWith(`.${s}`))) return null;
  // The string as given must already be that canonical form (no case, port or dot games).
  const path = url.pathname;
  if (!/^\/[A-Za-z0-9._~:\-/]+$/.test(path) || path.includes("//") || /(^|\/)\.\.?(\/|$)/.test(path)) return null;
  if (host.endsWith("notify.windows.com")) {
    // Windows: the token is the subscription; it is decoded and written back one fixed way (its
    // percent-escapes vary), and the regional host must look like the push service's own.
    if (!/^[a-z0-9-]+\.notify\.windows\.com$/.test(host) || path !== "/w/" || !/^\?token=[A-Za-z0-9%._~+\-/=]+$/.test(url.search)) return null;
    const token = wnsToken(url.search.slice("?token=".length));
    return token ? `https://${host}/w/?token=${encodeURIComponent(token)}` : null;
  }
  if (url.search) return null;
  const canonical = `https://${host}${path}`;
  return canonical === value ? canonical : null;
}

function wnsToken(raw: string): string | null {
  try {
    const t = decodeURIComponent(raw);
    return /^[A-Za-z0-9+/=._~-]{1,900}$/.test(t) ? t : null;
  } catch {
    return null;
  }
}

/**
 * What identifies a push subscription for the per-endpoint quota: the canonical endpoint, and for
 * Windows its token alone (the same token on another regional host is the same subscription).
 */
export function endpointIdentity(canonical: string): string {
  const m = /^https:\/\/[a-z0-9-]+\.notify\.windows\.com\/w\/\?token=(.+)$/.exec(canonical);
  return m ? `wns:${decodeURIComponent(m[1])}` : canonical;
}

/** A validated PushSubscription (endpoint on a known push service, P-256 key, 16-byte auth). */
export function parseSubscription(value: unknown): PushSubscriptionJson | null {
  if (!value || typeof value !== "object") return null;
  const v = value as { endpoint?: unknown; keys?: { p256dh?: unknown; auth?: unknown } };
  const endpoint = typeof v.endpoint === "string" ? canonicalEndpoint(v.endpoint) : null;
  if (!endpoint) return null;
  const p256dh = v.keys?.p256dh;
  const auth = v.keys?.auth;
  // 65-byte uncompressed point = 87 base64url chars; 16-byte secret = 22 chars.
  if (typeof p256dh !== "string" || !/^[A-Za-z0-9_-]{87}$/.test(p256dh)) return null;
  if (typeof auth !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(auth)) return null;
  return { endpoint, keys: { p256dh, auth } };
}

export function pushLang(value: unknown): PushLang {
  return value === "pt-BR" || value === "pt" ? "pt-BR" : "en";
}

/**
 * What a push may be about: a session waiting on the person ("needs you", from the count in
 * {"t":"push","n"}), and the Miblo+ events the writer names with a fixed kind ({"t":"push","k"}).
 * A kind is all the relay ever learns of an event, and the phone gets only fixed words for it.
 */
export type PushKind = "needs_you" | "approval" | "task_done" | "task_failed";
/** The kinds a writer may name in {"t":"push","k"} (needs_you comes from the count). */
export const PUSH_EVENT_KINDS: readonly PushKind[] = ["approval", "task_done", "task_failed"];

const PUSH_WORDS: Record<PushKind, Record<PushLang, string>> = {
  needs_you: { "pt-BR": "A sessão precisa de você", en: "A session needs you" },
  approval: { "pt-BR": "Pedido de permissão", en: "Permission request" },
  task_done: { "pt-BR": "Tarefa concluída", en: "Task finished" },
  task_failed: { "pt-BR": "A tarefa falhou", en: "Task failed" },
};

export function isPushEventKind(value: unknown): value is PushKind {
  return typeof value === "string" && (PUSH_EVENT_KINDS as readonly string[]).includes(value);
}

/**
 * The notification for a kind, in the phone's saved language: fixed words only, nothing from the
 * computer (no session, tool, command or text). The service worker opens the app on its own page.
 */
export function pushNotification(kind: PushKind, lang: PushLang) {
  return { t: kind, title: "Miblo", body: PUSH_WORDS[kind][lang], lang };
}

/** The generic "needs you" notification (kept for callers of the v1 name). */
export function needsYouNotification(lang: PushLang) {
  return pushNotification("needs_you", lang);
}
