// One Durable Object per phone relay room (docs/phone-relay-protocol.md, v3), on the WebSocket
// Hibernation API so an idle room costs nothing. The writer is verified by recomputing the room
// from its token (room = SHA-256("miblo-room-v2|" + writeToken)[:22]); readers by the read-token
// hash the writer registered. It stores only: that hash, the last ciphertext frame (in memory,
// written at most once a minute and only once a reader has joined), push subscriptions and
// counters, timestamps and the room's plan. Never IPs, never plaintext, and nothing about the
// frames is logged. Miblo+ channels (history, chat, reply, approval) and reader "up" frames are
// forwarded to whoever is connected right now and never stored: with nobody there, they are dropped.
// The account side sets the room's plan through an internal call (POST /__plus, only reachable
// through the namespace, never through the router), after the room itself checked the computer's
// proof of its write token (HMAC keyed with SHA-256(writeToken)). On a self-hosted server every
// room a linked computer registers gets the "plus" plan with no end (no license check): the
// plan code stays so the protocol (and its free-room limits for unregistered rooms) is unchanged.
// The same class runs on Cloudflare (a Durable Object, server/worker) and on Node (server/node,
// which provides the same state, storage, alarm and WebSocket API in process): only RoomRuntime
// below differs between them.
// v5: the writer also registers its enrolled phones (each one's id and the SHA-256 of its own
// reader token). A phone that authenticates with its token is known by its id: Miblo+ frames are
// sealed per phone and reach only the phones they name, a phone the writer no longer lists is
// closed (4411) and refused, and one phone can only push out its own older sockets. Sockets that
// authenticate with the shared read token are guests: the status only, plus an enrollment.
import { base64urlDecode, sha256Hex } from "../crypto";
import {
  CLOSE,
  LIMITS,
  bearerToken,
  deriveRoom,
  CT_MAX,
  UP_PER_MINUTE,
  PHONE_RE,
  fitsChannel,
  parsePhones,
  sealedTo,
  validPushKey,
  endpointIdentity,
  isDigest,
  isMsgFrame,
  isRole,
  isRoom,
  isToken,
  needsYouNotification,
  parseSubscription,
  pushLang,
  sameString,
  sha256B64url,
  type Plan,
  type PushLang,
  type PushSubscriptionJson,
  type Role,
} from "./protocol";
import { sendPush, type VapidKeys } from "./webpush";
import type { RoomNamespace, RoomStub } from "../env";

export type RelayEnv = {
  /** The server's origin: the push subject when RELAY_VAPID_SUBJECT is not set. */
  PUBLIC_ORIGIN?: string;
  RELAY_VAPID_PUBLIC_KEY?: string;
  RELAY_VAPID_PRIVATE_KEY?: string;
  RELAY_VAPID_SUBJECT?: string;
  /** The rooms' own namespace: the global push budget lives in one of its objects. */
  RELAY?: RoomNamespace;
};

/** A room's WebSocket as the room uses it (Cloudflare's hibernatable WebSocket API). */
export interface RoomSocket {
  readonly readyState: number;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  serializeAttachment(value: unknown): void;
  deserializeAttachment(): unknown;
}
/** A room's storage (the Durable Object storage API subset the room uses). */
export interface RoomStorage {
  get<T>(key: string): Promise<T | undefined>;
  get<T>(keys: string[]): Promise<Map<string, T>>;
  put(key: string, value: unknown): Promise<void>;
  delete(keys: string | string[]): Promise<unknown>;
  list<T>(options: { prefix: string }): Promise<Map<string, T>>;
  deleteAll(): Promise<void>;
  getAlarm(): Promise<number | null>;
  setAlarm(at: number): Promise<void>;
  deleteAlarm(): Promise<void>;
}
/** A room's state (the Durable Object state API subset the room uses). */
export interface RoomState {
  id: { toString(): string };
  storage: RoomStorage;
  blockConcurrencyWhile<T>(fn: () => Promise<T>): Promise<T>;
  acceptWebSocket(ws: RoomSocket, tags?: string[]): void;
  getWebSockets(tag?: string): RoomSocket[];
}
/**
 * What differs between the runtimes: a new server socket for an accepted upgrade with the answer
 * that completes it (Cloudflare: a WebSocketPair and a 101 response), and answering the keep-alive
 * ping without waking the room.
 */
export interface RoomRuntime {
  upgrade(): { server: RoomSocket; response: Response };
  autoPong(state: RoomState, ping: string, pong: string): void;
}

/**
 * `phone`: the enrolled phone a reader authenticated as (absent: a guest, or the writer).
 * `ck`: the client's networks as the router passed them ("<tier>:<keyed hash>,..."; new rooms only).
 */
type Attachment = { role: Role; authed: boolean; openedAt: number; room: string; phone?: string; ph?: string; ck?: string };
type Meta = {
  /** base64url(SHA-256(readToken)), registered by the writer. */
  readHash?: string;
  createdAt?: number;
  /** Last writer activity (readers never refresh it). */
  lastSeen?: number;
  /** A reader has authenticated at least once: frames may be persisted, the 30-day rule applies. */
  readerEver?: boolean;
  pushN?: number;
  pushAt?: number;
  pushDay?: number;
  pushCount?: number;
  plan?: Plan;
  /** Miblo+: when the "plus" plan lapses on its own (ms), even if the account side never calls. */
  planUntil?: number;
  /** Miblo+: base64url(SHA-256(writeToken)), the key of the room ownership proof. */
  writeKey?: string;
  /** v5: the enrolled phones: {phone id: base64url(SHA-256(its reader token))}. */
  phones?: Record<string, string>;
  /** v5: Miblo+: an opaque key of the paying account (the account side's HMAC): its push quota. */
  account?: string;
  /** v5: the networks that created the room ("<tier>:<keyed hash>"): a free room's push payers. */
  nets?: string[];
};
type StoredFrame = { iv: string; ct: string; at: number };
type StoredSub = { sub: PushSubscriptionJson; lang: PushLang; at: number };

const OPEN = 1;
const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
/** Alarms may fire slightly before the deadline by the object's clock: close pending sockets anyway. */
const ALARM_SLACK_MS = 1000;
/** Name of the object that keeps the global daily push budget (not a valid room name). */
export const PUSH_BUDGET_OBJECT = "push-budget";
const BUDGET_PATH = "/__push-budget";
/** Internal Miblo+ plan call (the router only forwards 22-character room paths, never this). */
export const PLUS_PATH = "/__plus";
const enc = new TextEncoder();
/** The router's network keys: "4:<key>" (IPv4) or "64:<key>,56:<key>,48:<key>" (IPv6). */
const NET_KEYS_RE = /^(4|64|56|48):[A-Za-z0-9_-]{22}(,(64|56|48):[A-Za-z0-9_-]{22}){0,2}$/;
/** New rooms per day and per 30-day period, and free push deliveries per day, by network tier. */
const TIER_CAPS: Record<string, { day: number; period: number | null; pushes: number }> = {
  // The period caps count only rooms a phone really joined (op=used); a room never joined costs a
  // day's slot at most, given back when it goes. IPv4 is shared (CGNAT, offices): a much higher
  // period cap there, so neighbours who pair are not locked out by each other.
  "4": { day: LIMITS.newRoomsPerNetworkPerDay, period: LIMITS.newRoomsPerIpv4PerPeriod, pushes: LIMITS.pushesPerNetworkPerDay },
  "64": { day: LIMITS.newRoomsPerNetworkPerDay, period: LIMITS.newRoomsPerNetworkPerPeriod, pushes: LIMITS.pushesPerNetworkPerDay },
  "56": { day: 2 * LIMITS.newRoomsPerNetworkPerDay, period: 2 * LIMITS.newRoomsPerNetworkPerPeriod, pushes: Math.round(2.5 * LIMITS.pushesPerNetworkPerDay) },
  "48": { day: 4 * LIMITS.newRoomsPerNetworkPerDay, period: 4 * LIMITS.newRoomsPerNetworkPerPeriod, pushes: 5 * LIMITS.pushesPerNetworkPerDay },
  // A room with no network on record (made before v5, or by an internal call): the room pays alone.
  "0": { day: 0, period: null, pushes: LIMITS.pushesPerNetworkPerDay },
};
/** A free room still gets this many deliveries a day when its networks' quotas are spent by others... */
const ROOM_FALLBACK_PUSHES = 10;
/** ...within its networks' own fallback quota (a multiple of their push quota), so it does not grow with rooms. */
const FALLBACK_FACTOR = 1;

/** True when the UTF-8 encoding of `s` is longer than `max` bytes. */
function tooLong(s: string, max: number): boolean {
  // Cheap bounds first: a UTF-16 unit is 1 to 3 UTF-8 bytes.
  if (s.length > max) return true;
  return s.length * 3 > max && enc.encode(s).length > max;
}

const utcDay = (ms: number) => Math.floor(ms / DAY);

export class RelayRoom {
  private meta: Meta = {};
  /** The newest status frame (memory); `persistedAt` is when it was last written to storage. */
  private frame: StoredFrame | undefined;
  private frameDirty = false;
  private persistedAt = 0;
  private alarmAt: number | null = null;
  private lastSeenWritten = 0;
  private authTimer: ReturnType<typeof setTimeout> | null = null;
  /** Per-socket frame counters for the rate limit (lost on hibernation, which needs idleness). */
  private rate = new WeakMap<RoomSocket, { second: number; n: number }>();
  private upRate = new WeakMap<RoomSocket, { second: number; n: number }>();
  /** v3: per reader and channel, "up" frames in the current minute. */
  private upMinute = new WeakMap<RoomSocket, Map<string, { minute: number; n: number }>>();

  constructor(
    protected readonly ctx: RoomState,
    protected readonly env: RelayEnv,
    private readonly runtime: RoomRuntime,
  ) {
    void ctx.blockConcurrencyWhile(async () => {
      const got = await ctx.storage.get<Meta | StoredFrame>(["meta", "frame"]);
      this.meta = (got.get("meta") as Meta | undefined) ?? {};
      this.frame = got.get("frame") as StoredFrame | undefined;
      this.persistedAt = this.frame?.at ?? 0;
      this.lastSeenWritten = this.meta.lastSeen ?? 0;
      this.alarmAt = await ctx.storage.getAlarm();
    });
    // Keep-alive pings answered without waking the object.
    runtime.autoPong(ctx, '{"t":"ping"}', '{"t":"pong"}');
  }

  /** The clock; tests move it. */
  protected now(): number {
    return Date.now();
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === BUDGET_PATH) return this.budgetRequest(url, request);
    if (url.pathname === PLUS_PATH) return this.plusRequest(request);
    const room = url.pathname.slice(1);
    if (!isRoom(room)) return new Response("bad room", { status: 404 });
    if (request.method === "DELETE") return this.wipeRequest(request, room);
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return new Response("upgrade required", { status: 426 });
    const role = url.searchParams.get("role");
    if (!isRole(role)) return new Response("bad role", { status: 400 });

    // Node clients (the plugin) authenticate with headers, verified before anything is counted
    // or accepted; browsers send the auth message and wait in a small per-role pending pool.
    const auth = request.headers.get("Authorization");
    const headerToken = bearerToken(auth);
    const keysHeader = request.headers.get("X-Client-Keys");
    const ck = keysHeader && NET_KEYS_RE.test(keysHeader) ? keysHeader : undefined;
    if (auth) {
      if (!headerToken) return new Response("unauthorized", { status: 401 });
      const verdict = await this.verify(role, room, headerToken, request.headers.get("X-Read-Hash"), {
        phones: request.headers.get("X-Phones") ?? "",
        ck,
      });
      if (verdict !== "ok") return new Response(verdict, { status: verdict === "not ready" ? 403 : verdict === "too many rooms" ? 429 : 401 });
    } else {
      const cap = role === "writer" ? LIMITS.maxPendingWriters : LIMITS.maxPendingReaders;
      if (this.sockets(role).filter((ws) => !this.attachment(ws)?.authed).length >= cap) {
        return new Response("too many connections", { status: 429 });
      }
    }

    const { server, response } = this.runtime.upgrade();
    this.ctx.acceptWebSocket(server, [role]);
    const now = this.now();
    server.serializeAttachment({ role, authed: false, openedAt: now, room, ...(ck ? { ck } : {}) } satisfies Attachment);
    if (headerToken) {
      await this.authed(server, role, room);
    } else {
      // An in-memory timer closes it on time; the alarm is the backup if the object is evicted.
      this.armAuthTimer();
      await this.scheduleAlarm(now + LIMITS.authTimeoutMs);
    }
    return response;
  }

  async webSocketMessage(ws: RoomSocket, message: string | ArrayBuffer): Promise<void> {
    const att = this.attachment(ws);
    if (!att) return ws.close(CLOSE.badFrame, "bad state");
    if (typeof message !== "string") return ws.close(CLOSE.badFrame, "text frames only");
    const max = att.role === "writer" ? LIMITS.frameBytes : LIMITS.readerFrameBytes;
    if (tooLong(message, max)) return ws.close(CLOSE.tooLarge, "frame too large");

    let data: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(message);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
      data = parsed as Record<string, unknown>;
    } catch {
      return ws.close(att.authed ? CLOSE.badFrame : CLOSE.unauthorized, "bad frame");
    }

    if (!att.authed) {
      if (this.now() > att.openedAt + LIMITS.authTimeoutMs) return ws.close(CLOSE.unauthorized, "auth timeout");
      if (data.t !== "auth" || !isToken(data.token)) return ws.close(CLOSE.unauthorized, "unauthorized");
      if (data.phone !== undefined && (att.role !== "reader" || typeof data.phone !== "string" || !PHONE_RE.test(data.phone))) {
        return ws.close(CLOSE.unauthorized, "unauthorized");
      }
      const phone = typeof data.phone === "string" ? data.phone : undefined;
      const verdict = await this.verify(att.role, att.room, data.token, data.readHash, { phones: data.phones ?? "", phone, ck: att.ck });
      if (verdict === "not ready") return ws.close(CLOSE.notReady, "writer not registered yet");
      if (verdict === "too many rooms") return ws.close(CLOSE.tooMany, "too many new rooms");
      if (verdict !== "ok") return ws.close(CLOSE.unauthorized, "unauthorized");
      return this.authed(ws, att.role, att.room, phone, phone ? this.meta.phones?.[phone] : undefined);
    }
    if (data.t === "auth") return; // already authenticated
    if (!this.allow(ws, att.role === "writer" ? LIMITS.writerPerSecond : LIMITS.readerPerSecond)) return;

    // v1.1 (Miblo+): channels other than "status" and reader "up" frames need the plus plan.
    const plus = this.plan() === "plus";
    if (!plus && ((data.ch !== undefined && data.ch !== "status") || data.t === "up")) {
      return ws.close(CLOSE.plan, "plan");
    }

    if (att.role === "writer") {
      if (data.t === "msg") return this.relayFrame(data, ws);
      if (data.t === "push") return this.push(data.n);
      if (data.t === "phones") {
        const phones = parsePhones(data.list);
        if (phones) await this.updatePhones(phones);
        return;
      }
    } else if (data.t === "sub") {
      return this.subscribe(data.sub, data.lang);
    } else if (data.t === "up") {
      return this.relayUp(ws, data);
    }
    // Unknown frame types are ignored (forward compatibility).
  }

  async webSocketClose(ws: RoomSocket, code: number): Promise<void> {
    try {
      ws.close(code === 1005 || code === 1006 ? 1000 : code, "bye");
    } catch {
      // Already closed.
    }
    const att = this.attachment(ws);
    if (att?.role === "reader" && att.authed) this.presence(ws);
  }

  async webSocketError(): Promise<void> {}

  async alarm(): Promise<void> {
    const now = this.now();
    this.alarmAt = null;
    // The budget object: yesterday's counts go (keyed hashes); a network's room count lives for its
    // key's 30-day period.
    const today = utcDay(now);
    const old: string[] = [];
    for (const prefix of ["e:", "p:", "r:"]) {
      for (const [k, v] of await this.ctx.storage.list<{ day: number }>({ prefix })) {
        if (prefix === "r:" ? v.day < today - 31 : v.day < today) old.push(k);
      }
    }
    for (let i = 0; i < old.length; i += 128) await this.ctx.storage.delete(old.slice(i, i + 128));
    this.closeExpiredPending(now + ALARM_SLACK_MS);
    if (this.frameDirty && this.meta.readerEver && now >= this.persistedAt + LIMITS.persistIntervalMs) await this.persistFrame(now);
    if (this.frame && this.frame.at + LIMITS.frameTtlMs <= now) {
      const stored = this.persistedAt > 0;
      this.frame = undefined;
      this.frameDirty = false;
      this.persistedAt = 0;
      if (stored) await this.ctx.storage.delete("frame");
    }
    // Miblo+ lapsed on its own: the free plan's one phone applies at once.
    if (this.meta.plan === "plus" && this.plan() === "free") this.enforceFreeCap();
    const expiry = this.expiry();
    const anyoneHere = this.sockets().some((ws) => this.attachment(ws)?.authed);
    if (expiry !== null && expiry <= now && !anyoneHere) {
      await this.wipe();
      return;
    }
    const next = this.nextDeadline(now);
    if (next !== null) await this.scheduleAlarm(next, true);
  }

  // --- internals ---------------------------------------------------------------------------

  private sockets(tag?: Role): RoomSocket[] {
    return this.ctx.getWebSockets(tag).filter((ws) => ws.readyState === OPEN);
  }

  private attachment(ws: RoomSocket): Attachment | null {
    return (ws.deserializeAttachment() as Attachment | null) ?? null;
  }

  private closeExpiredPending(now: number): void {
    for (const ws of this.sockets()) {
      const att = this.attachment(ws);
      if (att && !att.authed && att.openedAt + LIMITS.authTimeoutMs <= now) ws.close(CLOSE.unauthorized, "auth timeout");
    }
  }

  private armAuthTimer(): void {
    if (this.authTimer) return;
    this.authTimer = setTimeout(() => {
      this.authTimer = null;
      this.closeExpiredPending(this.now());
      const pending = this.sockets().some((ws) => !this.attachment(ws)?.authed);
      if (pending) this.armAuthTimer();
    }, LIMITS.authTimeoutMs / 5);
  }

  /**
   * Checks a connection's credentials. The writer: its token must derive this room, and it must
   * name the read-token hash (registered, replacing an older one) and its enrolled phones (v5). A
   * new room counts against its network's daily limit ("too many rooms"). A reader: the writer
   * must have registered a hash ("not ready" before that); with `phone`, the token must match that
   * enrolled phone's own hash, else the shared read token's.
   */
  private async verify(
    role: Role,
    room: string,
    token: string,
    readHash: unknown,
    { phones, phone, ck }: { phones?: unknown; phone?: string; ck?: string } = {},
  ): Promise<"ok" | "unauthorized" | "not ready" | "too many rooms"> {
    if (role === "writer") {
      if (!isDigest(readHash)) return "unauthorized";
      const list = parsePhones(phones ?? "");
      if (!list) return "unauthorized";
      if (!sameString(await deriveRoom(token), room)) return "unauthorized";
      if (this.meta.createdAt === undefined) {
        if (!(await this.newRoomAllowed(ck))) return "too many rooms";
        if (ck) this.meta.nets = ck.split(",");
      }
      await this.registerWriter(readHash, await sha256B64url(token), list);
      return "ok";
    }
    const hash = await sha256B64url(token);
    const stored = this.meta.readHash;
    if (!stored) return "not ready";
    if (phone !== undefined) {
      const mine = this.meta.phones?.[phone];
      return mine && sameString(hash, mine) ? "ok" : "unauthorized";
    }
    return sameString(hash, stored) ? "ok" : "unauthorized";
  }

  private async registerWriter(readHash: string, writeKey: string, phones: Record<string, string>): Promise<void> {
    const now = this.now();
    const changed = this.meta.readHash !== readHash;
    const samePhones = JSON.stringify(this.meta.phones ?? {}) === JSON.stringify(phones);
    if (!changed && samePhones && this.meta.createdAt !== undefined && this.meta.writeKey === writeKey) return;
    if (changed && this.meta.readHash) {
      // New read token: guests holding the old one are out (enrolled phones use their own tokens).
      for (const r of this.sockets("reader")) if (!this.attachment(r)?.phone) r.close(CLOSE.unauthorized, "read token changed");
    }
    this.meta = { ...this.meta, readHash, writeKey, phones, createdAt: this.meta.createdAt ?? now, lastSeen: now };
    this.lastSeenWritten = now;
    this.closeUnlisted();
    await this.ctx.storage.put("meta", this.meta);
  }

  /** v5: the writer's current list of enrolled phones (one revoked, one added). */
  private async updatePhones(phones: Record<string, string>): Promise<void> {
    if (JSON.stringify(this.meta.phones ?? {}) === JSON.stringify(phones)) return;
    this.meta.phones = phones;
    this.closeUnlisted();
    await this.ctx.storage.put("meta", this.meta);
    this.presence();
  }

  /** A phone the writer no longer lists (revoked), or whose token changed, is closed at once. */
  private closeUnlisted(): void {
    for (const r of this.sockets("reader")) {
      const att = this.attachment(r);
      if (att?.phone && (!this.meta.phones?.[att.phone] || att.ph !== this.meta.phones[att.phone])) r.close(CLOSE.revoked, "phone revoked");
    }
  }

  private async authed(ws: RoomSocket, role: Role, room: string, phone?: string, ph?: string): Promise<void> {
    const now = this.now();
    const before = this.attachment(ws);
    ws.serializeAttachment({ role, authed: true, openedAt: now, room, ...(phone ? { phone, ph } : {}), ...(before?.ck ? { ck: before.ck } : {}) } satisfies Attachment);
    const peers = this.sockets(role).filter((s) => s !== ws && this.attachment(s)?.authed);
    if (role === "writer") {
      for (const old of peers) old.close(CLOSE.replaced, "replaced by a newer writer");
      await this.touch(now);
      this.presence();
      return;
    }
    const oldestFirst = (list: RoomSocket[]) => list.sort((a, b) => (this.attachment(a)?.openedAt ?? 0) - (this.attachment(b)?.openedAt ?? 0));
    // The plan caps distinct phones, enrolled identities included: on free (or a lapsed Miblo+) one
    // phone at a time, whatever it authenticated with; on Miblo+ LIMITS.maxReaders enrolled phones.
    const others = peers.filter((s) => !phone || this.attachment(s)?.phone !== phone);
    if (this.plan() === "free" && others.length >= LIMITS.maxReadersFree) {
      ws.close(CLOSE.readerLimit, "the free plan allows 1 phone");
      return;
    }
    if (phone) {
      const distinct = new Set(peers.map((s) => this.attachment(s)?.phone).filter((p): p is string => !!p && p !== phone));
      if (distinct.size >= LIMITS.maxReaders) {
        ws.close(CLOSE.readerLimit, "too many phones");
        return;
      }
    }
    if (phone) {
      // An enrolled phone only ever pushes out its own older sockets, never another phone.
      const mine = oldestFirst(peers.filter((s) => this.attachment(s)?.phone === phone));
      while (mine.length >= LIMITS.maxSocketsPerPhone) mine.shift()!.close(CLOSE.replaced, "a newer socket of this phone");
    } else {
      const guests = oldestFirst(peers.filter((s) => !this.attachment(s)?.phone));
      // Miblo+: guests (status only, or enrolling) have their own few places; the oldest goes.
      while (guests.length >= LIMITS.maxGuests) guests.shift()!.close(CLOSE.replaced, "too many readers");
    }
    this.presence();
    if (this.frame && this.frame.at + LIMITS.frameTtlMs > now) {
      ws.send(JSON.stringify({ t: "msg", ch: "status", iv: this.frame.iv, ct: this.frame.ct }));
    }
    if (!this.meta.readerEver) {
      this.meta.readerEver = true;
      await this.ctx.storage.put("meta", this.meta);
      await this.roomUsed();
      if (this.frameDirty) await this.persistFrame(now);
      await this.scheduleIdleAlarm();
    }
  }

  private allow(ws: RoomSocket, perSecond: number, counters = this.rate): boolean {
    const second = Math.floor(this.now() / 1000);
    const r = counters.get(ws);
    if (!r || r.second !== second) {
      counters.set(ws, { second, n: 1 });
      return true;
    }
    r.n += 1;
    return r.n <= perSecond;
  }

  /** The room's plan: "free" unless the account side set "plus" (and it has not lapsed). */
  protected plan(): Plan {
    if (this.meta.plan !== "plus") return "free";
    return this.meta.planUntil === undefined || this.now() < this.meta.planUntil ? "plus" : "free";
  }

  protected async setPlan(plan: Plan, until?: number): Promise<void> {
    this.meta.plan = plan;
    if (plan === "plus" && until !== undefined) this.meta.planUntil = until;
    else delete this.meta.planUntil;
    await this.ctx.storage.put("meta", this.meta);
    if (this.plan() === "free") this.enforceFreeCap();
    else if (this.meta.planUntil !== undefined) await this.scheduleAlarm(this.meta.planUntil);
  }

  /**
   * The room is free (set so, or Miblo+ lapsed): one phone at a time from now on, not only for the
   * next connection. The oldest phone stays (all of its own sockets); every other reader is closed
   * with 4406 and retries later.
   */
  private enforceFreeCap(): void {
    const readers = this.sockets("reader").filter((r) => this.attachment(r)?.authed);
    readers.sort((a, b) => (this.attachment(a)?.openedAt ?? 0) - (this.attachment(b)?.openedAt ?? 0));
    const first = readers[0];
    if (!first) return;
    const keep = this.attachment(first)?.phone;
    let changed = false;
    for (const r of readers.slice(1)) {
      if (keep && this.attachment(r)?.phone === keep) continue;
      r.close(CLOSE.readerLimit, "the free plan allows 1 phone");
      changed = true;
    }
    if (changed) this.presence();
  }

  /**
   * Miblo+ plan call from the account side (docs/miblo-plus.md, "Room plan"):
   *   {"op":"claim","challenge","proof","plan","until"} checks the computer's proof first:
   *     proof = base64url(HMAC-SHA256(key = SHA-256(writeToken), challenge)); 403 when wrong.
   *   {"op":"set","plan","until"} only changes the plan.
   * 409 when no writer has registered the room yet (nothing to attach a plan to).
   */
  private async plusRequest(request: Request): Promise<Response> {
    if (request.method !== "POST") return new Response("method not allowed", { status: 405 });
    let body: { op?: unknown; plan?: unknown; until?: unknown; challenge?: unknown; proof?: unknown; account?: unknown };
    try {
      body = (await request.json()) as typeof body;
    } catch {
      return new Response("bad request", { status: 400 });
    }
    const plan = body.plan === "plus" ? "plus" : body.plan === "free" ? "free" : null;
    const until = body.until === undefined || body.until === null ? undefined : Number(body.until);
    if (!plan || (until !== undefined && !Number.isFinite(until))) return new Response("bad request", { status: 400 });
    if (body.op === "claim") {
      if (typeof body.challenge !== "string" || body.challenge.length > 512 || typeof body.proof !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(body.proof)) {
        return new Response("bad request", { status: 400 });
      }
      if (!this.meta.writeKey || this.meta.createdAt === undefined) return new Response("not ready", { status: 409 });
      const key = await crypto.subtle.importKey("raw", base64urlDecode(this.meta.writeKey), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
      const ok = await crypto.subtle.verify("HMAC", key, base64urlDecode(body.proof), new TextEncoder().encode(body.challenge));
      if (!ok) return new Response("bad proof", { status: 403 });
    } else if (body.op !== "set") {
      return new Response("bad request", { status: 400 });
    } else if (this.meta.createdAt === undefined) {
      // A wiped (or never used) room keeps no plan: the computer claims it again when it is back.
      return new Response("not ready", { status: 409 });
    }
    if (typeof body.account === "string" && /^[A-Za-z0-9_-]{22}$/.test(body.account)) this.meta.account = body.account;
    await this.setPlan(plan, until);
    return Response.json({ plan: this.plan(), until: this.meta.planUntil ?? null });
  }

  /**
   * v3: tells the writer how many phones are connected ({"t":"presence","readers":n}, metadata the
   * relay has anyway). The computer only waits for a phone's approval while one is connected.
   * `leaving`: a reader socket that is closing and must not be counted.
   */
  private presence(leaving?: RoomSocket): void {
    const here = this.sockets("reader").filter((r) => r !== leaving && this.attachment(r)?.authed);
    // v5: and which enrolled phones they are (the writer sends a phone what it missed).
    const phones = [...new Set(here.map((r) => this.attachment(r)?.phone).filter((p): p is string => !!p))];
    const out = JSON.stringify({ t: "presence", readers: here.length, phones });
    for (const writer of this.sockets("writer")) {
      if (!this.attachment(writer)?.authed) continue;
      try {
        writer.send(out);
      } catch {
        // Closing.
      }
    }
  }

  private async relayFrame(data: Record<string, unknown>, ws?: RoomSocket): Promise<void> {
    if (!isMsgFrame(data)) return;
    if (!fitsChannel(data)) {
      ws?.close(CLOSE.tooLarge, "frame too large for its channel");
      return;
    }
    const now = this.now();
    const channel = data.ch ?? "status";
    const readers = this.sockets("reader").filter((r) => this.attachment(r)?.authed);
    if (channel === "status" && data.to) {
      // v5: a status-channel frame sealed to some phones (new status keys after a revoke): allowed on
      // every plan, forwarded to the named phones only, never kept as the room's last frame.
      const to = sealedTo(data.to)!;
      for (const reader of readers) {
        const phone = this.attachment(reader)?.phone;
        if (phone && to[phone]) reader.send(JSON.stringify({ t: "msg", ch: "status", iv: data.iv, ct: data.ct, k: to[phone] }));
      }
      await this.touch(now);
      return;
    }
    if (channel === "status") {
      const out = JSON.stringify(data.ch ? { t: "msg", ch: data.ch, iv: data.iv, ct: data.ct } : { t: "msg", iv: data.iv, ct: data.ct });
      for (const reader of readers) reader.send(out);
    } else if (data.to) {
      // v5: sealed per phone: each named phone gets its own wrap of the key, nobody else anything.
      const to = sealedTo(data.to)!;
      for (const reader of readers) {
        const phone = this.attachment(reader)?.phone;
        if (phone && to[phone]) reader.send(JSON.stringify({ t: "msg", ch: channel, iv: data.iv, ct: data.ct, k: to[phone] }));
      }
    } else if (data.g === 1) {
      // v5: an answer to an enrollment (sealed under the pairing window's key): to guests only.
      const out = JSON.stringify({ t: "msg", ch: channel, g: 1, iv: data.iv, ct: data.ct });
      for (const reader of readers) if (!this.attachment(reader)?.phone) reader.send(out);
    }
    // Any other Miblo+ frame names nobody: dropped.
    await this.touch(now);
    // Only the live status is retained for late joiners; other channels are never stored.
    if (channel !== "status") return;
    this.frame = { iv: data.iv, ct: data.ct, at: now };
    this.frameDirty = true;
    if (!this.meta.readerEver) return; // nobody to show it to later: memory only
    if (now >= this.persistedAt + LIMITS.persistIntervalMs) await this.persistFrame(now);
    else await this.scheduleAlarm(this.persistedAt + LIMITS.persistIntervalMs);
  }

  private async persistFrame(now: number): Promise<void> {
    if (!this.frame) return;
    this.frameDirty = false;
    this.persistedAt = now;
    await this.ctx.storage.put("frame", this.frame);
    await this.scheduleAlarm(this.frame.at + LIMITS.frameTtlMs);
  }

  /**
   * A reader's encrypted frame, forwarded to the writer as is (never stored; dropped when the
   * writer is not connected). v3: it must name a Miblo+ channel, fit that channel's cap (else 1009)
   * and stay within 1 per second and the channel's per-minute budget (extra ones are dropped).
   */
  private relayUp(ws: RoomSocket, data: Record<string, unknown>): void {
    if (!isMsgFrame(data, "up")) return;
    const ch = data.ch ?? "status";
    if (CT_MAX.up[ch] === undefined) return;
    if (!fitsChannel(data)) return ws.close(CLOSE.tooLarge, "frame too large for its channel");
    const phone = this.attachment(ws)?.phone;
    // v5: a guest (no phone identity) may only enroll, on the approval channel, a few times a minute.
    if (!phone && ch !== "approval") return;
    if (!this.allow(ws, LIMITS.upPerSecond, this.upRate) || !this.allowMinute(ws, ch, phone ? undefined : LIMITS.guestUpPerMinute)) return;
    // The writer learns which enrolled phone sent it (`p`, the phone this socket authenticated as).
    const out = JSON.stringify({ t: "up", ...(data.ch ? { ch: data.ch } : {}), iv: data.iv, ct: data.ct, ...(phone ? { p: phone } : {}) });
    for (const writer of this.sockets("writer")) {
      if (this.attachment(writer)?.authed) writer.send(out);
    }
  }

  private allowMinute(ws: RoomSocket, ch: string, cap?: number): boolean {
    const max = cap ?? UP_PER_MINUTE[ch as keyof typeof UP_PER_MINUTE];
    if (max === undefined) return false;
    const minute = Math.floor(this.now() / 60_000);
    let per = this.upMinute.get(ws);
    if (!per) this.upMinute.set(ws, (per = new Map()));
    const r = per.get(ch);
    if (!r || r.minute !== minute) {
      per.set(ch, { minute, n: 1 });
      return true;
    }
    r.n += 1;
    return r.n <= max;
  }

  /** Records writer activity for the idle cleanup (written at most once an hour). */
  private async touch(now: number): Promise<void> {
    this.meta.lastSeen = now;
    if (now - this.lastSeenWritten >= HOUR) {
      this.lastSeenWritten = now;
      await this.ctx.storage.put("meta", this.meta);
    }
    await this.scheduleIdleAlarm();
  }

  /** When the room is deleted: 24 h after creation if no reader ever joined, else 30 days idle. */
  private expiry(): number | null {
    if (this.meta.createdAt === undefined) return null;
    if (!this.meta.readerEver) return this.meta.createdAt + LIMITS.noReaderTtlMs;
    return (this.meta.lastSeen ?? this.meta.createdAt) + LIMITS.idleMs;
  }

  private async scheduleIdleAlarm(): Promise<void> {
    const at = this.expiry();
    if (at !== null) await this.scheduleAlarm(Math.max(at, this.now() + 1));
  }

  private async push(n: unknown): Promise<void> {
    if (typeof n !== "number" || !Number.isInteger(n) || n < 0 || n > 10_000) return;
    const now = this.now();
    const previous = this.meta.pushN ?? 0;
    const day = utcDay(now);
    const usedToday = this.meta.pushDay === day ? (this.meta.pushCount ?? 0) : 0;
    const due =
      n > previous &&
      usedToday < LIMITS.pushesPerRoomPerDay &&
      (this.meta.pushAt === undefined || now - this.meta.pushAt >= LIMITS.pushIntervalMs);
    this.meta.pushN = n;
    if (due) Object.assign(this.meta, { pushAt: now, pushDay: day, pushCount: usedToday + 1 });
    if (n !== previous || due) await this.ctx.storage.put("meta", this.meta);
    if (due) await this.sendPushes();
  }

  private vapid(): VapidKeys | null {
    const { RELAY_VAPID_PUBLIC_KEY: publicKey, RELAY_VAPID_PRIVATE_KEY: privateKey } = this.env;
    return publicKey && privateKey ? { publicKey, privateKey } : null;
  }

  /** The budget object (the rooms' namespace, one object): null when unavailable. */
  private budgetStub(): RoomStub | null {
    const ns = this.env.RELAY;
    return ns ? ns.get(ns.idFromName(PUSH_BUDGET_OBJECT)) : null;
  }

  /**
   * Asks the budget object which of these endpoints (hashes) may get a push now, charging them to
   * `pool`, to each endpoint and to the room's payers (the Miblo+ account; for a free room each tier
   * of the network that created it, with the room's own small daily fallback so neighbours behind
   * one address cannot silence it). -> the allowed hashes ([] when spent or unavailable).
   */
  private async takeBudget(pool: Plan, payers: string[], fallback: string, endpoints: string[]): Promise<Map<string, "p" | "f">> {
    const stub = this.budgetStub();
    const out = new Map<string, "p" | "f">();
    if (!stub || !endpoints.length) return out;
    try {
      const q = `op=take&pool=${pool}&payers=${encodeURIComponent(payers.join(","))}&fallback=${encodeURIComponent(fallback)}&e=${endpoints.join(",")}`;
      const res = await stub.fetch(`https://relay.internal${BUDGET_PATH}?${q}`);
      if (!res.ok) return out;
      const got = (await res.json()) as { allowed?: unknown; paths?: Record<string, unknown> };
      for (const h of Array.isArray(got.allowed) ? got.allowed : []) {
        if (typeof h === "string" && endpoints.includes(h)) out.set(h, got.paths?.[h] === "f" ? "f" : "p");
      }
      return out;
    } catch {
      return out;
    }
  }

  /**
   * Gives back deliveries that did not go out (refused by the push service, or failed), to exactly
   * whom they were charged: `byPayers` to the payers, `byFallback` to the room's fallback (and the
   * networks' fallback quotas).
   */
  private async refundBudget(pool: Plan, payers: string[], fallback: string, byPayers: number, byFallback: number): Promise<void> {
    const stub = this.budgetStub();
    if (!stub) return;
    const nets = payers.filter((x) => x.startsWith("n"));
    const send = async (who: string[], n: number) => {
      if (n < 1 || !who.length) return;
      await stub.fetch(`https://relay.internal${BUDGET_PATH}?op=refund&pool=${pool}&payers=${encodeURIComponent(who.join(","))}&n=${n}`);
    };
    try {
      await send(payers, byPayers);
      await send([fallback, ...nets.map((x) => `f${x.slice(1)}`)].filter(Boolean), byFallback);
    } catch {
      // Lost: the day's budget is a little smaller; it resets at midnight UTC.
    }
  }

  /**
   * A new room: each tier of its network (keyed hashes the router passed, never an IP) must be under
   * its daily and 30-day caps (TIER_CAPS). Without keys (tests, internal calls) or a budget object,
   * allowed.
   */
  private async newRoomAllowed(ck: string | undefined): Promise<boolean> {
    const stub = this.budgetStub();
    if (!ck || !stub) return true;
    try {
      return (await stub.fetch(`https://relay.internal${BUDGET_PATH}?op=room&k=${encodeURIComponent(ck)}`)).ok;
    } catch {
      return true;
    }
  }

  /** The first phone joined: the room now counts against its networks' period caps. */
  private async roomUsed(): Promise<void> {
    const stub = this.budgetStub();
    if (!stub || !this.meta.nets?.length) return;
    try {
      await stub.fetch(`https://relay.internal${BUDGET_PATH}?op=used&k=${encodeURIComponent(this.meta.nets.join(","))}`);
    } catch {
      // Lost: the networks' period counts stay a little lower.
    }
  }

  /** A room wiped before any phone joined it: its networks get that day's slot back (it never served anyone). */
  private async returnRoom(): Promise<void> {
    const stub = this.budgetStub();
    if (!stub || !this.meta.nets?.length || this.meta.readerEver) return;
    try {
      await stub.fetch(`https://relay.internal${BUDGET_PATH}?op=unroom&k=${encodeURIComponent(this.meta.nets.join(","))}`);
    } catch {
      // Lost: the networks' counts stay a little higher until the period ends.
    }
  }

  /**
   * The budget object's side, in its own storage (everything per UTC day): "budget" {day, free,
   * plus, alerted} for the pools, "p:<pool>:<payer>" and "e:<endpoint hash>" {day, n} for payers and
   * endpoints, "r:<tier>:<network key>" {day, n, total} for new rooms: n made today, total joined by
   * a phone in the key's period (the key changes every 30 days).
   */
  private async budgetRequest(url: URL, request: Request): Promise<Response> {
    if (request.headers.get("Upgrade")) return new Response("bad request", { status: 400 });
    const op = url.searchParams.get("op") ?? "take";
    const day = utcDay(this.now());
    await this.scheduleAlarm((day + 1) * DAY + 60_000);
    type Count = { day: number; n: number };
    const count = async (key: string) => {
      const got = await this.ctx.storage.get<Count>(key);
      return got?.day === day ? got.n : 0;
    };
    if (op === "room" || op === "unroom" || op === "used") {
      const k = url.searchParams.get("k") ?? "";
      if (!NET_KEYS_RE.test(k)) return new Response("bad key", { status: 400 });
      const tiers = k.split(",").map((pair) => {
        const [tier, key] = pair.split(":");
        return { tier, key: `r:${tier}:${key}`, cap: TIER_CAPS[tier] };
      });
      const rows = await Promise.all(tiers.map(async (t) => ({ ...t, got: await this.ctx.storage.get<{ day: number; n: number; total: number }>(t.key) })));
      if (op === "unroom") {
        // Never joined: today's slot back (an older day's has expired anyway).
        for (const r of rows) {
          if (r.got?.day === day) await this.ctx.storage.put(r.key, { ...r.got, n: Math.max(0, r.got.n - 1) });
        }
        return new Response("ok");
      }
      if (op === "used") {
        for (const r of rows) await this.ctx.storage.put(r.key, { day: r.got?.day ?? day, n: r.got?.n ?? 0, total: (r.got?.total ?? 0) + 1 });
        return new Response("ok");
      }
      for (const r of rows) {
        const today = r.got?.day === day ? r.got.n : 0;
        if (today >= r.cap.day || (r.cap.period !== null && (r.got?.total ?? 0) >= r.cap.period)) return new Response("too many rooms", { status: 429 });
      }
      for (const r of rows) await this.ctx.storage.put(r.key, { day, n: (r.got?.day === day ? r.got.n : 0) + 1, total: r.got?.total ?? 0 });
      return new Response("ok");
    }
    const pool: Plan = url.searchParams.get("pool") === "plus" ? "plus" : "free";
    const payers = (url.searchParams.get("payers") ?? "").split(",").filter((x) => /^(a|n0|n4|n64|n56|n48|f0|f4|f64|f56|f48|r):[A-Za-z0-9_-]{1,64}$/.test(x)).slice(0, 4);
    type Budget = { day: number; free: number; plus: number; alerted: string[] };
    const got = await this.ctx.storage.get<Budget>("budget");
    const b: Budget = got?.day === day ? { day, free: got.free ?? 0, plus: got.plus ?? 0, alerted: got.alerted ?? [] } : { day, free: 0, plus: 0, alerted: [] };
    const cap = pool === "plus" ? LIMITS.pushesPlusPerDay : LIMITS.pushesFreePerDay;
    const capOf = (payer: string) =>
      payer.startsWith("a:") ? LIMITS.pushesPerAccountPerDay : payer.startsWith("r:") ? ROOM_FALLBACK_PUSHES
        : payer.startsWith("f") ? FALLBACK_FACTOR * (TIER_CAPS[payer.slice(1, payer.indexOf(":"))]?.pushes ?? 0)
        : (TIER_CAPS[payer.slice(1, payer.indexOf(":"))]?.pushes ?? 0);
    if (op === "refund") {
      const n = Number(url.searchParams.get("n"));
      if (!Number.isInteger(n) || n < 1 || n > LIMITS.maxSubscriptions) return new Response("bad n", { status: 400 });
      // The pool is refunded once per delivery: only with the call that names the deliveries' first payer.
      if (!payers[0]?.startsWith("f")) b[pool] = Math.max(0, b[pool] - n);
      await this.ctx.storage.put("budget", b);
      for (const payer of payers) await this.ctx.storage.put(`p:${pool}:${payer}`, { day, n: Math.max(0, (await count(`p:${pool}:${payer}`)) - n) });
      return new Response("ok");
    }
    const fallback = url.searchParams.get("fallback") ?? "";
    const hasFallback = /^r:[A-Za-z0-9_-]{1,64}$/.test(fallback);
    if (!payers.length && !hasFallback) return new Response("bad payer", { status: 400 });
    const endpoints = (url.searchParams.get("e") ?? "").split(",").filter((h) => /^[0-9a-f]{32}$/.test(h)).slice(0, LIMITS.maxSubscriptions);
    if (!endpoints.length) return new Response("bad endpoints", { status: 400 });
    // A free room's fallback is also charged to its networks' fallback quotas, so it cannot grow with
    // the number of rooms a network keeps.
    const netFallbacks = payers.filter((x) => x.startsWith("n")).map((x) => `f${x.slice(1)}`);
    const fallbackPayers = hasFallback ? [fallback, ...netFallbacks] : [];
    const paid = new Map<string, number>();
    for (const payer of [...payers, ...fallbackPayers]) paid.set(payer, await count(`p:${pool}:${payer}`));
    const allowed: string[] = [];
    const paths: Record<string, "p" | "f"> = {};
    for (const h of endpoints) {
      if (b[pool] >= cap) {
        await this.alert(b, pool, "spent", cap);
        break;
      }
      const sent = await count(`e:${h}`);
      // One endpoint gets a few dozen a day, however many rooms hold it (in its one spelling).
      if (sent >= LIMITS.pushesPerEndpointPerDay) continue;
      // Every payer under its quota, or else the room's own small fallback.
      const viaPayers = payers.length > 0 && payers.every((x) => paid.get(x)! < capOf(x));
      const viaFallback = !viaPayers && hasFallback && fallbackPayers.every((x) => paid.get(x)! < capOf(x));
      if (!viaPayers && !viaFallback) break;
      for (const x of viaPayers ? payers : fallbackPayers) paid.set(x, paid.get(x)! + 1);
      await this.ctx.storage.put(`e:${h}`, { day, n: sent + 1 });
      allowed.push(h);
      paths[h] = viaPayers ? "p" : "f";
      b[pool] += 1;
    }
    if (b[pool] >= cap * LIMITS.pushAlertShare) await this.alert(b, pool, "high", cap);
    await this.ctx.storage.put("budget", b);
    for (const [x, n] of paid) await this.ctx.storage.put(`p:${pool}:${x}`, { day, n });
    return Response.json({ allowed, paths });
  }

  /**
   * Once a day per pool and level, a warning in the Worker's logs (Cloudflare observability): the
   * push budget is running out, or ran out (someone may be flooding it). No room, IP or content.
   */
  private async alert(b: { alerted: string[]; day: number }, pool: Plan, level: "high" | "spent", cap: number): Promise<void> {
    const tag = `${pool}:${level}`;
    if (b.alerted.includes(tag)) return;
    b.alerted.push(tag);
    await this.ctx.storage.put("budget", b);
    console.warn(JSON.stringify({ event: "relay_push_budget", pool, level, cap, day: b.day }));
  }

  private async sendPushes(): Promise<void> {
    const keys = this.vapid();
    // Only a room a phone has really joined, and only subscriptions a phone re-sent recently.
    if (!keys || !this.meta.readerEver) return;
    const now = this.now();
    const all = [...(await this.ctx.storage.list<StoredSub>({ prefix: "sub:" }))];
    const stale = all.filter(([, v]) => now - v.at > LIMITS.subscriptionFreshMs).map(([k]) => k);
    if (stale.length) await this.ctx.storage.delete(stale);
    const subs = all.filter(([, v]) => now - v.at <= LIMITS.subscriptionFreshMs);
    const pool = this.plan();
    // Who pays: the Miblo+ account; for a free room each tier of the network that created it, with
    // the room's own small fallback.
    const fallback = `r:${this.ctx.id.toString().slice(0, 40)}`;
    const nets = (this.meta.nets ?? []).map((x) => `n${x}`);
    const payers = pool === "plus" && this.meta.account ? [`a:${this.meta.account}`] : nets.length ? nets : [`n0:${fallback.slice(2)}`];
    const fb = pool === "plus" && this.meta.account ? "" : fallback;
    const allowed = await this.takeBudget(pool, payers, fb, subs.map(([k]) => k.slice(4)));
    const going = subs.filter(([k]) => allowed.has(k.slice(4)));
    if (!going.length) return;
    const subject = this.env.RELAY_VAPID_SUBJECT || this.env.PUBLIC_ORIGIN || "";
    if (!subject) return;
    const failed = { p: 0, f: 0 };
    await Promise.all(
      going.map(async ([key, stored]) => {
        const path = allowed.get(key.slice(4)) ?? "p";
        try {
          const res = await sendPush(stored.sub, needsYouNotification(stored.lang), keys, { subject, ttl: 3600, topic: "needs-you" });
          if (res.gone) await this.ctx.storage.delete(key);
          if (res.status < 200 || res.status >= 300) failed[path] += 1;
        } catch {
          // A failing push service must not break the room; the next push retries.
          failed[path] += 1;
        }
      }),
    );
    // Only deliveries the push service accepted are spent, each given back to whom it was charged.
    await this.refundBudget(pool, payers, fb, failed.p, failed.f);
  }

  private async subscribe(raw: unknown, lang: unknown): Promise<void> {
    const sub = parseSubscription(raw);
    // The key must be a real P-256 point (made-up subscriptions are refused here, not at send time).
    if (!sub || !(await validPushKey(sub.keys.p256dh))) return;
    // Keyed by what identifies the subscription (Windows: its token), so spellings cannot multiply it.
    const key = `sub:${(await sha256Hex(endpointIdentity(sub.endpoint))).slice(0, 32)}`;
    const isNew = (await this.ctx.storage.get(key)) === undefined;
    await this.ctx.storage.put(key, { sub, lang: pushLang(lang), at: this.now() } satisfies StoredSub);
    if (!isNew) return;
    const all = [...(await this.ctx.storage.list<StoredSub>({ prefix: "sub:" }))].sort((a, b) => a[1].at - b[1].at);
    // About one per phone the plan allows: the newest stay.
    const cap = this.plan() === "plus" ? LIMITS.maxSubscriptions : LIMITS.maxSubscriptionsFree;
    const extra = all.length - cap;
    if (extra > 0) await this.ctx.storage.delete(all.slice(0, extra).map(([k]) => k));
  }

  /** 204 with the room's write token (idempotent), 401 otherwise: existence is never revealed. */
  private async wipeRequest(request: Request, room: string): Promise<Response> {
    const token = bearerToken(request.headers.get("Authorization"));
    if (!token || !sameString(await deriveRoom(token), room)) return new Response("unauthorized", { status: 401 });
    await this.wipe();
    return new Response(null, { status: 204 });
  }

  private async wipe(): Promise<void> {
    await this.returnRoom();
    for (const ws of this.ctx.getWebSockets()) {
      try {
        ws.close(CLOSE.roomDeleted, "room deleted");
      } catch {
        // Already closing.
      }
    }
    this.meta = {};
    this.frame = undefined;
    this.frameDirty = false;
    this.persistedAt = 0;
    this.alarmAt = null;
    this.lastSeenWritten = 0;
    await this.ctx.storage.deleteAlarm();
    await this.ctx.storage.deleteAll();
  }

  private nextDeadline(now: number): number | null {
    const deadlines: number[] = [];
    for (const ws of this.sockets()) {
      const att = this.attachment(ws);
      if (att && !att.authed) deadlines.push(att.openedAt + LIMITS.authTimeoutMs);
    }
    if (this.frameDirty && this.meta.readerEver) deadlines.push(this.persistedAt + LIMITS.persistIntervalMs);
    if (this.frame && this.persistedAt) deadlines.push(this.frame.at + LIMITS.frameTtlMs);
    if (this.meta.plan === "plus" && this.meta.planUntil !== undefined && this.meta.planUntil > now) deadlines.push(this.meta.planUntil);
    const expiry = this.expiry();
    // Someone is still connected past the expiry: look again in a day.
    if (expiry !== null) deadlines.push(expiry <= now ? now + DAY : expiry);
    return deadlines.length ? Math.max(now + 1, Math.min(...deadlines)) : null;
  }

  /** Moves the alarm earlier (never later, unless `replace`): one alarm serves every deadline. */
  private async scheduleAlarm(at: number, replace = false): Promise<void> {
    if (!replace && this.alarmAt !== null && this.alarmAt <= at) return;
    this.alarmAt = at;
    await this.ctx.storage.setAlarm(at);
  }
}
