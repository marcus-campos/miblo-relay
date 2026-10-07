// The relay rooms on Node: the Durable Object API the room uses (state, storage, alarms, the
// hibernatable WebSocket API), provided in process over SQLite and the `ws` library, so the very
// same RelayRoom class runs here and on Cloudflare.
//
// - One RelayRoom per room name, made on first use and kept while it has sockets or recent work.
// - Every event of a room (a request, a message, a close, an alarm) runs one at a time, in order,
//   like a Durable Object's input gate.
// - Storage: one row per key in room_kv (JSON values); the alarm in room_alarms, re-armed at start.
// - Upgrades: the room answers an accepted upgrade with a 200 carrying `x-miblo-upgrade: <token>`;
//   the HTTP server completes the WebSocket handshake for that token and binds the socket. What the
//   room sent before that is queued and delivered first.
import crypto from "node:crypto";
import type { WebSocket } from "ws";
import { RelayRoom, type RelayEnv, type RoomRuntime, type RoomSocket, type RoomState, type RoomStorage } from "../core/relay/room";
import type { RoomNamespace, RoomStub } from "../core/env";
import type { SqliteDb } from "./sqlite-db";

const OPEN = 1;
const CLOSED = 3;
/** setTimeout's longest delay; later alarms are re-armed when it fires. */
const MAX_TIMER_MS = 2 **31 - 1;
/** A room without sockets, timers or work for this long leaves memory (its storage stays). */
const IDLE_EVICT_MS = 10 * 60_000;

/** A queue that runs one task at a time (a room's input gate). */
class Gate {
  private tail: Promise<unknown> = Promise.resolve();
  run<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.tail.then(fn, fn);
    this.tail = next.catch(() => {});
    return next;
  }
}

/** A room's end of a WebSocket, before and after the handshake completes. */
export class NodeRoomSocket implements RoomSocket {
  readyState = OPEN;
  tags: string[] = [];
  private attachment: unknown = null;
  private ws: WebSocket | null = null;
  private queued: string[] = [];
  private closeAfterBind: { code?: number; reason?: string } | null = null;

  constructor(
    readonly token: string,
    private readonly host: NodeRoomHost,
  ) {}

  serializeAttachment(value: unknown): void {
    this.attachment = value === undefined ? null : JSON.parse(JSON.stringify(value));
  }
  deserializeAttachment(): unknown {
    return this.attachment === null ? null : JSON.parse(JSON.stringify(this.attachment));
  }
  send(data: string): void {
    if (this.readyState !== OPEN) throw new Error("WebSocket is not open");
    if (!this.ws) this.queued.push(data);
    else this.ws.send(data);
  }
  close(code?: number, reason?: string): void {
    if (this.readyState === CLOSED) return;
    this.readyState = 2;
    if (!this.ws) {
      this.closeAfterBind = { code, reason };
      return;
    }
    try {
      this.ws.close(validCode(code), (reason ?? "").slice(0, 120));
    } catch {
      this.ws.terminate();
    }
  }

  /** The handshake completed: what was queued goes first, then the socket's events reach the room. */
  bind(ws: WebSocket): void {
    const { ping, pong } = this.host;
    this.ws = ws;
    for (const m of this.queued) ws.send(m);
    this.queued = [];
    ws.on("message", (data, isBinary) => {
      if (this.readyState === CLOSED) return;
      const text = isBinary ? null : data.toString();
      // The keep-alive is answered without waking the room (Cloudflare's auto response).
      if (text !== null && ping !== null && pong !== null && text === ping) {
        if (this.readyState === OPEN) ws.send(pong);
        return;
      }
      const message: string | ArrayBuffer = text ?? toArrayBuffer(data);
      void this.host.event((room) => room.webSocketMessage(this, message));
    });
    ws.on("close", (code) => this.closed(code));
    ws.on("error", () => this.closed(1006));
    if (this.closeAfterBind) {
      const c = this.closeAfterBind;
      this.closeAfterBind = null;
      try {
        ws.close(validCode(c.code), (c.reason ?? "").slice(0, 120));
      } catch {
        ws.terminate();
      }
    }
  }

  /** The handshake never completed (the client went away). */
  abandon(): void {
    this.closed(1006);
  }

  private closed(code: number): void {
    if (this.readyState === CLOSED) return;
    this.readyState = CLOSED;
    this.host.forget(this);
    void this.host.event((room) => room.webSocketClose(this, code));
  }
}

function validCode(code?: number): number {
  if (code === undefined) return 1000;
  return code === 1000 || (code >= 3000 && code <= 4999) || (code >= 1001 && code <= 1014 && code !== 1004 && code !== 1005 && code !== 1006) ? code : 1000;
}

function toArrayBuffer(data: unknown): ArrayBuffer {
  const buf = Buffer.isBuffer(data) ? data : Array.isArray(data) ? Buffer.concat(data as Buffer[]) : Buffer.from(data as ArrayBuffer);
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}

class SqliteRoomStorage implements RoomStorage {
  constructor(
    private readonly db: SqliteDb,
    private readonly name: string,
    private readonly onAlarm: (at: number | null) => void,
  ) {}
  get<T>(key: string): Promise<T | undefined>;
  get<T>(keys: string[]): Promise<Map<string, T>>;
  async get<T>(key: string | string[]): Promise<T | undefined | Map<string, T>> {
    const one = (k: string) => {
      const row = this.db.stmt("SELECT value FROM room_kv WHERE room = ? AND key = ?").get(this.name, k) as { value: string } | undefined;
      return row ? (JSON.parse(row.value) as T) : undefined;
    };
    if (Array.isArray(key)) {
      const out = new Map<string, T>();
      for (const k of key) {
        const v = one(k);
        if (v !== undefined) out.set(k, v);
      }
      return out;
    }
    return one(key);
  }
  async put(key: string, value: unknown): Promise<void> {
    this.db.stmt("INSERT INTO room_kv (room, key, value) VALUES (?, ?, ?) ON CONFLICT(room, key) DO UPDATE SET value = excluded.value").run(this.name, key, JSON.stringify(value));
  }
  async delete(keys: string | string[]): Promise<unknown> {
    const list = Array.isArray(keys) ? keys : [keys];
    let n = 0;
    for (const k of list) n += Number(this.db.stmt("DELETE FROM room_kv WHERE room = ? AND key = ?").run(this.name, k).changes);
    return Array.isArray(keys) ? n : n > 0;
  }
  async list<T>({ prefix }: { prefix: string }): Promise<Map<string, T>> {
    const rows = this.db.stmt("SELECT key, value FROM room_kv WHERE room = ? AND substr(key, 1, ?) = ? ORDER BY key").all(this.name, prefix.length, prefix) as { key: string; value: string }[];
    return new Map(rows.map((r) => [r.key, JSON.parse(r.value) as T]));
  }
  async deleteAll(): Promise<void> {
    this.db.stmt("DELETE FROM room_kv WHERE room = ?").run(this.name);
  }
  async getAlarm(): Promise<number | null> {
    const row = this.db.stmt("SELECT at FROM room_alarms WHERE room = ?").get(this.name) as { at: number } | undefined;
    return row ? Number(row.at) : null;
  }
  async setAlarm(at: number): Promise<void> {
    this.db.stmt("INSERT INTO room_alarms (room, at) VALUES (?, ?) ON CONFLICT(room) DO UPDATE SET at = excluded.at").run(this.name, Math.floor(at));
    this.onAlarm(Math.floor(at));
  }
  async deleteAlarm(): Promise<void> {
    this.db.stmt("DELETE FROM room_alarms WHERE room = ?").run(this.name);
    this.onAlarm(null);
  }
}

/** One room in memory: its state, its gate, its sockets and its alarm timer. */
export class NodeRoomHost {
  readonly gate = new Gate();
  readonly sockets = new Set<NodeRoomSocket>();
  room: RelayRoom;
  private timer: NodeJS.Timeout | null = null;
  ping: string | null = null;
  pong: string | null = null;
  lastUsed = Date.now();
  busy = 0;

  constructor(
    readonly name: string,
    private readonly ns: NodeRooms,
  ) {
    const storage = new SqliteRoomStorage(ns.db, name, (at) => this.armAlarm(at));
    const host = this;
    const state: RoomState = {
      id: { toString: () => crypto.createHash("sha256").update(`miblo-room-id|${name}`).digest("hex") },
      storage,
      blockConcurrencyWhile: <T>(fn: () => Promise<T>) => host.gate.run(fn),
      acceptWebSocket: (ws: RoomSocket, tags: string[] = []) => {
        const s = ws as NodeRoomSocket;
        s.tags = tags;
        host.sockets.add(s);
      },
      getWebSockets: (tag?: string) => [...host.sockets].filter((s) => s.readyState !== CLOSED && (tag === undefined || s.tags.includes(tag))),
    };
    const runtime: RoomRuntime = {
      upgrade: () => {
        const token = crypto.randomBytes(18).toString("base64url");
        const server = new NodeRoomSocket(token, host);
        ns.pending.set(token, { socket: server, host, at: Date.now() });
        return { server, response: new Response(null, { status: 200, headers: { "x-miblo-upgrade": token } }) };
      },
      autoPong: (_state, ping, pong) => {
        host.ping = ping;
        host.pong = pong;
      },
    };
    this.room = new ns.RoomClass(state, ns.env, runtime);
    // A pending alarm from before a restart.
    void storage.getAlarm().then((at) => this.armAlarm(at));
  }

  /** Runs one event of this room behind its gate. */
  event<T>(fn: (room: RelayRoom) => Promise<T>): Promise<T> {
    this.busy += 1;
    this.lastUsed = Date.now();
    return this.gate.run(() => fn(this.room)).finally(() => {
      this.busy -= 1;
      this.lastUsed = Date.now();
    });
  }

  forget(s: NodeRoomSocket): void {
    this.sockets.delete(s);
  }

  private armAlarm(at: number | null): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    if (at === null) return;
    const wait = Math.max(0, at - Date.now());
    this.timer = setTimeout(() => {
      this.timer = null;
      if (wait > MAX_TIMER_MS) return this.armAlarm(at);
      void this.event(async (room) => {
        // Like Durable Objects: the alarm is cleared before it runs (the room may set a new one).
        const now = this.ns.db.stmt("SELECT at FROM room_alarms WHERE room = ?").get(this.name) as { at: number } | undefined;
        if (!now || Number(now.at) > Date.now() + 5) return;
        this.ns.db.stmt("DELETE FROM room_alarms WHERE room = ?").run(this.name);
        await room.alarm();
      }).catch((e) => console.error(JSON.stringify({ event: "room_alarm_failed", error: (e as Error)?.name ?? "Error" })));
    }, Math.min(wait, MAX_TIMER_MS));
    this.timer.unref?.();
  }

  hasTimer(): boolean {
    return this.timer !== null;
  }

  stop(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }
}

/** The rooms' namespace (what the router and the account side call), all rooms of this process. */
export class NodeRooms implements RoomNamespace {
  readonly hosts = new Map<string, NodeRoomHost>();
  readonly pending = new Map<string, { socket: NodeRoomSocket; host: NodeRoomHost; at: number }>();
  env: RelayEnv;
  private sweeper: NodeJS.Timeout;

  constructor(
    readonly db: SqliteDb,
    env: Omit<RelayEnv, "RELAY">,
    /** The room class (tests pass one with a movable clock). */
    readonly RoomClass: new (state: RoomState, env: RelayEnv, runtime: RoomRuntime) => RelayRoom = RelayRoom,
  ) {
    db.sqlite.exec(`CREATE TABLE IF NOT EXISTS room_kv (room TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (room, key));
                    CREATE TABLE IF NOT EXISTS room_alarms (room TEXT PRIMARY KEY, at INTEGER NOT NULL);`);
    this.env = { ...env, RELAY: this };
    // Rooms with an alarm come back after a restart, so their deadlines (cleanup, retention) still fire.
    for (const r of db.sqlite.prepare("SELECT room FROM room_alarms").all() as { room: string }[]) this.host(r.room);
    this.sweeper = setInterval(() => this.sweep(), 60_000);
    this.sweeper.unref?.();
  }

  idFromName(name: string): unknown {
    return name;
  }

  get(id: unknown): RoomStub {
    const name = String(id);
    return {
      fetch: (input: string | Request, init?: RequestInit) => {
        const req = typeof input === "string" ? new Request(input, init) : input;
        return this.host(name).event((room) => room.fetch(req));
      },
    };
  }

  host(name: string): NodeRoomHost {
    let h = this.hosts.get(name);
    if (!h) {
      h = new NodeRoomHost(name, this);
      this.hosts.set(name, h);
    }
    return h;
  }

  /** The room socket waiting for the handshake of `token` (taken once). */
  takePending(token: string): NodeRoomSocket | null {
    const p = this.pending.get(token);
    if (!p) return null;
    this.pending.delete(token);
    return p.socket;
  }

  private sweep(): void {
    const now = Date.now();
    for (const [token, p] of this.pending) {
      if (now - p.at > 30_000) {
        this.pending.delete(token);
        p.socket.abandon();
      }
    }
    for (const [name, h] of this.hosts) {
      if (h.sockets.size === 0 && h.busy === 0 && !h.hasTimer() && now - h.lastUsed > IDLE_EVICT_MS) {
        h.stop();
        this.hosts.delete(name);
      }
    }
  }

  close(): void {
    clearInterval(this.sweeper);
    for (const h of this.hosts.values()) h.stop();
  }
}

