// The phone relay suite (protocol v2..v6), run against both runtimes of the server (test/relay/
// relay.*.test.ts): the RelayRoom and its router, with a movable clock. Covers the derived-room
// writer auth, the registered read hash, pending-slot limits, roles, rate and size limits,
// persistence throttling, retention and idle cleanup, push throttling, caps and payload
// encryption, and room deletion. Ported from miblo.ai's relay suite; only the harness differs.
import { createHash, webcrypto } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { LIMITS, UP_PER_MINUTE } from "../../server/core/relay/protocol";
import { uniqueIp } from "./ips";
import type { Harness } from "./harness";

// The protocol as miblo.ai runs it: rooms open to any writer (RELAY_OPEN_ROOMS=1); a self-hosted
// server's registered-rooms-only rule is checked in test/api.test.ts and test/worker.test.ts.
export function relaySuite(make: () => Promise<Harness>) {
const subtle = webcrypto.subtle;
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const rand = (n: number) => b64(webcrypto.getRandomValues(new Uint8Array(n)));
const newRoom = () => rand(16);
const newToken = () => rand(32);
const sha = (s: string) => createHash("sha256").update(s).digest("base64url");
/** A pairing as the plugin makes it: the room is derived from the write token. */
const pairing = () => {
  const w = newToken();
  const r = newToken();
  return { w, r, room: sha(`miblo-room-v2|${w}`).slice(0, 22), readHash: sha(r) };
};
type Pairing = ReturnType<typeof pairing>;

let h: Harness;

beforeAll(async () => {
  h = await make();
}, 60_000);

afterAll(async () => {
  await h?.dispose();
});

const until = async (check: () => boolean, ms = 3000) => {
  const end = Date.now() + ms;
  while (!check()) {
    if (Date.now() > end) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 10));
  }
};
const settle = (ms = 150) => new Promise((r) => setTimeout(r, ms));

type Client = {
  ws: import("./harness").TestSocket;
  messages: Record<string, unknown>[];
  /** v3 presence frames ({"t":"presence","readers":n}) the relay sent this writer. */
  presence: number[];
  /** v5: the enrolled phones each presence frame listed. */
  phones: string[][];
  close: { code: number } | null;
  send(data: unknown): void;
};

async function connect(
  room: string,
  role: string,
  token?: string,
  via: "message" | "header" = "message",
  readHash?: string,
  extra: { phone?: string; phones?: string; ip?: string } = {},
) {
  const headers: Record<string, string> = { Upgrade: "websocket" };
  if (token && via === "header") headers.Authorization = `Bearer ${token}`;
  if (readHash && via === "header") headers["X-Read-Hash"] = readHash;
  if (extra.phones !== undefined && via === "header") headers["X-Phones"] = extra.phones;
  if (extra.ip) headers["X-Test-IP"] = extra.ip;
  const up = await h.upgrade(`http://localhost/api/relay/${room}?role=${role}`, headers);
  const res = { status: up.status };
  const ws = up.ws;
  if (!ws) return { res, client: null };
  const client: Client = {
    ws,
    messages: [],
    presence: [],
    phones: [],
    close: null,
    send: (data) => ws.send(typeof data === "string" ? data : JSON.stringify(data)),
  };
  ws.addEventListener("message", (e) => {
    const data = JSON.parse(String((e as MessageEvent).data));
    if (data.t === "presence") {
      client.presence.push(data.readers);
      client.phones.push(data.phones ?? []);
    } else client.messages.push(data);
  });
  ws.addEventListener("close", (e) => (client.close = { code: (e as CloseEvent).code }));
  ws.accept();
  if (token && via === "message") {
    client.send({ t: "auth", token, ...(readHash ? { readHash } : {}), ...(extra.phone ? { phone: extra.phone } : {}), ...(extra.phones !== undefined ? { phones: extra.phones } : {}) });
  }
  return { res, client };
}

const open = async (room: string, role: string, token: string, readHash?: string) => {
  const { client } = await connect(room, role, token, "message", readHash);
  await settle(60);
  return client!;
};
/** The pairing's writer (message auth, registering the read hash) and optionally readers. */
const openWriter = (p: Pairing) => open(p.room, "writer", p.w, p.readHash);
const openReader = (p: Pairing) => open(p.room, "reader", p.r);
const frame = () => ({ t: "msg", iv: rand(12), ct: rand(48) });
/** v5: an enrolled phone: its id and its own reader token (the writer registers the token's hash). */
const enrolled = () => {
  const id = rand(16);
  const token = newToken();
  return { id, token, entry: `${id}.${sha(token)}` };
};
type Enrolled = ReturnType<typeof enrolled>;
const openPhone = async (p: Pairing, ph: Enrolled) => {
  const { client } = await connect(p.room, "reader", ph.token, "message", undefined, { phone: ph.id });
  await settle(60);
  return client!;
};
/** A Miblo+ room whose writer registered these enrolled phones. */
const plusWith = async (...phones: Enrolled[]) => {
  const p = pairing();
  const { client } = await connect(p.room, "writer", p.w, "message", p.readHash, { phones: phones.map((x) => x.entry).join(",") });
  await settle(60);
  await testCall(p.room, "plan", "?set=plus");
  return { p, writer: client! };
};
/** A frame sealed to some phones (the relay only checks the shape of each wrap). */
const sealed = (ch: string, ...ids: string[]) => ({ t: "msg", ch, iv: rand(12), ct: rand(64), to: Object.fromEntries(ids.map((id) => [id, rand(60)])) });
const testCall = (room: string, what: string, query = "") => h.dispatchFetch(`http://localhost/__test/${room}/${what}${query}`);
const advance = (room: string, ms: number) => testCall(room, "clock", `?advance=${ms}`);
const storage = async (room: string) =>
  (await (await testCall(room, "storage")).json()) as { entries: Record<string, unknown>; alarm: number | null };
const DAY = 24 * 3600 * 1000;

describe("relay router", () => {
  it("serves the VAPID public key", async () => {
    const res = await h.dispatchFetch("http://localhost/api/relay/vapid");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ publicKey: h.vapidPublic });
  });

  it("validates room, role and the upgrade", async () => {
    expect((await h.dispatchFetch("http://localhost/api/relay/short?role=reader", { headers: { Upgrade: "websocket" } })).status).toBe(404);
    expect((await h.dispatchFetch(`http://localhost/api/relay/${newRoom()}?role=admin`, { headers: { Upgrade: "websocket" } })).status).toBe(400);
    expect((await h.dispatchFetch(`http://localhost/api/relay/${newRoom()}?role=reader`)).status).toBe(426);
    expect((await h.dispatchFetch(`http://localhost/api/relay/${newRoom()}`, { method: "POST" })).status).toBe(405);
    expect((await h.dispatchFetch(`http://localhost/api/relay/${newRoom()}`, { method: "DELETE" })).status).toBe(401);
    // The push budget object is not reachable from outside.
    expect((await h.dispatchFetch("http://localhost/api/relay/__push-budget?n=1", { headers: { Upgrade: "websocket" } })).status).toBe(404);
  });
});

describe("relay room: phones changed (v6 push)", () => {
  const hint = (room: string, method = "POST") => h.dispatchFetch(`http://localhost/__test/${room}/phones`, { method });
  it("the account side's call reaches the authenticated writer only, as a fixed frame with nothing in it, and stores nothing", async () => {
    const p = pairing();
    const writer = await openWriter(p);
    const reader = await openReader(p);
    const pending = (await connect(p.room, "writer")).client!; // not authenticated yet
    await settle(60);
    const before = await storage(p.room);
    const res = await hint(p.room);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ writers: 1 });
    await settle(60);
    expect(writer.messages).toEqual([{ t: "phones_changed" }]);
    expect(reader.messages).toEqual([]);
    expect(pending.messages).toEqual([]);
    expect((await storage(p.room)).entries).toEqual(before.entries);
    // Only a POST; a room with nobody connected drops it.
    expect((await hint(p.room, "GET")).status).toBe(405);
    expect(await (await hint(pairing().room)).json()).toEqual({ writers: 0 });
    for (const c of [writer, reader, pending]) c.ws.close();
  });

  it("is never reachable from outside: the router forwards room paths only", async () => {
    for (const path of ["/api/relay/__phones", "/api/relay/__phones?role=writer", `/api/relay/${pairing().room}/__phones`]) {
      const res = await h.dispatchFetch(`http://localhost${path}`, { method: "POST" });
      expect(res.status).not.toBe(200);
    }
    expect((await h.dispatchFetch(`http://localhost/api/relay/${pairing().room}`, { method: "POST" })).status).toBe(405);
  });
});

describe("relay room: authentication (v2)", () => {
  it("verifies the writer by deriving the room from its token (message and header auth)", async () => {
    const p = pairing();
    const writer = await openWriter(p);
    expect(writer.close).toBeNull();
    const reader = await openReader(p);
    expect(reader.close).toBeNull();

    const s = await storage(p.room);
    const meta = s.entries.meta as Record<string, unknown>;
    expect(meta.readHash).toBe(p.readHash);
    expect(meta.writeHash).toBeUndefined();
    // Only the read hash: neither token is anywhere in storage.
    expect(JSON.stringify(s.entries)).not.toContain(p.w);
    expect(JSON.stringify(s.entries)).not.toContain(p.r);

    // Header auth (the plugin): verified before the upgrade.
    const viaHeader = await connect(p.room, "writer", p.w, "header", p.readHash);
    expect(viaHeader.res.status).toBe(101);
    await until(() => writer.close !== null);
    expect(writer.close!.code).toBe(4409);
    const readerHeader = await connect(p.room, "reader", p.r, "header");
    expect(readerHeader.res.status).toBe(101);
  });

  it("refuses a writer whose token does not derive the room, or that names no read hash", async () => {
    const p = pairing();
    const other = pairing();
    expect((await connect(p.room, "writer", other.w, "header", p.readHash)).res.status).toBe(401);
    expect((await connect(p.room, "writer", p.w, "header")).res.status).toBe(401);
    expect((await connect(p.room, "writer", p.w, "header", "not-a-hash")).res.status).toBe(401);
    const intruder = await open(p.room, "writer", other.w, p.readHash);
    await until(() => intruder.close !== null);
    expect(intruder.close!.code).toBe(4401);
    const noHash = await open(p.room, "writer", p.w);
    await until(() => noHash.close !== null);
    expect(noHash.close!.code).toBe(4401);
    // Nothing was registered by the failed attempts.
    expect((await storage(p.room)).entries.meta).toBeUndefined();
  });

  it("M1: an attacker cannot win the race: readers are refused until the writer registered its hash", async () => {
    const p = pairing();
    const attacker = newToken();
    // The attacker knows the room (e.g. a leaked link without the token) and comes first.
    const early = await open(p.room, "reader", attacker);
    await until(() => early.close !== null);
    expect(early.close!.code).toBe(4403);
    expect((await connect(p.room, "reader", attacker, "header")).res.status).toBe(403);
    // Even the right reader waits for the writer.
    const tooSoon = await openReader(p);
    await until(() => tooSoon.close !== null);
    expect(tooSoon.close!.code).toBe(4403);
    // Nor can the attacker claim the writer role first.
    const fakeWriter = await open(p.room, "writer", newToken(), sha(attacker));
    await until(() => fakeWriter.close !== null);
    expect(fakeWriter.close!.code).toBe(4401);

    const writer = await openWriter(p);
    const late = await open(p.room, "reader", attacker);
    await until(() => late.close !== null);
    expect(late.close!.code).toBe(4401);
    const reader = await openReader(p);
    expect(reader.close).toBeNull();
    expect(writer.close).toBeNull();
  });

  it("a writer registering a new read hash signs out the phones holding the old token", async () => {
    const p = pairing();
    await openWriter(p);
    const reader = await openReader(p);
    const r2 = newToken();
    await open(p.room, "writer", p.w, sha(r2));
    await until(() => reader.close !== null);
    expect(reader.close!.code).toBe(4401);
    const old = await openReader(p);
    await until(() => old.close !== null);
    expect(old.close!.code).toBe(4401);
    const fresh = await open(p.room, "reader", r2);
    expect(fresh.close).toBeNull();
  });

  it("closes sockets that do not authenticate within 5 s (on time), refuses late auth, and malformed auth at once", async () => {
    const p = pairing();
    await openWriter(p);
    const started = Date.now();
    const { client: silent } = await connect(p.room, "reader");
    // A keep-alive ping is answered without authenticating (and without waking the room). It
    // also gets Miniflare's client side of the socket going, so the later close reaches it.
    silent!.send({ t: "ping" });
    await until(() => silent!.messages.length === 1);
    expect(silent!.messages[0]).toEqual({ t: "pong" });
    await until(() => silent!.close !== null, 9000);
    expect(silent!.close!.code).toBe(4401);
    const took = Date.now() - started;
    expect(took).toBeGreaterThanOrEqual(4900);
    expect(took).toBeLessThan(6500);

    // The object's clock passes the deadline before the auth message arrives: refused.
    const { client: slow } = await connect(p.room, "reader");
    await advance(p.room, 6000);
    slow!.send({ t: "auth", token: p.r });
    await until(() => slow!.close !== null);
    expect(slow!.close!.code).toBe(4401);

    const { client: garbage } = await connect(p.room, "reader");
    garbage!.send("not json");
    await until(() => garbage!.close !== null);
    expect(garbage!.close!.code).toBe(4401);
  });

  it("M3: a flood of unauthenticated readers neither blocks the writer nor counts bad headers", async () => {
    const p = pairing();
    const pending: Client[] = [];
    for (let i = 0; i < 10; i++) {
      const { res, client } = await connect(p.room, "reader");
      expect(res.status).toBe(101);
      pending.push(client!);
    }
    expect((await connect(p.room, "reader")).res.status).toBe(429);
    // The writer's header auth is verified first and never takes a pending slot.
    const header = await connect(p.room, "writer", p.w, "header", p.readHash);
    expect(header.res.status).toBe(101);
    // Writers pending on the auth message have their own small pool.
    const w1 = await connect(p.room, "writer");
    const w2 = await connect(p.room, "writer");
    expect([w1.res.status, w2.res.status]).toEqual([101, 101]);
    expect((await connect(p.room, "writer")).res.status).toBe(429);
    // A wrong header is refused before anything is counted or accepted.
    expect((await connect(p.room, "writer", newToken(), "header", p.readHash)).res.status).toBe(401);
    expect((await connect(p.room, "reader", newToken(), "header")).res.status).toBe(401);
    // The authenticated reader path still works with header auth.
    expect((await connect(p.room, "reader", p.r, "header")).res.status).toBe(101);
    for (const c of pending) c.ws.close(1000);
  });
});

describe("relay room: frames", () => {
  it("relays writer frames to readers only, and ignores frames a role may not send", async () => {
    const p = pairing();
    const writer = await openWriter(p);
    await testCall(p.room, "plan", "?set=plus"); // two phones at once
    const a = await openReader(p);
    const b = await openReader(p);

    const f = frame();
    writer.send(f);
    await until(() => a.messages.length === 1 && b.messages.length === 1);
    expect(a.messages[0]).toEqual(f);

    a.send(frame()); // readers cannot publish
    writer.send({ t: "msg", iv: "short", ct: rand(48) }); // malformed iv: dropped
    writer.send({
      t: "sub",
      sub: { endpoint: "https://fcm.googleapis.com/fcm/send/x", keys: { p256dh: rand(65), auth: rand(16) } },
    }); // writers cannot subscribe
    await settle();
    expect(b.messages).toHaveLength(1);
    expect(writer.messages).toHaveLength(0);
    expect(Object.keys((await storage(p.room)).entries).filter((k) => k.startsWith("sub:"))).toHaveLength(0);
  });

  it("keeps one writer and, on Miblo+, a few guests (the oldest one goes)", async () => {
    const p = pairing();
    const first = await openWriter(p);
    await testCall(p.room, "plan", "?set=plus");
    const second = await openWriter(p);
    await until(() => first.close !== null);
    expect(first.close!.code).toBe(4409);
    expect(second.close).toBeNull();

    const readers: Client[] = [];
    for (let i = 0; i < LIMITS.maxGuests + 1; i++) readers.push(await openReader(p));
    await until(() => readers[0].close !== null);
    expect(readers[0].close!.code).toBe(4409);
    expect(readers.slice(1).every((c) => c.close === null)).toBe(true);
  });

  it("v3: a free room accepts one phone at a time: a second is refused with 4406, the first keeps going", async () => {
    const p = pairing();
    const writer = await openWriter(p);
    const first = await openReader(p);
    const second = await openReader(p);
    await until(() => second.close !== null);
    expect(second.close!.code).toBe(4406);
    expect(first.close).toBeNull();
    writer.send(frame());
    await until(() => first.messages.length === 1);
    // Once the first phone leaves, another one gets in.
    first.ws.close(1000);
    await settle();
    const third = await openReader(p);
    await settle();
    expect(third.close).toBeNull();
  });

  it("closes on frames over 64 KB and drops frames past 2 per second", async () => {
    const p = pairing();
    const writer = await openWriter(p);
    const reader = await openReader(p);
    for (let i = 0; i < 10; i++) writer.send(frame());
    await settle(300);
    // Ten frames sent in well under two seconds: at most two per second window get through.
    expect(reader.messages.length).toBeGreaterThanOrEqual(2);
    expect(reader.messages.length).toBeLessThanOrEqual(4);

    writer.send({ t: "msg", iv: rand(12), ct: "A".repeat(65 * 1024) });
    await until(() => writer.close !== null);
    expect(writer.close!.code).toBe(1009);

    reader.send({ t: "sub", pad: "x".repeat(17 * 1024) });
    await until(() => reader.close !== null);
    expect(reader.close!.code).toBe(1009);
  });

  it("shows the last frame on connect for 10 minutes only", async () => {
    const p = pairing();
    const writer = await openWriter(p);
    const f = frame();
    writer.send(f);
    await settle();

    const early = await openReader(p);
    await until(() => early.messages.length === 1);
    expect(early.messages[0]).toEqual({ ...f, ch: "status" });

    await advance(p.room, 11 * 60 * 1000);
    const late = await openReader(p);
    await settle();
    expect(late.messages).toHaveLength(0);
    await testCall(p.room, "alarm");
    expect((await storage(p.room)).entries.frame).toBeUndefined();
  });

  it("M2: frames stay in memory until a reader has joined, then are written at most once a minute", async () => {
    const p = pairing();
    const writer = await openWriter(p);
    writer.send(frame());
    await settle(600);
    writer.send(frame());
    await settle();
    // No reader ever: nothing but the room's meta is stored.
    expect(Object.keys((await storage(p.room)).entries)).toEqual(["meta"]);

    const reader = await openReader(p);
    await until(() => reader.messages.length === 1);
    const firstStored = (await storage(p.room)).entries.frame as { iv: string };
    expect(firstStored.iv).toBe(reader.messages[0].iv); // written once the first reader joined

    await advance(p.room, 1000);
    const f2 = frame();
    writer.send(f2);
    await until(() => reader.messages.length === 2);
    await settle();
    // Within the minute: memory only (a reader connecting now still gets it).
    expect(((await storage(p.room)).entries.frame as { iv: string }).iv).toBe(firstStored.iv);
    reader.ws.close(1000); // the free plan: one phone at a time
    await settle();
    const r2 = await openReader(p);
    await until(() => r2.messages.length === 1);
    expect(r2.messages[0].iv).toBe(f2.iv);

    // A minute later the pending frame is flushed by the alarm.
    await advance(p.room, 61_000);
    await testCall(p.room, "alarm");
    expect(((await storage(p.room)).entries.frame as { iv: string }).iv).toBe(f2.iv);
    // And past the minute a new frame is written at once.
    await advance(p.room, 61_000);
    const f3 = frame();
    writer.send(f3);
    await until(() => r2.messages.length === 2);
    await settle();
    expect(((await storage(p.room)).entries.frame as { iv: string }).iv).toBe(f3.iv);
  });
});

describe("relay room: cleanup", () => {
  it("M2: deletes a room no reader ever joined 24 hours after it was created", async () => {
    const p = pairing();
    const writer = await openWriter(p);
    writer.send(frame());
    await settle();
    writer.ws.close(1000);
    await settle();
    const s = await storage(p.room);
    expect(s.alarm).not.toBeNull();

    await advance(p.room, 23 * 3600 * 1000);
    await testCall(p.room, "alarm");
    expect((await storage(p.room)).entries.meta).toBeDefined();
    await advance(p.room, 2 * 3600 * 1000);
    await testCall(p.room, "alarm");
    const after = await storage(p.room);
    expect(after.entries).toEqual({});
    expect(after.alarm).toBeNull();
  });

  it("L7: once a reader joined, only writer activity keeps the room for 30 days", async () => {
    const p = pairing();
    const writer = await openWriter(p);
    writer.send(frame());
    await settle();
    const reader = await openReader(p);
    reader.ws.close(1000);
    writer.ws.close(1000);
    await settle();

    await advance(p.room, 2 * DAY); // past the no-reader 24 h: kept, a reader joined
    await testCall(p.room, "alarm");
    expect((await storage(p.room)).entries.meta).toBeDefined();

    // A phone reconnecting on day 29 does not extend the room's life.
    await advance(p.room, 27 * DAY);
    const phone = await openReader(p);
    expect(phone.close).toBeNull();
    phone.ws.close(1000);
    await settle();
    await advance(p.room, 2 * DAY);
    await testCall(p.room, "alarm");
    const s = await storage(p.room);
    expect(s.entries).toEqual({});
    expect(s.alarm).toBeNull();
  });

  it("L7: writer activity does extend it", async () => {
    const p = pairing();
    const writer = await openWriter(p);
    const reader = await openReader(p);
    reader.ws.close(1000);
    writer.ws.close(1000);
    await settle();
    await advance(p.room, 29 * DAY);
    const back = await openWriter(p);
    back.ws.close(1000);
    await settle();
    await advance(p.room, 2 * DAY);
    await testCall(p.room, "alarm");
    expect((await storage(p.room)).entries.meta).toBeDefined();
  });
});

describe("relay room: push", () => {
  it("sends an encrypted, generic, localized push when needs-you rises, at most once a minute", async () => {
    const p = pairing();
    const writer = await openWriter(p);
    const reader = await openReader(p);
    const ua = await subscriber();
    const endpoint = `https://fcm.googleapis.com/fcm/send/${rand(12)}`;
    reader.send({ t: "sub", sub: { endpoint, keys: ua.keys }, lang: "pt-BR" });
    reader.send({ t: "sub", sub: { endpoint: "https://evil.example.com/push", keys: ua.keys }, lang: "en" });
    await settle();
    const subs = Object.keys((await storage(p.room)).entries).filter((k) => k.startsWith("sub:"));
    expect(subs).toHaveLength(1);

    const mine = () => h.pushed.filter((x) => x.url === endpoint);
    writer.send({ t: "push", n: 1 });
    await until(() => mine().length === 1);
    const got = mine()[0];
    expect(got.headers["content-encoding"]).toBe("aes128gcm");
    expect(got.headers.authorization).toMatch(/^vapid t=[\w-]+\.[\w-]+\.[\w-]+, k=/);
    expect(got.headers.authorization).toContain(`k=${h.vapidPublic}`);
    expect(Number(got.headers.ttl)).toBeGreaterThan(0);
    const payload = JSON.parse(new TextDecoder().decode(await decryptPush(got.body, ua)));
    expect(payload).toEqual({ t: "needs_you", title: "Miblo", body: "Uma sessão precisa de você", lang: "pt-BR" });

    writer.send({ t: "push", n: 2 }); // rises, but within the minute
    await settle(600);
    expect(mine()).toHaveLength(1);
    await advance(p.room, 61_000);
    writer.send({ t: "push", n: 2 }); // no rise
    await settle(600);
    expect(mine()).toHaveLength(1);
    writer.send({ t: "push", n: 1 });
    await settle(600);
    writer.send({ t: "push", n: 3 });
    await until(() => mine().length === 2);
  });

  it("L6: at most 30 pushes per room per day", async () => {
    const p = pairing();
    const writer = await openWriter(p);
    const reader = await openReader(p);
    const ua = await subscriber();
    const endpoint = `https://fcm.googleapis.com/fcm/send/${rand(12)}`;
    reader.send({ t: "sub", sub: { endpoint, keys: ua.keys }, lang: "en" });
    await settle();
    const mine = () => h.pushed.filter((x) => x.url === endpoint).length;
    // Start at the beginning of a UTC day by the room's clock, so the run stays within one day.
    const st = (await (await testCall(p.room, "storage")).json()) as { sockets: { now: number }[] };
    const roomNow = st.sockets[0].now;
    await advance(p.room, DAY - (roomNow % DAY) + 1000);
    for (let i = 0; i < 31; i++) {
      // Two frames per (moved) second: within the writer's rate budget.
      writer.send({ t: "push", n: 0 });
      writer.send({ t: "push", n: 1 });
      await settle(60);
      await advance(p.room, 61_000);
    }
    await until(() => mine() >= 30);
    await settle(300);
    expect(mine()).toBe(30);
    await advance(p.room, DAY);
    writer.send({ t: "push", n: 0 });
    await settle(520);
    writer.send({ t: "push", n: 1 });
    await until(() => mine() === 31);
  });

  it("L6: nothing goes out once the global daily budget is spent", async () => {
    const p = pairing();
    const writer = await openWriter(p);
    const reader = await openReader(p);
    const ua = await subscriber();
    const endpoint = `https://fcm.googleapis.com/fcm/send/${rand(12)}`;
    reader.send({ t: "sub", sub: { endpoint, keys: ua.keys }, lang: "en" });
    await settle();
    const mine = () => h.pushed.filter((x) => x.url === endpoint).length;
    await testCall("push-budget", "budget", `?free=${LIMITS.pushesFreePerDay}`);
    writer.send({ t: "push", n: 1 });
    await settle(800);
    expect(mine()).toBe(0);
    await testCall("push-budget", "budget", "?free=0");
    await advance(p.room, 61_000);
    writer.send({ t: "push", n: 2 });
    await until(() => mine() === 1);
  });

  it("drops subscriptions the push service reports gone", async () => {
    const p = pairing();
    const writer = await openWriter(p);
    const reader = await openReader(p);
    const ua = await subscriber();
    reader.send({ t: "sub", sub: { endpoint: `https://fcm.googleapis.com/fcm/send/gone${rand(8)}`, keys: ua.keys }, lang: "en" });
    await settle();
    expect(Object.keys((await storage(p.room)).entries).some((k) => k.startsWith("sub:"))).toBe(true);
    writer.send({ t: "push", n: 1 });
    await settle(800);
    expect(Object.keys((await storage(p.room)).entries).some((k) => k.startsWith("sub:"))).toBe(false);
  });
});

describe("relay room: plans and deletion", () => {
  it("v1.1: on the free plan, channels other than status and up frames close with 4402", async () => {
    const p = pairing();
    const writer = await openWriter(p);
    const reader = await openReader(p);
    writer.send({ ...frame(), ch: "status" });
    await until(() => reader.messages.length === 1);
    expect(reader.messages[0].ch).toBe("status");

    reader.send({ t: "up", iv: rand(12), ct: rand(40) });
    await until(() => reader.close !== null);
    expect(reader.close!.code).toBe(4402);
    writer.send({ ...frame(), ch: "chat" });
    await until(() => writer.close !== null);
    expect(writer.close!.code).toBe(4402);
  });

  it("v1.1: on Miblo+, sealed frames reach their phone unstored and its up frames reach the writer (1/s)", async () => {
    const ph = enrolled();
    const { p, writer } = await plusWith(ph);
    const reader = await openPhone(p, ph);

    const status = frame();
    writer.send(status);
    await settle(600); // next second: the writer's rate window
    const history = sealed("history", ph.id);
    writer.send(history);
    await until(() => reader.messages.length === 2);
    expect(reader.messages[1]).toEqual({ t: "msg", ch: "history", iv: history.iv, ct: history.ct, k: history.to[ph.id] });
    const stored = (await storage(p.room)).entries.frame as { iv: string };
    expect(stored.iv).toBe(status.iv); // the history frame was not retained

    const up = { t: "up", ch: "reply", iv: rand(12), ct: rand(40) };
    reader.send(up);
    reader.send({ t: "up", ch: "reply", iv: rand(12), ct: rand(40) }); // same second: dropped
    await settle(300);
    expect(writer.messages).toEqual([{ ...up, p: ph.id }]);
    expect(reader.close).toBeNull();
  });

  it("L9: DELETE wipes with the write token only; any other token gets 401, whether the room exists or not", async () => {
    const p = pairing();
    const writer = await openWriter(p);
    const reader = await openReader(p);
    writer.send(frame());
    await settle();

    const del = (room: string, token: string) =>
      h.dispatchFetch(`http://localhost/api/relay/${room}`, { method: "DELETE", headers: { Authorization: `Bearer ${token}` } });
    expect((await del(p.room, p.r)).status).toBe(401);
    expect((await del(p.room, newToken())).status).toBe(401);
    expect((await del(newRoom(), newToken())).status).toBe(401); // unknown room: same answer
    expect((await del(p.room, p.w)).status).toBe(204);
    await until(() => reader.close !== null && writer.close !== null);
    expect(reader.close!.code).toBe(4404);
    expect((await storage(p.room)).entries).toEqual({});
    // Idempotent for the owner (the bridge may never have connected).
    expect((await del(p.room, p.w)).status).toBe(204);
    expect((await storage(p.room)).entries).toEqual({});

    // The plugin re-enabling the feature (same pairing) registers it afresh.
    const again = await openWriter(p);
    expect(again.close).toBeNull();
  });
});

describe("relay room: Miblo+ (v3)", () => {
  const plus = async () => {
    const p = pairing();
    const writer = await openWriter(p);
    await testCall(p.room, "plan", "?set=plus");
    return { p, writer };
  };

  it("a plus plan that lapsed is free again: the next Miblo+ frame closes with 4402", async () => {
    const ph = enrolled();
    const { p, writer } = await plusWith(ph);
    await testCall(p.room, "plan", `?set=plus&until=${Date.now() + 60_000}`);
    const reader = await openPhone(p, ph);
    writer.send(sealed("history", ph.id));
    await until(() => reader.messages.length === 1);
    await advance(p.room, 120_000);
    await settle(600);
    writer.send(sealed("history", ph.id));
    await until(() => writer.close !== null);
    expect(writer.close!.code).toBe(4402);
  });

  it("tells the writer how many phones are connected", async () => {
    const { p, writer } = await plus();
    await until(() => writer.presence.length >= 1);
    expect(writer.presence.at(-1)).toBe(0);
    const a = await openReader(p);
    await until(() => writer.presence.at(-1) === 1);
    const b = await openReader(p);
    await until(() => writer.presence.at(-1) === 2);
    a.ws.close(1000);
    await until(() => writer.presence.at(-1) === 1);
    b.ws.close(1000);
    await until(() => writer.presence.at(-1) === 0);
    // Pending (unauthenticated) readers are not phones.
    await connect(p.room, "reader");
    await settle();
    expect(writer.presence.at(-1)).toBe(0);
  });

  it("caps each channel's frame size (1009) in both directions", async () => {
    const { p, writer } = await plus();
    const reader = await openReader(p);
    writer.send({ t: "msg", ch: "reply", iv: rand(12), ct: "A".repeat(2 * 1024 + 4) });
    await until(() => writer.close !== null);
    expect(writer.close!.code).toBe(1009);
    expect(reader.messages).toEqual([]);

    const w2 = await openWriter(p);
    reader.send({ t: "up", ch: "approval", iv: rand(12), ct: "A".repeat(4 * 1024 + 4) });
    await until(() => reader.close !== null);
    expect(reader.close!.code).toBe(1009);
    expect(w2.messages).toEqual([]);
  });

  it("drops up frames without a Miblo+ channel and past each channel's per-minute budget", async () => {
    const ph = enrolled();
    const { p, writer } = await plusWith(ph);
    const reader = await openPhone(p, ph);
    // Start early in a minute so the 14 sends below stay inside one budget window.
    const into = Date.now() % 60_000;
    if (into > 40_000) await settle(60_000 - into + 50);
    reader.send({ t: "up", iv: rand(12), ct: rand(40) }); // no channel ("status"): never goes up
    await settle(1100);
    for (let i = 0; i < UP_PER_MINUTE.history! + 2; i++) {
      reader.send({ t: "up", ch: "history", iv: rand(12), ct: rand(40) });
      await settle(1050);
    }
    expect(writer.messages.length).toBe(UP_PER_MINUTE.history);
    expect(writer.messages.every((m) => m.ch === "history")).toBe(true);
    expect(reader.close).toBeNull();
  }, 60_000);

  it("forwards the approval channel both ways and stores none of the Miblo+ frames", async () => {
    const ph = enrolled();
    const { p, writer } = await plusWith(ph);
    const reader = await openPhone(p, ph);
    const ask = sealed("approval", ph.id);
    writer.send(ask);
    await until(() => reader.messages.length === 1);
    expect(reader.messages[0]).toEqual({ t: "msg", ch: "approval", iv: ask.iv, ct: ask.ct, k: ask.to[ph.id] });
    const answer = { t: "up", ch: "approval", iv: rand(12), ct: rand(200) };
    reader.send(answer);
    await until(() => writer.messages.length === 1);
    expect(writer.messages[0]).toEqual({ ...answer, p: ph.id });
    const s = await storage(p.room);
    expect(JSON.stringify(s.entries)).not.toContain(ask.ct);
    expect(JSON.stringify(s.entries)).not.toContain(answer.ct);
    // With no phone connected, a Miblo+ frame is dropped, never kept for later.
    reader.ws.close(1000);
    await settle(600);
    const lost = sealed("history", ph.id);
    writer.send(lost);
    await settle(200);
    const late = await openPhone(p, ph);
    await settle(200);
    expect(late.messages.some((m) => m.ct === lost.ct)).toBe(false);
  });
});

describe("relay room: each enrolled phone (v5)", () => {
  it("a phone authenticates with its own token; the shared read token or another phone's token does not make it that phone", async () => {
    const a = enrolled();
    const b = enrolled();
    const { p, writer } = await plusWith(a, b);
    const pa = await openPhone(p, a);
    expect(pa.close).toBeNull();
    await until(() => (writer.phones.at(-1) ?? []).includes(a.id));
    // a's id with b's token, or with the shared read token: refused.
    const { client: wrong } = await connect(p.room, "reader", b.token, "message", undefined, { phone: a.id });
    const { client: shared } = await connect(p.room, "reader", p.r, "message", undefined, { phone: a.id });
    const { client: unknown } = await connect(p.room, "reader", newToken(), "message", undefined, { phone: rand(16) });
    await until(() => wrong!.close !== null && shared!.close !== null && unknown!.close !== null);
    for (const c of [wrong!, shared!, unknown!]) expect(c.close!.code).toBe(4401);
  });

  it("sealed frames reach only the phones they name; guests get the status and enrollment answers, nothing else", async () => {
    const a = enrolled();
    const b = enrolled();
    const { p, writer } = await plusWith(a, b);
    const pa = await openPhone(p, a);
    const pb = await openPhone(p, b);
    const guest = await openReader(p);
    const toA = sealed("approval", a.id);
    writer.send(toA);
    await until(() => pa.messages.length === 1);
    await settle(600);
    expect(pa.messages[0].k).toBe(toA.to[a.id]);
    expect(pb.messages).toEqual([]);
    expect(guest.messages).toEqual([]);
    // A Miblo+ frame that names nobody goes nowhere (the shared key never carries Miblo+).
    writer.send({ ...frame(), ch: "history" });
    await settle(600);
    // An answer to an enrollment: guests only.
    const enrolledAnswer = { t: "msg", ch: "approval", g: 1, iv: rand(12), ct: rand(80) };
    writer.send(enrolledAnswer);
    await until(() => guest.messages.length === 1);
    await settle(600);
    expect(guest.messages[0]).toEqual(enrolledAnswer);
    expect(pa.messages).toHaveLength(1);
    expect(pb.messages).toEqual([]);
    // Malformed recipients: dropped.
    writer.send({ ...sealed("approval", a.id), to: { [a.id]: "short" } });
    await settle(600);
    expect(pa.messages).toHaveLength(1);
  });

  it("guests may only send enrollments up (approval channel), a few a minute, and the writer sees no phone on them", async () => {
    const { p, writer } = await plusWith();
    const guest = await openReader(p);
    guest.send({ t: "up", ch: "history", iv: rand(12), ct: rand(40) });
    await settle(1100);
    guest.send({ t: "up", ch: "reply", iv: rand(12), ct: rand(40) });
    await settle(1100);
    expect(writer.messages).toEqual([]);
    const enroll = { t: "up", ch: "approval", iv: rand(12), ct: rand(200) };
    guest.send(enroll);
    await until(() => writer.messages.length === 1);
    expect(writer.messages[0]).toEqual(enroll);
  });

  it("a revoked phone is closed (4411) and refused from then on; the other phones stay", async () => {
    const a = enrolled();
    const gone = enrolled();
    const { p, writer } = await plusWith(a, gone);
    const pa = await openPhone(p, a);
    const pg = await openPhone(p, gone);
    await until(() => (writer.phones.at(-1) ?? []).length === 2);
    writer.send({ t: "phones", list: [{ id: a.id, h: sha(a.token) }] });
    await until(() => pg.close !== null);
    expect(pg.close!.code).toBe(4411);
    expect(pa.close).toBeNull();
    await until(() => JSON.stringify(writer.phones.at(-1)) === JSON.stringify([a.id]));
    const again = await openPhone(p, gone);
    await until(() => again.close !== null);
    expect(again.close!.code).toBe(4401);
    // Nothing sealed to it reaches it any more, and the registration survives a writer reconnect.
    const w2 = (await connect(p.room, "writer", p.w, "header", p.readHash, { phones: `${a.id}.${sha(a.token)}` })).client!;
    await settle(100);
    expect(w2.close).toBeNull();
    const back = await openPhone(p, gone);
    await until(() => back.close !== null);
    expect(back.close!.code).toBe(4401);
  });

  it("a phone only pushes out its own older sockets, never another phone; a new read token signs out guests only", async () => {
    const a = enrolled();
    const b = enrolled();
    const { p, writer } = await plusWith(a, b);
    const pb = await openPhone(p, b);
    const mine: Client[] = [];
    for (let i = 0; i < LIMITS.maxSocketsPerPhone + 3; i++) mine.push(await openPhone(p, a));
    await settle(200);
    expect(pb.close).toBeNull();
    expect(mine.filter((c) => c.close === null)).toHaveLength(LIMITS.maxSocketsPerPhone);
    expect(mine.filter((c) => c.close !== null).every((c) => c.close!.code === 4409)).toBe(true);
    // Guests cannot push phones out either.
    const guests: Client[] = [];
    for (let i = 0; i < 4; i++) guests.push(await openReader(p));
    await settle(200);
    expect(pb.close).toBeNull();
    // The writer registers a new read token (a phone was revoked and the pairing re-keyed): guests
    // holding the old one are out; enrolled phones stay.
    const r2 = newToken();
    writer.ws.close(1000);
    await connect(p.room, "writer", p.w, "header", sha(r2), { phones: [a, b].map((x) => x.entry).join(",") });
    await until(() => guests.every((g) => g.close !== null));
    expect(guests.filter((g) => g.close!.code === 4401).length).toBeGreaterThan(0);
    expect(pb.close).toBeNull();
  });
});

describe("relay room: phones per plan, sealed status, token changes (v5)", () => {
  it("a Miblo+ room that goes free closes every phone but the first at once", async () => {
    const phones = [enrolled(), enrolled(), enrolled()];
    const { p } = await plusWith(...phones);
    const socks: Client[] = [];
    for (const ph of phones) socks.push(await openPhone(p, ph));
    await testCall(p.room, "plan", "?set=free");
    await until(() => socks[1].close !== null && socks[2].close !== null);
    expect(socks.slice(1).every((c) => c.close!.code === 4406)).toBe(true);
    expect(socks[0].close).toBeNull();
  });

  it("a free (or lapsed) room allows one phone at a time, enrolled identities included", async () => {
    const a = enrolled();
    const b = enrolled();
    const p = pairing();
    const writer = (await connect(p.room, "writer", p.w, "message", p.readHash, { phones: [a, b].map((x) => x.entry).join(",") })).client!;
    await settle(60);
    const pa = await openPhone(p, a);
    const pa2 = await openPhone(p, a); // the same phone may hold its own second socket
    const pb = await openPhone(p, b);
    const guest = await openReader(p);
    await until(() => pb.close !== null && guest.close !== null);
    expect(pb.close!.code).toBe(4406);
    expect(guest.close!.code).toBe(4406);
    expect(pa.close).toBeNull();
    expect(pa2.close).toBeNull();
    expect(writer.close).toBeNull();
  });

  it("a Miblo+ room caps distinct enrolled phones at five", async () => {
    const phones = Array.from({ length: 6 }, () => enrolled());
    const { p } = await plusWith(...phones);
    const socks: Client[] = [];
    for (const ph of phones) socks.push(await openPhone(p, ph));
    await until(() => socks[5].close !== null);
    expect(socks[5].close!.code).toBe(4406);
    expect(socks.slice(0, 5).every((c) => c.close === null)).toBe(true);
  });

  it("a status frame sealed to some phones goes on a free room to those phones only, and is never kept", async () => {
    const a = enrolled();
    const p = pairing();
    const writer = (await connect(p.room, "writer", p.w, "message", p.readHash, { phones: a.entry })).client!;
    await settle(60);
    const pa = await openPhone(p, a);
    const rekey = { t: "msg", ch: "status", iv: rand(12), ct: rand(64), to: { [a.id]: rand(60) } };
    writer.send(rekey);
    await until(() => pa.messages.length === 1);
    expect(pa.messages[0]).toEqual({ t: "msg", ch: "status", iv: rekey.iv, ct: rekey.ct, k: rekey.to[a.id] });
    await settle(200);
    expect(writer.close).toBeNull(); // no 4402
    expect(JSON.stringify((await storage(p.room)).entries)).not.toContain(rekey.ct);
  });

  it("a phone whose token the writer replaced is closed", async () => {
    const a = enrolled();
    const { p, writer } = await plusWith(a);
    const pa = await openPhone(p, a);
    writer.send({ t: "phones", list: [{ id: a.id, h: sha(newToken()) }] });
    await until(() => pa.close !== null);
    expect(pa.close!.code).toBe(4411);
  });
});

describe("relay room: push budget (v5)", () => {
  const withSub = async (plan: "free" | "plus", endpointPath = rand(12)) => {
    const p = pairing();
    const writer = await openWriter(p);
    if (plan === "plus") await testCall(p.room, "plan", "?set=plus");
    const reader = await openReader(p);
    const ua = await subscriber();
    const endpoint = `https://fcm.googleapis.com/fcm/send/${endpointPath}`;
    reader.send({ t: "sub", sub: { endpoint, keys: ua.keys }, lang: "en" });
    await settle();
    return { p, writer, reader, endpoint };
  };
  const budget = async () => ((await (await testCall("push-budget", "storage")).json()) as { entries: { budget?: { free: number; plus: number } } }).entries.budget!;

  it("a made-up push key (not a P-256 point) is refused when it is subscribed", async () => {
    const p = pairing();
    await openWriter(p);
    const reader = await openReader(p);
    reader.send({ t: "sub", sub: { endpoint: `https://fcm.googleapis.com/fcm/send/${rand(8)}`, keys: { p256dh: rand(65), auth: rand(16) } }, lang: "en" });
    await settle();
    expect(Object.keys((await storage(p.room)).entries).filter((k) => k.startsWith("sub:"))).toHaveLength(0);
  });

  it("a room keeps about one subscription per phone its plan allows (free: 2)", async () => {
    const p = pairing();
    await openWriter(p);
    const reader = await openReader(p);
    for (let i = 0; i < 5; i++) {
      const ua = await subscriber();
      reader.send({ t: "sub", sub: { endpoint: `https://fcm.googleapis.com/fcm/send/${rand(8)}`, keys: ua.keys }, lang: "en" });
      await settle(60);
    }
    await settle();
    expect(Object.keys((await storage(p.room)).entries).filter((k) => k.startsWith("sub:"))).toHaveLength(LIMITS.maxSubscriptionsFree);
  });

  it("free rooms spending their pool leave Miblo+ rooms' pushes going; refused deliveries are given back", async () => {
    await testCall("push-budget", "budget", `?free=${LIMITS.pushesFreePerDay}&plus=0`);
    const free = await withSub("free");
    const paid = await withSub("plus");
    free.writer.send({ t: "push", n: 1 });
    paid.writer.send({ t: "push", n: 1 });
    await until(() => h.pushed.some((x) => x.url === paid.endpoint));
    await settle(300);
    expect(h.pushed.some((x) => x.url === free.endpoint)).toBe(false);
    expect((await budget()).plus).toBe(1);
    // A subscription the push service refuses (gone) costs nothing.
    await testCall("push-budget", "budget", "?free=0&plus=0");
    const dead = await withSub("free", `gone${rand(8)}`);
    dead.writer.send({ t: "push", n: 1 });
    await until(() => h.pushed.some((x) => x.url === dead.endpoint));
    await settle(300);
    expect((await budget()).free).toBe(0);
  });

  it("one endpoint subscribed in many rooms gets a few dozen pushes a day in all", async () => {
    await testCall("push-budget", "budget", "?free=0&plus=0");
    const ua = await subscriber();
    const endpoint = `https://fcm.googleapis.com/fcm/send/${rand(12)}`;
    const rooms = [];
    for (let i = 0; i < 3; i++) {
      const p = pairing();
      const writer = await openWriter(p);
      const reader = await openReader(p);
      // The same subscription spelled another way ("#1", "?x=2") is not another endpoint: refused.
      reader.send({ t: "sub", sub: { endpoint: [endpoint, `${endpoint}#${i}`, `${endpoint}?x=${i}`][i], keys: ua.keys }, lang: "en" });
      if (i > 0) reader.send({ t: "sub", sub: { endpoint, keys: ua.keys }, lang: "en" });
      rooms.push({ p, writer });
    }
    await settle();
    const mine = () => h.pushed.filter((x) => x.url === endpoint).length;
    // Pretend the endpoint already had its share today: no room can push it any more.
    const eh = createHash("sha256").update(endpoint).digest("hex").slice(0, 32);
    await h.dispatchFetch(`http://localhost/__test/push-budget/endpoint?h=${eh}&n=${LIMITS.pushesPerEndpointPerDay}`);
    for (const r of rooms) r.writer.send({ t: "push", n: 1 });
    await settle(800);
    expect(mine()).toBe(0);
    expect(h.pushed.some((x) => x.url.startsWith(endpoint) && x.url !== endpoint)).toBe(false);
    for (const r of rooms) {
      const subs = Object.values((await storage(r.p.room)).entries).filter((v) => (v as { sub?: { endpoint: string } }).sub) as { sub: { endpoint: string } }[];
      expect(subs.map((v) => v.sub.endpoint)).toEqual([endpoint]);
    }
  });

  it("each payer has its own daily quota: one Miblo+ account (or the network that made free rooms) cannot spend everyone's", async () => {
    await testCall("push-budget", "budget", "?free=0&plus=0");
    const mk = async (account: string) => {
      const p = pairing();
      const writer = await openWriter(p);
      await testCall(p.room, "plan", "?set=plus");
      await h.dispatchFetch(`http://localhost/__test/${p.room}/plus`, { method: "POST", body: JSON.stringify({ op: "set", plan: "plus", account }) });
      const reader = await openReader(p);
      const ua = await subscriber();
      const endpoint = `https://fcm.googleapis.com/fcm/send/${rand(12)}`;
      reader.send({ t: "sub", sub: { endpoint, keys: ua.keys }, lang: "en" });
      await settle();
      return { writer, endpoint };
    };
    const greedy = await mk("g".repeat(22));
    const honest = await mk("h".repeat(22));
    await h.dispatchFetch(`http://localhost/__test/push-budget/payer?k=${encodeURIComponent(`p:plus:a:${"g".repeat(22)}`)}&n=${LIMITS.pushesPerAccountPerDay}`);
    greedy.writer.send({ t: "push", n: 1 });
    honest.writer.send({ t: "push", n: 1 });
    await until(() => h.pushed.some((x) => x.url === honest.endpoint));
    await settle(300);
    expect(h.pushed.some((x) => x.url === greedy.endpoint)).toBe(false);
  });

  it("subscriptions no phone re-sent for 30 days get no push and are dropped", async () => {
    const p = pairing();
    const writer = await openWriter(p);
    const reader = await openReader(p);
    const ua = await subscriber();
    const endpoint = `https://fcm.googleapis.com/fcm/send/${rand(12)}`;
    reader.send({ t: "sub", sub: { endpoint, keys: ua.keys }, lang: "en" });
    await settle();
    await advance(p.room, 31 * DAY);
    writer.send({ t: "push", n: 1 });
    await settle(800);
    expect(h.pushed.some((x) => x.url === endpoint)).toBe(false);
    expect(Object.keys((await storage(p.room)).entries).some((k) => k.startsWith("sub:"))).toBe(false);
  });

  it("new rooms: an IPv6 host counts by its /64, and a network's rooms add up over 30 days", async () => {
    const made: number[] = [];
    for (let i = 1; i <= LIMITS.newRoomsPerNetworkPerDay + 1; i++) {
      const p = pairing();
      made.push((await connect(p.room, "writer", p.w, "header", p.readHash, { ip: `2001:db8:5:6::${i.toString(16)}` })).res.status);
    }
    expect(made.slice(0, LIMITS.newRoomsPerNetworkPerDay).every((s) => s === 101)).toBe(true);
    expect(made.at(-1)).toBe(429);
    const other = pairing();
    expect((await connect(other.room, "writer", other.w, "header", other.readHash, { ip: "2001:db8:5:7::1" })).res.status).toBe(101);
  });

  it("a network's rooms a phone joined add up over its key's 30-day period, not only per day", async () => {
    const k = `64:${rand(16)}`;
    const day = Math.floor(Date.now() / DAY);
    const cap = (state?: unknown) => h.dispatchFetch(`http://localhost/__test/push-budget/roomcap?k=${k}${state ? `&state=${encodeURIComponent(JSON.stringify(state))}` : ""}`);
    // A few days ago it already made its period's share: today's first room is refused.
    expect((await cap({ day: day - 3, n: 10, total: LIMITS.newRoomsPerNetworkPerPeriod })).status).toBe(429);
    expect((await cap({ day: day - 3, n: 10, total: LIMITS.newRoomsPerNetworkPerPeriod - 1 })).status).toBe(200);
    // Making a room is not using it: only a phone joining counts over the period.
    expect((await cap()).status).toBe(200);
    // IPv4 (CGNAT, offices) has a much higher period cap: 30 joined rooms are nothing there.
    const v4 = `4:${rand(16)}`;
    const v4cap = (total: number) => h.dispatchFetch(`http://localhost/__test/push-budget/roomcap?k=${v4}&state=${encodeURIComponent(JSON.stringify({ day: day - 3, n: 10, total }))}`);
    expect((await v4cap(LIMITS.newRoomsPerNetworkPerPeriod)).status).toBe(200);
    expect((await v4cap(LIMITS.newRoomsPerIpv4PerPeriod)).status).toBe(429);
  });

  it("CGNAT: 30 rooms phones really use on one IPv4 never lock a neighbour out; rooms never joined never count over the period", async () => {
    const ip = uniqueIp();
    const sockets: Client[] = [];
    const netRow = async () => {
      const all = ((await (await testCall("push-budget", "storage")).json()) as { entries: Record<string, { day: number; n: number; total: number }> }).entries;
      return Object.entries(all).filter(([k]) => k.startsWith("r:4:"));
    };
    const before = new Set((await netRow()).map(([k]) => k));
    let advanced = 0;
    try {
      for (let d = 0; d < 3; d++) {
        for (let i = 0; i < LIMITS.newRoomsPerNetworkPerDay; i++) {
          const p = pairing();
          const w = await connect(p.room, "writer", p.w, "header", p.readHash, { ip });
          expect(w.res.status).toBe(101);
          sockets.push(w.client!, await openReader(p));  // a phone joins: it counts now
        }
        await testCall("push-budget", "clock", `?advance=${DAY}`);
        advanced += DAY;
      }
      await settle();
      const mine = (await netRow()).filter(([k]) => !before.has(k));
      expect(mine.length).toBe(1);
      expect(mine[0][1].total).toBe(3 * LIMITS.newRoomsPerNetworkPerDay);
      // The next day a neighbour behind the same address pairs.
      const neighbour = pairing();
      const nw = await connect(neighbour.room, "writer", neighbour.w, "header", neighbour.readHash, { ip });
      expect(nw.res.status).toBe(101);
      sockets.push(nw.client!);
      // Rooms no phone joins cost today's slots only, and are given back when they go.
      const idle = [];
      for (let i = 1; i < LIMITS.newRoomsPerNetworkPerDay; i++) {
        const p = pairing();
        const w = await connect(p.room, "writer", p.w, "header", p.readHash, { ip });
        expect(w.res.status).toBe(101);
        sockets.push(w.client!);
        idle.push(p);
      }
      const late = pairing();
      expect((await connect(late.room, "writer", late.w, "header", late.readHash, { ip })).res.status).toBe(429);
      for (const p of idle) {
        expect((await h.dispatchFetch(`http://localhost/api/relay/${p.room}`, { method: "DELETE", headers: { Authorization: `Bearer ${p.w}` } })).status).toBe(204);
      }
      const after = (await netRow()).find(([k]) => k === mine[0][0])![1];
      expect(after.total).toBe(3 * LIMITS.newRoomsPerNetworkPerDay);
      expect(after.n).toBe(1);
      const ok = await connect(late.room, "writer", late.w, "header", late.readHash, { ip });
      expect(ok.res.status).toBe(101);
      sockets.push(ok.client!);
    } finally {
      for (const c of sockets) c.ws.close();
      if (advanced) await testCall("push-budget", "clock", `?advance=${-advanced}`);
    }
  }, 60_000);

  it("IPv6: the /56 and /48 around a host count too (a home's /56 is not 256 networks)", async () => {
    const made: number[] = [];
    for (let i = 0; i < 2 * LIMITS.newRoomsPerNetworkPerDay + 1; i++) {
      const p = pairing();
      // Each room from another /64 of one /56.
      made.push((await connect(p.room, "writer", p.w, "header", p.readHash, { ip: `2001:db8:aa:1${i.toString(16).padStart(2, "0")}::1` })).res.status);
    }
    expect(made.slice(0, 2 * LIMITS.newRoomsPerNetworkPerDay).every((x) => x === 101)).toBe(true);
    expect(made.at(-1)).toBe(429);
  });

  it("a room no phone ever joined gives its network its room back when it goes", async () => {
    const ip = uniqueIp();
    const rooms = [];
    for (let i = 0; i < LIMITS.newRoomsPerNetworkPerDay; i++) {
      const p = pairing();
      expect((await connect(p.room, "writer", p.w, "header", p.readHash, { ip })).res.status).toBe(101);
      rooms.push(p);
    }
    const extra = pairing();
    expect((await connect(extra.room, "writer", extra.w, "header", extra.readHash, { ip })).res.status).toBe(429);
    // One of them is deleted before any phone joined (the computer turned the companion off).
    const del = await h.dispatchFetch(`http://localhost/api/relay/${rooms[0].room}`, { method: "DELETE", headers: { Authorization: `Bearer ${rooms[0].w}` } });
    expect(del.status).toBe(204);
    expect((await connect(extra.room, "writer", extra.w, "header", extra.readHash, { ip })).res.status).toBe(101);
  });

  it("a failing subscription gives back only what it was charged: the fallback stays at 10 a day", async () => {
    await testCall("push-budget", "budget", "?free=0&plus=0");
    const ip = uniqueIp();
    const p = pairing();
    const writer = (await connect(p.room, "writer", p.w, "header", p.readHash, { ip })).client!;
    const reader = await openReader(p);
    const good = await subscriber();
    const bad = await subscriber();
    const ok = `https://fcm.googleapis.com/fcm/send/${rand(12)}`;
    const failing = `https://fcm.googleapis.com/fcm/send/fail${rand(8)}`;
    reader.send({ t: "sub", sub: { endpoint: failing, keys: bad.keys }, lang: "en" });
    reader.send({ t: "sub", sub: { endpoint: ok, keys: good.keys }, lang: "en" });
    await settle();
    const meta = (await storage(p.room)).entries.meta as { nets: string[] };
    const net = meta.nets[0].slice(2);
    await h.dispatchFetch(`http://localhost/__test/push-budget/payer?k=${encodeURIComponent(`p:free:n4:${net}`)}&n=${LIMITS.pushesPerNetworkPerDay}`);
    const st = (await (await testCall(p.room, "storage")).json()) as { sockets: { now: number }[] };
    await advance(p.room, DAY - (st.sockets[0].now % DAY) + 1000);
    for (let i = 0; i < 16; i++) {
      writer.send({ t: "push", n: 0 });
      writer.send({ t: "push", n: 1 });
      await settle(80);
      await advance(p.room, 61_000);
    }
    await settle(500);
    expect(h.pushed.filter((x) => x.url === ok).length).toBeLessThanOrEqual(10);
  }, 60_000);

  it("a free room keeps a small push quota of its own when its network's is spent by others", async () => {
    await testCall("push-budget", "budget", "?free=0&plus=0");
    const ip = uniqueIp();
    const p = pairing();
    const writer = (await connect(p.room, "writer", p.w, "header", p.readHash, { ip })).client!;
    const reader = await openReader(p);
    const ua = await subscriber();
    const endpoint = `https://fcm.googleapis.com/fcm/send/${rand(12)}`;
    reader.send({ t: "sub", sub: { endpoint, keys: ua.keys }, lang: "en" });
    await settle();
    // The network's quota spent (neighbours behind the same address).
    const meta = (await storage(p.room)).entries.meta as { nets: string[] };
    const net = meta.nets[0].slice(2);
    await h.dispatchFetch(`http://localhost/__test/push-budget/payer?k=${encodeURIComponent(`p:free:n4:${net}`)}&n=${LIMITS.pushesPerNetworkPerDay}`);
    writer.send({ t: "push", n: 1 });
    await until(() => h.pushed.some((x) => x.url === endpoint));
  });

  it("new rooms per network are capped per day by a keyed hash; the budget object never stores an IP", async () => {
    const ip = uniqueIp();
    const made: number[] = [];
    for (let i = 0; i < LIMITS.newRoomsPerNetworkPerDay + 1; i++) {
      const p = pairing();
      const { res } = await connect(p.room, "writer", p.w, "header", p.readHash, { ip });
      made.push(res.status);
    }
    expect(made.slice(0, LIMITS.newRoomsPerNetworkPerDay).every((s) => s === 101)).toBe(true);
    expect(made.at(-1)).toBe(429);
    // Another network is not affected, and an existing room reconnects freely.
    const other = pairing();
    expect((await connect(other.room, "writer", other.w, "header", other.readHash, { ip: "198.51.100.7" })).res.status).toBe(101);
    expect((await connect(other.room, "writer", other.w, "header", other.readHash, { ip })).res.status).toBe(101);
    const all = JSON.stringify(((await (await testCall("push-budget", "storage")).json()) as { entries: unknown }).entries);
    expect(all).not.toContain(ip);
    expect(all).not.toContain("198.51.100.7");
  });
});

// --- a Web Push subscriber (the browser's side of RFC 8291) ------------------------------------

async function subscriber() {
  const pair = (await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as CryptoKeyPair;
  const pub = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
  const auth = webcrypto.getRandomValues(new Uint8Array(16));
  return { pair, pub, auth, keys: { p256dh: b64(pub), auth: b64(auth) } };
}

async function hmac(key: Uint8Array, data: Uint8Array) {
  const k = await subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle.sign("HMAC", k, data));
}
const cat = (...parts: Uint8Array[]) => new Uint8Array(Buffer.concat(parts));
const hkdf = async (salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, n: number) =>
  (await hmac(await hmac(salt, ikm), cat(info, new Uint8Array([1])))).slice(0, n);

async function decryptPush(body: Uint8Array, ua: Awaited<ReturnType<typeof subscriber>>) {
  const salt = body.slice(0, 16);
  const idlen = body[20];
  const asPublic = body.slice(21, 21 + idlen);
  const ct = body.slice(21 + idlen);
  const as = await subtle.importKey("raw", asPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ecdh = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: as }, ua.pair.privateKey, 256));
  const te = new TextEncoder();
  const ikm = await hkdf(ua.auth, ecdh, cat(te.encode("WebPush: info\0"), ua.pub, asPublic), 32);
  const cek = await hkdf(salt, ikm, te.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, te.encode("Content-Encoding: nonce\0"), 12);
  const key = await subtle.importKey("raw", cek, "AES-GCM", false, ["decrypt"]);
  const plain = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, ct));
  expect(plain[plain.length - 1]).toBe(2); // last-record delimiter
  return plain.slice(0, -1);
}

}
