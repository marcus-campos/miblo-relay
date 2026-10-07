// The relay suite's two runtimes: workerd (Miniflare, the Cloudflare deploy) and Node (the Docker
// deploy), behind one interface, so the very same tests check that both speak exactly the protocol.
import http from "node:http";
import { join } from "node:path";
import { build } from "esbuild";
import { WebSocket as WsClient } from "ws";
import { generateVapidKeys } from "../../server/core/relay/webpush";
import { handleRelay, type RelayRouterEnv } from "../../server/core/relay/router";
import { PUSH_BUDGET_OBJECT } from "../../server/core/relay/room";
import { SqliteDb } from "../../server/node/sqlite-db";
import { NodeRooms } from "../../server/node/rooms";
import { TestRelayRoom, TEST_ROUTE } from "./test-room";

export type Pushed = { url: string; headers: Record<string, string>; body: Uint8Array };

/** A WebSocket as the tests drive it (Cloudflare's client end: events wait for accept()). */
export interface TestSocket {
  addEventListener(type: "message" | "close", fn: (e: { data?: unknown; code?: number }) => void): void;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  accept(): void;
}

export interface Harness {
  name: string;
  vapidPublic: string;
  pushed: Pushed[];
  dispatchFetch(url: string, init?: RequestInit): Promise<Response>;
  upgrade(url: string, headers: Record<string, string>): Promise<{ status: number; ws: TestSocket | null }>;
  dispose(): Promise<void>;
}

const PUSH_RE = /^https:\/\/[^/]*(fcm\.googleapis\.com|push\.services\.mozilla\.com|push\.apple\.com|notify\.windows\.com)\//;
function pushAnswer(url: string): number {
  return url.includes("/gone") ? 410 : url.includes("/fail") ? 403 : 201;
}

export async function workerdHarness(): Promise<Harness> {
  const { Miniflare, convertV4MiniflareOptions } = await import("miniflare");
  const out = await build({
    entryPoints: [join(__dirname, "worker-entry.ts")],
    bundle: true,
    write: false,
    format: "esm",
    platform: "neutral",
    target: "es2022",
  });
  const keys = await generateVapidKeys();
  const pushed: Pushed[] = [];
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: out.outputFiles[0].text,
      compatibilityDate: "2026-09-01",
      durableObjects: { RELAY: { className: "TestRelayRoom", useSQLite: true } },
      bindings: { RELAY_VAPID_PUBLIC_KEY: keys.publicKey, RELAY_VAPID_PRIVATE_KEY: keys.privateKey, RELAY_VAPID_SUBJECT: "https://relay.test", RELAY_RATE_LIMIT: "100000", RELAY_OPEN_ROOMS: "1" },
      outboundService: async (req: Request) => {
        const body = new Uint8Array(await req.arrayBuffer());
        pushed.push({ url: req.url, headers: Object.fromEntries(req.headers), body });
        return new Response(null, { status: pushAnswer(req.url) });
      },
    } as never),
  );
  await mf.ready;
  return {
    name: "workerd",
    vapidPublic: keys.publicKey,
    pushed,
    dispatchFetch: (url, init) => mf.dispatchFetch(url, init as never) as unknown as Promise<Response>,
    async upgrade(url, headers) {
      const res = (await mf.dispatchFetch(url, { headers })) as unknown as Response & { webSocket: TestSocket | null };
      return { status: res.status, ws: res.webSocket ?? null };
    },
    dispose: () => mf.dispose(),
  };
}

/** The Node runtime: the real router and rooms (server/node/rooms.ts) behind a local HTTP server. */
export async function nodeHarness(): Promise<Harness> {
  const keys = await generateVapidKeys();
  const pushed: Pushed[] = [];
  const realFetch = globalThis.fetch;
  // Push deliveries leave the process through fetch: recorded here, answered like a push service.
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input as RequestInfo, init);
    if (PUSH_RE.test(req.url)) {
      pushed.push({ url: req.url, headers: Object.fromEntries(req.headers), body: new Uint8Array(await req.arrayBuffer()) });
      return new Response(null, { status: pushAnswer(req.url) });
    }
    return realFetch(input as RequestInfo, init);
  }) as typeof fetch;
  const db = new SqliteDb(":memory:");
  const rooms = new NodeRooms(db, { RELAY_VAPID_PUBLIC_KEY: keys.publicKey, RELAY_VAPID_PRIVATE_KEY: keys.privateKey, RELAY_VAPID_SUBJECT: "https://relay.test", RELAY_OPEN_ROOMS: "1" }, TestRelayRoom);
  const env = { ...rooms.env, RELAY: rooms, RELAY_RATE_LIMIT: "100000" } as RelayRouterEnv;

  const toRequest = (req: http.IncomingMessage, body: Buffer | null) => {
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") headers.set(k, v);
    headers.delete("cf-connecting-ip");
    const testIp = headers.get("x-test-ip");
    if (testIp) headers.set("cf-connecting-ip", testIp);
    headers.delete("x-test-ip");
    return new Request(new URL(req.url ?? "/", "http://localhost"), { method: req.method, headers, body: body && body.length ? new Uint8Array(body) : undefined });
  };
  const route = async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    const test = TEST_ROUTE.exec(url.pathname);
    if (test) {
      const name = test[1] === "push-budget" ? PUSH_BUDGET_OBJECT : test[1];
      const body = request.method === "POST" ? await request.text() : undefined;
      return rooms.get(rooms.idFromName(name)).fetch(`https://relay.internal/__test/${test[2]}${url.search}`, { method: request.method, body });
    }
    return (await handleRelay(request, env)) ?? new Response("not found", { status: 404 });
  };
  const { WebSocketServer } = await import("ws");
  const wss = new WebSocketServer({ noServer: true, perMessageDeflate: false, maxPayload: 1024 * 1024 });
  const server = http.createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const out = await route(toRequest(req, Buffer.concat(chunks)));
    res.writeHead(out.status, Object.fromEntries(out.headers));
    res.end(Buffer.from(await out.arrayBuffer()));
  });
  server.on("upgrade", async (req, socket, head) => {
    const out = await route(toRequest(req, null));
    const token = out.headers.get("x-miblo-upgrade");
    const pending = token ? rooms.takePending(token) : null;
    if (!pending) {
      socket.end(`HTTP/1.1 ${out.status} ${http.STATUS_CODES[out.status] ?? "Error"}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => pending.bind(ws));
  });
  const port = await new Promise<number>((resolve) => server.listen(0, "127.0.0.1", () => resolve((server.address() as { port: number }).port)));
  const base = `http://127.0.0.1:${port}`;
  const local = (url: string) => base + new URL(url).pathname + new URL(url).search;

  return {
    name: "node",
    vapidPublic: keys.publicKey,
    pushed,
    // Plain http.request: fetch refuses an Upgrade header, which some tests send without upgrading.
    dispatchFetch: (url, init) =>
      new Promise<Response>((resolve, reject) => {
        const headers = Object.fromEntries(new Headers(init?.headers ?? {}));
        const req = http.request(local(url), { method: init?.method ?? "GET", headers }, (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => {
            const body = Buffer.concat(chunks);
            const h = new Headers();
            for (const [k, v] of Object.entries(res.headers)) if (typeof v === "string") h.set(k, v);
            resolve(new Response(res.statusCode === 204 || res.statusCode === 304 ? null : new Uint8Array(body), { status: res.statusCode, headers: h }));
          });
        });
        // An upgrade the server refused comes back as an ordinary answer on the "upgrade" path.
        req.on("upgrade", (res, socket) => {
          socket.destroy();
          resolve(new Response(null, { status: res.statusCode ?? 101 }));
        });
        req.on("error", reject);
        if (init?.body) req.write(typeof init.body === "string" ? init.body : Buffer.from(init.body as ArrayBuffer));
        req.end();
      }),
    upgrade(url, headers) {
      return new Promise((resolve) => {
        const h = { ...headers };
        delete (h as Record<string, string>).Upgrade;
        const ws = new WsClient(local(url).replace(/^http/, "ws"), { headers: h, perMessageDeflate: false });
        // Events wait for accept(), like a Cloudflare client socket.
        const queue: { type: "message" | "close"; e: { data?: unknown; code?: number } }[] = [];
        const listeners: Record<string, ((e: { data?: unknown; code?: number }) => void)[]> = { message: [], close: [] };
        let accepted = false;
        const emit = (type: "message" | "close", e: { data?: unknown; code?: number }) => {
          if (!accepted) return void queue.push({ type, e });
          for (const fn of listeners[type]) fn(e);
        };
        ws.on("message", (data) => emit("message", { data: data.toString() }));
        ws.on("close", (code) => emit("close", { code }));
        ws.on("error", () => {});
        const socket: TestSocket = {
          addEventListener: (type, fn) => listeners[type].push(fn),
          send: (data) => ws.send(data),
          close: (code, reason) => ws.close(code, reason),
          accept: () => {
            accepted = true;
            for (const q of queue.splice(0)) for (const fn of listeners[q.type]) fn(q.e);
          },
        };
        ws.once("open", () => resolve({ status: 101, ws: socket }));
        ws.once("unexpected-response", (_req, res) => {
          resolve({ status: res.statusCode ?? 0, ws: null });
          res.resume();
          ws.terminate();
        });
      });
    },
    async dispose() {
      globalThis.fetch = realFetch;
      for (const c of wss.clients) c.terminate();
      server.closeAllConnections();
      await new Promise<void>((r) => server.close(() => r()));
      rooms.close();
      db.sqlite.close();
    },
  };
}
