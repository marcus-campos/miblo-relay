// The Node runtime: an HTTP server (put it behind your own TLS reverse proxy, see deploy/docker)
// running the same fetch handler as the Cloudflare Worker, over SQLite and in-process rooms.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import type { Duplex } from "node:stream";
import { WebSocketServer } from "ws";
import type { Env } from "../core/env";
import { scopeOf } from "../core/env";
import { handle, type Assets } from "../core/site";
import { housekeeping } from "../core/housekeeping";
import { SqliteDb } from "./sqlite-db";
import { NodeRooms } from "./rooms";

export type ServerOptions = {
  /** Everything but DB and RELAY (made here). */
  env: Omit<Env, "DB" | "RELAY">;
  /** The SQLite file (":memory:" in tests). */
  dbFile: string;
  migrationsDir: string;
  /** The built phone app and account page (dist/public); null serves no files. */
  publicDir: string | null;
  /** Logs one line per request (method, path without query, status): off by default. */
  accessLog?: boolean;
};

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".webmanifest": "application/manifest+json",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".wasm": "application/wasm",
  ".woff2": "font/woff2",
  ".woff": "font/woff",
  ".txt": "text/plain; charset=utf-8",
};

export function fileAssets(dir: string | null): Assets {
  const root = dir ? fs.realpathSync(dir) : null;
  return async (file) => {
    if (!root) return null;
    const full = path.join(root, file);
    if (!full.startsWith(root + path.sep)) return null;
    let real: string;
    try {
      real = fs.realpathSync(full);
      if (!real.startsWith(root + path.sep) || !fs.statSync(real).isFile()) return null;
    } catch {
      return null;
    }
    const body = fs.readFileSync(real);
    return new Response(body, { status: 200, headers: { "Content-Type": TYPES[path.extname(real).toLowerCase()] ?? "application/octet-stream", "Content-Length": String(body.length) } });
  };
}

/**
 * The client's address as the core sees it (CF-Connecting-IP, set here and nowhere else): the
 * socket's, or with TRUSTED_PROXY=1 the last X-Forwarded-For entry, the one your own proxy added
 * (earlier entries come from the client and are ignored). Only a rate-limit key.
 */
export function clientAddress(req: http.IncomingMessage, trustedProxy: boolean): string {
  if (trustedProxy) {
    const xff = req.headers["x-forwarded-for"];
    const last = (Array.isArray(xff) ? xff.join(",") : xff)?.split(",").map((x) => x.trim()).filter(Boolean).pop();
    if (last) return last;
  }
  return req.socket.remoteAddress ?? "unknown";
}

function toRequest(req: http.IncomingMessage, origin: URL, trustedProxy: boolean, body: Buffer | null): Request {
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (v === undefined) continue;
    const name = k.toLowerCase();
    // Only this server says who the client is.
    if (name === "cf-connecting-ip" || name === "x-forwarded-for" || name === "x-client-keys" || name.startsWith(":")) continue;
    if (Array.isArray(v)) for (const x of v) headers.append(name, x);
    else headers.set(name, v);
  }
  headers.set("cf-connecting-ip", clientAddress(req, trustedProxy));
  // The URL is always the configured origin's: the Host header never decides anything.
  const url = new URL(req.url ?? "/", origin);
  const method = req.method ?? "GET";
  return new Request(url, { method, headers, body: body && method !== "GET" && method !== "HEAD" ? new Uint8Array(body) : undefined });
}

async function readBody(req: http.IncomingMessage, max = 256 * 1024): Promise<Buffer | null> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > max) return null;
    chunks.push(c as Buffer);
  }
  return Buffer.concat(chunks);
}

async function writeResponse(res: http.ServerResponse, out: Response, head: boolean): Promise<void> {
  const headers: Record<string, string | string[]> = {};
  out.headers.forEach((value, key) => {
    if (key === "set-cookie") return;
    headers[key] = value;
  });
  const cookies = out.headers.getSetCookie?.() ?? [];
  if (cookies.length) headers["set-cookie"] = cookies;
  res.writeHead(out.status, headers);
  if (head || !out.body) {
    res.end();
    return;
  }
  res.end(Buffer.from(await out.arrayBuffer()));
}

export async function createRelayServer(opts: ServerOptions) {
  const db = new SqliteDb(opts.dbFile);
  db.migrate(opts.migrationsDir);
  const rooms = new NodeRooms(db, opts.env);
  const env: Env = { ...(opts.env as Env), DB: db, RELAY: rooms };
  const origin = new URL(env.PUBLIC_ORIGIN);
  const trustedProxy = env.TRUSTED_PROXY === "1";
  const assets = fileAssets(opts.publicDir);
  const scope = scopeOf(env);
  const wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 + 1024, perMessageDeflate: false });

  const server = http.createServer(async (req, res) => {
    try {
      const body = req.method === "GET" || req.method === "HEAD" ? null : await readBody(req);
      if (body === null && req.method !== "GET" && req.method !== "HEAD") {
        res.writeHead(413, { "Content-Type": "application/json" });
        res.end('{"error":"payload_too_large"}');
        return;
      }
      const out = await handle(scope, toRequest(req, origin, trustedProxy, body), assets);
      if (opts.accessLog) console.log(`${req.method} ${(req.url ?? "").split("?")[0].slice(0, 80)} ${out.status}`);
      await writeResponse(res, out, req.method === "HEAD");
    } catch {
      if (!res.headersSent) res.writeHead(500, { "Content-Type": "application/json" });
      res.end('{"error":"server_error"}');
    }
  });

  server.on("upgrade", async (req: http.IncomingMessage, socket: Duplex, head: Buffer) => {
    socket.on("error", () => socket.destroy());
    try {
      const out = await handle(scope, toRequest(req, origin, trustedProxy, null), assets);
      const token = out.headers.get("x-miblo-upgrade");
      const pending = token ? rooms.takePending(token) : null;
      if (!pending || !token) {
        const reason = http.STATUS_CODES[out.status] ?? "Error";
        socket.end(`HTTP/1.1 ${out.status} ${reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
        return;
      }
      wss.handleUpgrade(req, socket, head, (ws) => pending.bind(ws));
    } catch {
      socket.destroy();
    }
  });

  const keeper = setInterval(() => void housekeeping(scope).catch(() => console.warn("housekeeping failed")), 3600_000);
  keeper.unref?.();
  void housekeeping(scope).catch(() => {});

  return {
    server,
    db,
    rooms,
    env,
    listen(port: number, hostname = "0.0.0.0"): Promise<number> {
      return new Promise((resolve) => server.listen(port, hostname, () => resolve((server.address() as { port: number }).port)));
    },
    async close(): Promise<void> {
      clearInterval(keeper);
      rooms.close();
      for (const c of wss.clients) c.terminate();
      server.closeAllConnections?.();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      db.sqlite.close();
    },
  };
}
