// The Cloudflare deploy: the real Worker (server/worker/index.ts) in workerd through Miniflare, with
// D1 (the migrations applied like `wrangler d1 migrations apply`), the RelayRoom Durable Object and
// the secrets as bindings: identity, setup, the device flow and the relay upgrade answer as on Node.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { build } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { newIdentityKey } from "../server/core/identity";
import { generateVapidKeys } from "../server/core/relay/webpush";

const ORIGIN = "https://relay.example.com";
let mf: import("miniflare").Miniflare;

beforeAll(async () => {
  const { Miniflare, convertV4MiniflareOptions } = await import("miniflare");
  const out = await build({ entryPoints: [path.join(__dirname, "..", "server", "worker", "index.ts")], bundle: true, write: false, format: "esm", platform: "neutral", target: "es2022", mainFields: ["module", "main"], conditions: ["workerd", "worker", "import"] });
  const vapid = await generateVapidKeys();
  mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: out.outputFiles[0].text,
      compatibilityDate: "2026-09-01",
      d1Databases: { DB: "miblo-relay-test" },
      durableObjects: { RELAY: { className: "RelayRoom", useSQLite: true } },
      bindings: {
        PUBLIC_ORIGIN: ORIGIN,
        SESSION_SECRET: crypto.randomBytes(40).toString("base64url"),
        MFA_KEY: crypto.randomBytes(32).toString("base64url"),
        SERVER_IDENTITY_KEY: await newIdentityKey(),
        SETUP_TOKEN: "worker-setup-token-0123456789",
        RELAY_VAPID_PUBLIC_KEY: vapid.publicKey,
        RELAY_VAPID_PRIVATE_KEY: vapid.privateKey,
      },
    } as never),
  );
  const db = await mf.getD1Database("DB");
  const sql = fs.readFileSync(path.join(__dirname, "..", "migrations", "0001_init.sql"), "utf8");
  for (const stmt of sql.replace(/--.*$/gm, "").split(";").map((s) => s.trim()).filter(Boolean)) await db.prepare(stmt).run();
}, 60_000);

afterAll(async () => {
  await mf?.dispose();
});

const call = async (p: string, init: RequestInit = {}) => {
  const res = (await mf.dispatchFetch(`${ORIGIN}${p}`, init as never)) as unknown as Response;
  return { status: res.status, headers: res.headers, data: (await res.json().catch(() => ({}))) as Record<string, unknown> };
};

describe("the Worker (Deploy to your own Cloudflare)", () => {
  it("serves the identity, takes the setup, starts the device flow and upgrades a relay writer", async () => {
    const doc = await call("/.well-known/miblo-relay.json");
    expect(doc.data).toMatchObject({ kind: "miblo-relay", origin: ORIGIN });
    expect(doc.headers.get("strict-transport-security")).toContain("max-age");
    const setup = await call("/api/setup", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: "worker-setup-token-0123456789", username: "ana", password: "correct horse battery" }) });
    expect(setup.status).toBe(200);
    expect(setup.headers.get("set-cookie")).toMatch(/miblo_session=.*; Secure/);
    const start = await call("/api/plus/device/start", { method: "POST", headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.7" }, body: JSON.stringify({ name: "Mac", platform: "darwin" }) });
    expect(start.data.verification_uri).toBe(`${ORIGIN}/plus/link`);
    // A writer upgrade reaches the room's Durable Object, which refuses a room no linked computer
    // registered (no open relay).
    const w = crypto.randomBytes(32).toString("base64url");
    const room = crypto.createHash("sha256").update(`miblo-room-v2|${w}`).digest("base64url").slice(0, 22);
    const res = (await mf.dispatchFetch(`${ORIGIN}/api/relay/${room}?role=writer`, { headers: { Upgrade: "websocket", Authorization: `Bearer ${w}`, "X-Read-Hash": crypto.createHash("sha256").update("r").digest("base64url") } })) as unknown as Response & { webSocket: unknown };
    expect(res.status).toBe(403);
    // Unknown pages are 404 without an assets binding; pages redirect as on Node.
    expect((await mf.dispatchFetch(`${ORIGIN}/app`, { redirect: "manual" } as never)).status).toBe(308);
  });
});
