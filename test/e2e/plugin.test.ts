// End to end: the real Miblo plugin (its CLI commands, bridge, relay connection, account client and
// phone admission) against this self-hosted server (the Node runtime, on a local port), with a
// phone played by the plugin's own test phone (the same crypto as the phone app):
//
//   miblo server set <this server>      identity fetched, proved and pinned; switch behind the gadget code
//   setup + second factor               the server's one account
//   miblo account link                  device flow, the code confirmed on the account page
//   miblo phone on + the bridge          the writer connects (after the identity proof), the room is registered
//   a phone joins the account            v7: the computer shows a 6-digit code (`miblo phone pending`),
//                                        the phone types it (the PAKE answer through this server, pushed:
//                                        the server's hints, the phone's long poll; join to grant timed),
//                                        the sealed grant with the computer's confirmation
//   the phone connects as a reader       and decrypts the live snapshot the bridge sends
//   miblo phone off                      the room is deleted on this server
// and nothing at all is sent to miblo.ai.
//
// The plugin is not part of this repository: set MIBLO_PLUGIN_DIR to a checkout's plugin/ folder
// (1.23 or later: `miblo server` and the v7 code exchange, lib/plus/pake.js). Without it this file is skipped.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { WebSocket } from "ws";
import { adminWithTotp, Browser, freePort, startServer, totpNow } from "../helpers/server";

const candidates = [process.env.MIBLO_PLUGIN_DIR, path.resolve(__dirname, "../../../claude_gadget/.worktrees/selfhost/plugin")].filter(Boolean) as string[];
const pluginDir = candidates.find((d) => fs.existsSync(path.join(d, "lib", "server-cli.js")) && fs.existsSync(path.join(d, "lib", "plus", "pake.js")));
const suite = pluginDir ? describe : describe.skip;
if (!pluginDir) console.warn("e2e: MIBLO_PLUGIN_DIR is not set to a 1.23+ plugin (`miblo server`, v7); skipping the plugin end-to-end test.");

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Any = any;
const load = (rel: string): Promise<Any> => import(pathToFileURL(path.join(pluginDir!, rel)).href);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
// Polls slowly enough for the server's per-account limit (30 account calls a minute).
async function until<T>(fn: () => T | Promise<T>, ms = 15_000, every = 250): Promise<T> {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error("timed out");
    await sleep(every);
  }
}

suite("the plugin against a self-hosted server", () => {
  let srv: Awaited<ReturnType<typeof startServer>>;
  let dataDir = "";
  const calls: string[] = [];
  const realFetch = globalThis.fetch;
  let bridge: Any = null;

  beforeAll(async () => {
    // The plugin accepts http only for a loopback server under MIBLO_TEST=1 (never in real use).
    process.env.MIBLO_TEST = "1";
    // Every fetch the plugin makes is recorded: none may go to miblo.ai.
    globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
      calls.push(String(input instanceof Request ? input.url : input));
      return realFetch(input as RequestInfo, init);
    }) as typeof fetch;
    srv = await startServer({}, { port: await freePort() });
    dataDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "miblo-relay-e2e-")));
  });

  afterAll(async () => {
    globalThis.fetch = realFetch;
    try {
      bridge?.phone?.stop?.();
      bridge?.server?.close?.();
    } catch {
      // Already down.
    }
    await srv?.app.close();
  });

  it("switches the plugin to this server, links it, admits a phone and relays the live snapshot end to end", async () => {
    const { serverCommand } = await load("lib/server-cli.js");
    const { plusCommand } = await load("lib/plus/plus-cli.js");
    const { phoneCommand } = await load("lib/phone-cli.js");
    const { readServer } = await load("lib/server-config.js");
    const { readAccount } = await load("lib/plus/plus-config.js");
    const { readSecrets, decryptFrame } = await load("lib/phone-secrets.js");
    const { readerToken } = await load("lib/plus/plus-crypto.js");
    const { createBridge } = await load("bin/bridge.js");
    const { fakePresence } = await load("test/fakes/fake-presence.js");
    const { makeAccountPhone } = await load("test/fakes/test-phone.js");
    const terminal = { context: () => "terminal" };

    // 1. `miblo server set`: the identity key is read and proved, the fingerprint shown, the gadget's code typed.
    const printed: string[] = [];
    const doc = (await (await realFetch(`${srv.base}/.well-known/miblo-relay.json`)).json()) as { fingerprint: string };
    const set = await serverCommand(["set", srv.origin], { dataDir, gate: terminal, print: (t: string) => printed.push(t), ...fakePresence().deps });
    expect(set.code, set.out).toBe(0);
    expect(printed.join("")).toContain(doc.fingerprint);
    expect(readServer(dataDir)).toMatchObject({ kind: "custom", origin: srv.origin, fingerprint: doc.fingerprint });

    // 2. The server's account, with its second factor.
    const admin = await adminWithTotp(srv.base);

    // 3. `miblo account link`: a code, confirmed on the account page, then the token.
    const first = JSON.parse((await plusCommand(["link", "--wait", "0", "--json"], { dataDir, hostname: "Ana-Mac", runClaude: () => ({ status: 0 }) })).out);
    expect(first.state).toBe("pending");
    expect(first.verificationUri).toBe(`${srv.origin}/plus/link`);
    const form = String((await admin.browser.get("/api/plus/device/form")).data.form);
    expect((await admin.browser.post("/api/plus/device/lookup", { userCode: first.userCode, form })).status).toBe(200);
    expect((await admin.browser.post("/api/plus/device/confirm", { userCode: first.userCode, approve: true, form })).data.result).toBe("approved");
    const linked = JSON.parse((await plusCommand(["link", "--wait", "0", "--json"], { dataDir, hostname: "Ana-Mac", runClaude: () => ({ status: 0 }) })).out);
    expect(linked.state, JSON.stringify(linked)).toBe("linked");
    expect(readAccount(dataDir)).toMatchObject({ plan: "plus", validUntil: null });

    // 4. `miblo phone on` and the bridge: the writer connects once the server proved its key, and
    // the room is registered with the account (plan plus, no end).
    expect((await phoneCommand(["on"], { dataDir, hostname: "Ana-Mac", gate: terminal })).code).toBe(0);
    const secrets = readSecrets(dataDir);
    bridge = createBridge({ dataDir, discoverFn: async () => [], host: "Ana-Mac" });
    await bridge.push();
    // The bridge's tick registers the room first (this server accepts no writer in a room no
    // linked computer registered), then the relay connects.
    await until(() => {
      bridge.plus.tick();
      return bridge.phone.connected;
    }, 20_000);
    await until(async () => {
      bridge.plus.tick();
      return readAccount(dataDir)?.room === secrets.room;
    });

    // 5. A phone joins the account: signs in (password + second factor), registers its key and passkey.
    const phone = makeAccountPhone({ rpId: "127.0.0.1", origin: srv.origin, name: "Ana iPhone" });
    const pb = new Browser(srv.base);
    expect((await pb.post("/api/community/auth/password", { username: admin.username, password: admin.password })).status).toBe(200);
    await pb.refreshCsrf();
    expect((await pb.post("/api/community/mfa/totp/verify", { code: await totpNow(admin.secret, 1) })).status).toBe(200);
    const listing = phone.listing();
    // v6 push: from here nothing makes the bridge read the account but the server's hints on its
    // relay connection; the phone follows with the long poll (`?wait=<sig>`), as the phone app does.
    // A plugin from before push reads on its timer: the test makes it read instead.
    const push = typeof (await load("lib/plus/account-phones.js")).HINT_GAP_MS === "number";
    const read = () => (push ? Promise.resolve() : bridge.plus.accountPhones.sync());
    await sleep(1500); // the connection's own catch-up read is over
    const t0 = Date.now();
    expect((await pb.post("/api/phones", { id: listing.id, name: listing.name, pub: listing.pub, att: listing.att, cdj: listing.cdj })).status).toBe(200);

    // The computer asks the person, with an attempt of the code exchange (its share, never the code).
    let sig: string | null = null;
    const next = async (want: (r: Any) => unknown) => {
      for (let i = 0; i < 10; i++) {
        const v = await pb.get(`/api/phones/${phone.id}/grants${sig ? `?wait=${sig}` : ""}`);
        sig = String(v.data.sig);
        const hit = (v.data.requests as Any[])?.find(want);
        if (hit) return hit;
      }
      throw new Error("timed out");
    };
    await read();
    const req = await next((r: Any) => r.pake);
    expect(req.commit ?? null).toBeNull();
    // The person reads the code this computer shows (`miblo phone pending`) and types it on the phone.
    const pending = JSON.parse((await phoneCommand(["pending", "--json"], { dataDir, hostname: "Ana-Mac", gate: terminal })).out) as Any[];
    const code = pending.find((p: Any) => p.id === phone.id)?.code as string;
    expect(code).toMatch(/^\d{6}$/);
    expect(JSON.stringify(req)).not.toContain(code);
    expect((await pb.post(`/api/phones/${phone.id}/pake`, { device: req.device.id, ...phone.answer(req, code) })).status).toBe(200);
    // The computer checks the answer (told by the server's hint) and seals the grant by itself.
    await read();
    const grants = await until(async () => {
      const g = (await pb.get(`/api/phones/${phone.id}/grants`)).data.grants as Any[];
      return g?.length ? g : null;
    });
    const ms = Date.now() - t0;
    if (push) {
      console.log(`push (real plugin bridge + self-hosted server, loopback): phone join -> grant in ${ms} ms`);
      expect(ms).toBeLessThan(8000);
    }
    const opened = phone.trustedOpen(grants![0]);
    expect(opened).toMatchObject({ v: 6, kind: "grant", room: secrets.room, key: secrets.key });

    // 6. The phone connects to the relay with its own reader token and reads the live snapshot.
    const ws = new WebSocket(`${srv.base.replace("http", "ws")}/api/relay/${opened.room}?role=reader`);
    const frames: Any[] = [];
    ws.on("message", (d) => frames.push(JSON.parse(d.toString())));
    await new Promise((resolve, reject) => {
      ws.once("open", resolve);
      ws.once("error", reject);
    });
    let closed: number | null = null;
    ws.on("close", (c) => (closed = c));
    // The room knows this phone's token once the writer told it (after the approval).
    await until(async () => JSON.stringify((await (srv.app.rooms.hosts.get(opened.room) as Any)?.room.ctx.storage.get("meta"))?.phones ?? {}).includes(phone.id));
    ws.send(JSON.stringify({ t: "auth", token: readerToken(opened.macKey, opened.room, phone.id), phone: phone.id }));
    await bridge.push();
    const status = await until(() => frames.find((f) => f.t === "msg" && (f.ch ?? "status") === "status" && !f.k), 15_000);
    expect(closed).toBeNull();
    const snapshot = decryptFrame({ key: opened.key, room: opened.room }, status);
    expect(snapshot).toBeTruthy();
    expect(JSON.stringify(snapshot)).toContain("Ana-Mac");
    ws.close();

    // 7. `miblo phone off`: the room on this server is deleted.
    bridge.phone.stop();
    const off = await phoneCommand(["off"], { dataDir, hostname: "Ana-Mac", gate: terminal });
    expect(off.out).toContain("127.0.0.1");
    expect(off.out).toMatch(/deleted/);

    // Nothing of any of this went to miblo.ai.
    expect(calls.filter((u) => /miblo\.ai/.test(u))).toEqual([]);
    expect(calls.some((u) => u.startsWith(srv.base))).toBe(true);
  }, 90_000);
});
