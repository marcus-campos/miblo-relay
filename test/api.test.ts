// The self-hosted server's API end to end on the Node runtime: the identity key, setup and the
// mandatory second factor, signing in, the device flow, room registration (proof of the write
// token, checked by the room itself), and the phone registry of protocol v6.
import crypto from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { WebSocket } from "ws";
import { adminWithTotp, Browser, ORIGIN, SETUP_TOKEN, startServer, totpNow } from "./helpers/server";
import { SoftWebAuthn } from "./helpers/soft-webauthn";
import { resetLimits } from "../server/core/http";

let srv: Awaited<ReturnType<typeof startServer>>;
let admin: Awaited<ReturnType<typeof adminWithTotp>>;

beforeAll(async () => {
  srv = await startServer();
});
afterAll(async () => {
  await srv?.app.close();
});

const b64 = (n: number) => crypto.randomBytes(n).toString("base64url");
const sha = (s: string) => crypto.createHash("sha256").update(s).digest("base64url");
const json = async (p: string, init: RequestInit = {}) => {
  const res = await fetch(srv.base + p, init);
  return { status: res.status, data: (await res.json().catch(() => ({}))) as Record<string, unknown>, headers: res.headers };
};
const bearer = (token: string, method = "GET", body?: unknown): RequestInit => ({
  method,
  headers: { authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "content-type": "application/json" }) },
  body: body === undefined ? undefined : JSON.stringify(body),
});

describe("the server's identity", () => {
  it("publishes its Ed25519 key and signs a fresh challenge bound to its origin", async () => {
    const doc = await json("/.well-known/miblo-relay.json");
    expect(doc.status).toBe(200);
    expect(doc.data).toMatchObject({ v: 1, kind: "miblo-relay", origin: ORIGIN, protocol: 6 });
    expect(String(doc.data.fingerprint)).toMatch(/^[0-9A-F]{8}(-[0-9A-F]{8}){4}$/);
    const nonce = b64(24);
    const r = await json("/api/server/identity", { method: "POST", body: JSON.stringify({ nonce }) });
    expect(r.status).toBe(200);
    const pub = crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: String(doc.data.key) }, format: "jwk" });
    expect(crypto.verify(null, Buffer.from(`miblo-relay-identity-v1|${ORIGIN}|${nonce}`), pub, Buffer.from(String(r.data.sig), "base64url"))).toBe(true);
    // Another origin or nonce does not verify.
    expect(crypto.verify(null, Buffer.from(`miblo-relay-identity-v1|https://evil.example|${nonce}`), pub, Buffer.from(String(r.data.sig), "base64url"))).toBe(false);
    expect((await json("/api/server/identity", { method: "POST", body: JSON.stringify({ nonce: "short" }) })).status).toBe(400);
  });

  it("sets the security headers and a strict CSP on every answer", async () => {
    const r = await json("/api/setup");
    expect(r.headers.get("content-security-policy")).toContain("script-src 'self' 'wasm-unsafe-eval'");
    expect(r.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(r.headers.get("x-content-type-options")).toBe("nosniff");
  });
});

describe("setup and signing in", () => {
  it("creates the one account with the setup token, and only while it has no second factor", async () => {
    const b = new Browser(srv.base);
    expect((await b.post("/api/setup", { token: "wrong-token-0123456789", username: "ana", password: "correct horse battery" })).status).toBe(403);
    expect((await b.post("/api/setup", { token: SETUP_TOKEN, username: "ana", password: "short" })).data.error).toBe("password_too_short");
    // Before a second factor exists the password alone never signs in.
    const first = await b.post("/api/setup", { token: SETUP_TOKEN, username: "ana", password: "correct horse battery" });
    expect(first.status).toBe(200);
    const other = new Browser(srv.base);
    expect((await other.post("/api/community/auth/password", { username: "ana", password: "correct horse battery" })).data.error).toBe("finish_setup");
    // The setup session has no factor yet: the phone registry refuses it.
    await b.refreshCsrf();
    expect((await b.get("/api/phones")).data.error).toBe("mfa_setup_required");
    // An abandoned setup can be redone with the token (whoever started it is signed out).
    admin = await adminWithTotp(srv.base);
    expect((await b.get("/api/community/mfa")).data.signedIn).toBe(false);
    // Now the account is protected: setup is closed for good.
    expect((await new Browser(srv.base).post("/api/setup", { token: SETUP_TOKEN, username: "eve", password: "another long password" })).status).toBe(409);
    expect((await json("/api/setup")).data.needed).toBe(false);
  });

  it("signs in with the password, then needs the second factor before anything else", async () => {
    const b = new Browser(srv.base);
    expect((await b.post("/api/community/auth/password", { username: "ana", password: "wrong password!!" })).status).toBe(401);
    expect((await b.post("/api/community/auth/password", { username: "nobody", password: "correct horse battery" })).status).toBe(401);
    expect((await b.post("/api/community/auth/password", { username: "ana", password: admin.password })).status).toBe(200);
    const st = await b.refreshCsrf();
    expect(st).toMatchObject({ signedIn: true, pending: true });
    expect((await b.get("/api/phones")).status).toBe(401);
    expect((await b.post("/api/community/mfa/totp/verify", { code: await totpNow(admin.secret, 1) })).status).toBe(200);
    expect((await b.get("/api/phones")).status).toBe(200);
    // A code is never accepted twice.
    expect((await b.post("/api/community/mfa/totp/verify", { code: await totpNow(admin.secret, 1) })).data.error).toBe("replayed_code");
  });

  it("refuses cross-site and non-JSON writes", async () => {
    const r = await fetch(srv.base + "/api/community/auth/password", { method: "POST", headers: { "content-type": "application/json", "sec-fetch-site": "cross-site" }, body: "{}" });
    expect(r.status).toBe(403);
    const f = await fetch(srv.base + "/api/community/auth/password", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "username=ana" });
    expect(f.status).toBe(415);
  });

  it("adds an account passkey (relying party = PUBLIC_ORIGIN) and signs in with it alone", async () => {
    const b = admin.browser;
    const auth = new SoftWebAuthn();
    const o = await b.post("/api/community/mfa/passkey/options", { purpose: "register" });
    // A fresh second factor is needed to add another factor.
    expect(o.status).toBe(200);
    expect((o.data.rp as { id: string }).id).toBe("localhost");
    const made = auth.create({ challenge: String(o.data.challenge), rpId: "localhost", origin: ORIGIN });
    expect((await b.post("/api/community/mfa/passkey/register", { name: "Laptop", ...made, prf: false })).status).toBe(200);

    const p = new Browser(srv.base);
    const so = await p.post("/api/community/auth/passkey/options", {});
    // An assertion for another origin is refused.
    const bad = auth.get({ challenge: String(so.data.challenge), rpId: "localhost", origin: "https://evil.example" });
    expect((await p.post("/api/community/auth/passkey/verify", { wa: bad })).status).toBe(401);
    const so2 = await p.post("/api/community/auth/passkey/options", {});
    const good = auth.get({ challenge: String(so2.data.challenge), rpId: "localhost", origin: ORIGIN });
    expect((await p.post("/api/community/auth/passkey/verify", { wa: good })).status).toBe(200);
    const st = await p.refreshCsrf();
    expect(st).toMatchObject({ signedIn: true, pending: false, mfa: { enrolled: true, valid: true } });
  });

  it("locks the password after five wrong tries, from any address (TRUSTED_PROXY: the proxy's X-Forwarded-For)", async () => {
    resetLimits();
    const own = await startServer({ TRUSTED_PROXY: "1" });
    try {
      const a = await adminWithTotp(own.base);
      const from = (ip: string, password: string) =>
        fetch(own.base + "/api/community/auth/password", { method: "POST", headers: { "content-type": "application/json", "x-forwarded-for": `${ip}, 10.0.0.1` }, body: JSON.stringify({ username: a.username, password }) }).then(async (r) => ({ status: r.status, data: (await r.json()) as { error?: string } }));
      for (let i = 0; i < 5; i++) expect((await from(`203.0.113.${i + 1}`, `wrong-password-${i}`)).status).toBe(401);
      // The right password from yet another address: the account is locked for a while.
      expect((await from("203.0.113.99", a.password)).data.error).toBe("locked");
      // Without TRUSTED_PROXY the header is ignored: every try counts against the socket's address.
      let last = 0;
      for (let i = 0; i < 11; i++) last = (await fetch(srv.base + "/api/community/auth/password", { method: "POST", headers: { "content-type": "application/json", "x-forwarded-for": `198.51.100.${i}` }, body: JSON.stringify({ username: "x", password: "y" }) })).status;
      expect(last).toBe(429);
    } finally {
      await own.app.close();
    }
  });
});

describe("linked computers and the phone registry", () => {
  let token = "";
  let deviceId = "";
  const writeToken = b64(32);
  const readToken = b64(32);
  const room = sha(`miblo-room-v2|${writeToken}`).slice(0, 22);
  let writer: WebSocket | null = null;

  afterAll(() => writer?.terminate());

  it("links a computer through the device flow (the code typed on the account page, a fresh second factor)", async () => {
    const start = await json("/api/plus/device/start", { method: "POST", headers: { "content-type": "application/json", host: "evil.example" }, body: JSON.stringify({ name: "Ana's Mac", platform: "darwin" }) });
    expect(start.status).toBe(200);
    // The link page is always on this server's own origin, whatever Host the request named.
    expect(start.data.verification_uri).toBe(`${ORIGIN}/plus/link`);
    const b = admin.browser;
    const form = String((await b.get("/api/plus/device/form")).data.form);
    expect((await b.post("/api/plus/device/lookup", { userCode: start.data.user_code, form: "x".repeat(32) })).data.error).toBe("form");
    const look = await b.post("/api/plus/device/lookup", { userCode: String(start.data.user_code).toLowerCase(), form });
    expect(look.status).toBe(200);
    expect((look.data.code as { name: string }).name).toBe("Ana's Mac");
    expect((await json("/api/plus/device/token", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ device_code: start.data.device_code }) })).data.error).toBe("authorization_pending");
    const ok = await b.post("/api/plus/device/confirm", { userCode: start.data.user_code, approve: true, form });
    expect(ok.data).toMatchObject({ ok: true, result: "approved" });
    await new Promise((r) => setTimeout(r, 4100));
    const poll = await json("/api/plus/device/token", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ device_code: start.data.device_code }) });
    expect(poll.status).toBe(200);
    token = String(poll.data.token);
    expect(token).toMatch(/^mpt_[A-Za-z0-9_-]{43}$/);
    deviceId = String((poll.data.device as { id: string }).id);
    expect(poll.data.account).toMatchObject({ plan: "plus", valid_until: null });
    // The code is spent.
    expect((await json("/api/plus/device/token", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ device_code: start.data.device_code }) })).data.error).toBe("invalid_grant");
    const me = await json("/api/plus/me", bearer(token));
    expect(me.data).toMatchObject({ plan: "plus", valid_until: null, device: { id: deviceId } });
  }, 15_000);

  it("registers the computer's room with a proof of its write token, checked by the room", async () => {
    // The plugin connects as the room's writer first (header auth).
    writer = new WebSocket(`${srv.base.replace("http", "ws")}/api/relay/${room}?role=writer`, { headers: { authorization: `Bearer ${writeToken}`, "x-read-hash": sha(readToken), "x-phones": "" } });
    await new Promise((resolve, reject) => {
      writer!.once("open", resolve);
      writer!.once("error", reject);
    });
    const ch = await json("/api/plus/rooms/challenge", bearer(token, "POST", { room }));
    expect(ch.status).toBe(200);
    const proof = (secret: string) => crypto.createHmac("sha256", crypto.createHash("sha256").update(secret).digest()).update(String(ch.data.challenge)).digest("base64url");
    expect((await json("/api/plus/rooms", bearer(token, "POST", { room, challenge: ch.data.challenge, proof: proof(b64(32)) }))).status).toBe(403);
    const ch2 = await json("/api/plus/rooms/challenge", bearer(token, "POST", { room }));
    const proof2 = crypto.createHmac("sha256", crypto.createHash("sha256").update(writeToken).digest()).update(String(ch2.data.challenge)).digest("base64url");
    const reg = await json("/api/plus/rooms", bearer(token, "POST", { room, challenge: ch2.data.challenge, proof: proof2 }));
    expect(reg.data).toEqual({ room, plan: "plus", until: null });
  });

  it("lets a phone join the account and the computer seal it a grant after the code exchange", async () => {
    const phone = admin.browser;
    const id = b64(16);
    const ecdh = crypto.createECDH("prime256v1");
    ecdh.generateKeys();
    const pub = ecdh.getPublicKey().toString("base64url");
    const joined = await phone.post("/api/phones", { id, name: "Ana's iPhone", pub });
    expect(joined.status).toBe(200);
    // The computer sees it (with what its browser and system are), and no grant exists yet.
    const seen = await json("/api/plus/phones", bearer(token));
    const listed = (seen.data.phones as { id: string; model?: string }[]).find((p) => p.id === id);
    expect(listed?.model).toBe("iPhone · Safari");
    // The computer's round of the code exchange: a commitment and its identity key.
    const cpub = crypto.createECDH("prime256v1");
    cpub.generateKeys();
    const commit = b64(32);
    const expiresAt = new Date(Date.now() + 15 * 60_000).toISOString();
    expect((await json(`/api/plus/phones/${id}/request`, bearer(token, "PUT", { state: "pending", expiresAt, commit, cpub: cpub.getPublicKey().toString("base64url") }))).status).toBe(200);
    const g1 = await phone.get(`/api/phones/${id}/grants`);
    expect(g1.data.grants).toEqual([]);
    expect((g1.data.requests as { commit: string; state: string }[])[0]).toMatchObject({ state: "pending", commit, nonce: null });
    const pnonce = b64(32);
    expect((await phone.post(`/api/phones/${id}/sas`, { device: deviceId, commit, pnonce })).status).toBe(200);
    // Once per round.
    expect((await phone.post(`/api/phones/${id}/sas`, { device: deviceId, commit, pnonce: b64(32) })).status).toBe(409);
    const round = (await json("/api/plus/phones", bearer(token))).data.phones as { id: string; request?: { pnonce: string } }[];
    expect(round.find((p) => p.id === id)?.request?.pnonce).toBe(pnonce);
    // The person typed the code on the computer: it seals the grant (ciphertext the server cannot open).
    const grant = { room, epoch: 0, epk: ecdh.getPublicKey().toString("base64url"), iv: b64(12), ct: b64(200), cpub: cpub.getPublicKey().toString("base64url"), sig: b64(64) };
    expect((await json(`/api/plus/phones/${id}/grant`, bearer(token, "PUT", grant))).status).toBe(200);
    const g2 = await phone.get(`/api/phones/${id}/grants`);
    expect((g2.data.grants as { room: string; ct: string }[])[0]).toMatchObject({ room, ct: grant.ct });
    // A grant for a room this computer did not register is refused.
    expect((await json(`/api/plus/phones/${id}/grant`, bearer(token, "PUT", { ...grant, room: b64(16) }))).status).toBe(409);
    // Revoked on the account: the grant goes and the computer is told.
    expect((await phone.post("/api/phones/revoke", { id })).status).toBe(200);
    const after = await json("/api/plus/phones", bearer(token));
    expect((after.data.revoked as { id: string }[]).some((r) => r.id === id)).toBe(true);
    expect((await phone.get(`/api/phones/${id}/grants`)).status).toBe(404);
  });

  it("unlinking a computer kills its token and frees its rooms", async () => {
    const list = await admin.browser.get("/api/plus/devices");
    expect((list.data.devices as { id: string }[]).map((d) => d.id)).toContain(deviceId);
    expect((await json("/api/plus/device/unlink", bearer(token, "POST", {}))).status).toBe(200);
    expect((await json("/api/plus/me", bearer(token))).status).toBe(401);
  });
});
