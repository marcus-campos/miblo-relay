// Security audit 2026-10-08 (miblo-platform docs/audits/2026-10-08-web.md): relay regressions.
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { LIMIT_KEYS, resetLimits } from "../server/core/http";
import crypto from "node:crypto";
import http from "node:http";
import { adminWithTotp, Browser, startServer } from "./helpers/server";

let srv: Awaited<ReturnType<typeof startServer>>;

beforeAll(async () => {
  // Requests come through a proxy on 127.0.0.1 that names the client (X-Forwarded-For).
  srv = await startServer({ TRUSTED_PROXY: "127.0.0.1" });
});
afterAll(async () => {
  await srv?.app.close();
});
afterEach(() => resetLimits());

const from = (ip: string, body: unknown) => ({
  method: "POST",
  headers: { "content-type": "application/json", "x-forwarded-for": ip, "sec-fetch-site": "same-origin" },
  body: JSON.stringify(body),
});

describe("R1: a flood of new networks cannot lock everyone out of the server", () => {
  it("one /48 sending from thousands of /64s leaves the owner's sign-in (another network) answered", async () => {
    // The attacker: one free IPv6 /48 (a tunnel), a new /64 for every request, no account.
    const batch = 250;
    for (let i = 0; i < LIMIT_KEYS + 50; i += batch) {
      await Promise.all(
        Array.from({ length: batch }, (_, j) => {
          const n = i + j;
          return fetch(`${srv.base}/api/server/identity`, from(`2001:db8:77:${n.toString(16)}::1`, { nonce: "x".repeat(32) })).then((r) => r.arrayBuffer());
        }),
      );
    }
    // The owner signs in from home, right after: refused only on the merits (no such account), never 429.
    const r = await fetch(`${srv.base}/api/community/auth/password`, from("198.51.100.7", { username: "ana", password: "correct horse battery" }));
    expect(r.status).not.toBe(429);
    // The attacker's own networks are still held to their limits (the flood never reset a count).
    let refused = 0;
    for (let k = 0; k < 70; k++) {
      const x = await fetch(`${srv.base}/api/server/identity`, from("2001:db8:77:1::1", { nonce: "x".repeat(32) }));
      if (x.status === 429) refused++;
    }
    expect(refused).toBeGreaterThan(0);
  }, 120_000);
});

describe("RL2 (L1, L3 of miblo.ai): passkey options and the grants long poll", () => {
  let own: Awaited<ReturnType<typeof startServer>>;
  let browser: Browser;
  beforeAll(async () => {
    own = await startServer();
    browser = (await adminWithTotp(own.base)).browser;
  });
  afterAll(async () => {
    await own?.app.close();
  });

  it("passkey options read the body only after the session and origin checks", async () => {
    const post = (headers: Record<string, string>) =>
      fetch(`${own.base}/api/community/mfa/passkey/options`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: "{" + "x".repeat(200_000) });
    // Before: 400 (the body was parsed first). Now: no session, so the body is never looked at.
    expect((await post({ "sec-fetch-site": "same-origin" })).status).toBe(401);
    // Signed in, cross-site: refused before reading.
    expect((await post({ cookie: browser.cookie, "x-csrf-token": browser.csrf, "sec-fetch-site": "cross-site" })).status).toBe(403);
    // Signed in, same-origin: the body is read with the size limit.
    expect((await post({ cookie: browser.cookie, "x-csrf-token": browser.csrf, "sec-fetch-site": "same-origin" })).status).toBe(413);
    // Both purposes still work.
    expect((await browser.post("/api/community/mfa/passkey/options", { purpose: "register" })).status).toBe(200);
    expect((await browser.post("/api/community/mfa/passkey/options", { purpose: "verify" })).status).toBe(404);
  });

  it("a long poll whose client went away stops reading at once (Node: request.signal)", async () => {
    const ecdh = crypto.createECDH("prime256v1");
    ecdh.generateKeys();
    const id = crypto.randomBytes(16).toString("base64url");
    expect((await browser.post("/api/phones", { id, name: "Pixel", pub: ecdh.getPublicKey().toString("base64url") })).status).toBe(200);
    const sig = String((await browser.get(`/api/phones/${id}/grants`)).data.sig);
    // Count the long poll's looks (one change-counter read each).
    let looks = 0;
    const prepare = own.app.db.prepare.bind(own.app.db);
    own.app.db.prepare = ((sql: string) => {
      if (sql.startsWith("SELECT rev FROM account_phones")) looks++;
      return prepare(sql);
    }) as typeof own.app.db.prepare;
    try {
      const req = http.request(`${own.base}/api/phones/${id}/grants?wait=${sig}`, { headers: { cookie: browser.cookie, "sec-fetch-site": "same-origin" } });
      req.on("error", () => {});
      req.end();
      await new Promise((r) => setTimeout(r, 1200));
      expect(looks).toBeGreaterThan(0);
      req.destroy();
      await new Promise((r) => setTimeout(r, 700));
      const after = looks;
      await new Promise((r) => setTimeout(r, 2000));
      // Before: about 4 more looks in these 2 s (until the 20 s end). Now: none.
      expect(looks).toBe(after);
    } finally {
      own.app.db.prepare = prepare;
    }
  });
});
