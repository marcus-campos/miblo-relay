// A real self-hosted server for tests (the Node runtime, in memory, on a random port) and a
// browser-like client with a cookie jar and the CSRF token.
import crypto from "node:crypto";
import net from "node:net";
import path from "node:path";
import { createRelayServer } from "../../server/node/server";
import { newIdentityKey } from "../../server/core/identity";
import { generateVapidKeys } from "../../server/core/relay/webpush";
import { totpCode, base32Decode } from "../../server/core/account/mfa";

export const SETUP_TOKEN = "test-setup-token-0123456789";
export const ORIGIN = "http://localhost";

/** A free local port (for a server whose PUBLIC_ORIGIN must name its own port). */
export function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const port = (s.address() as { port: number }).port;
      s.close(() => resolve(port));
    });
  });
}

export async function startServer(extra: Record<string, string> = {}, opts: { port?: number } = {}) {
  const vapid = await generateVapidKeys();
  const origin = opts.port ? `http://127.0.0.1:${opts.port}` : ORIGIN;
  const app = await createRelayServer({
    env: {
      PUBLIC_ORIGIN: origin,
      MIBLO_RELAY_DEV: "1",
      SESSION_SECRET: crypto.randomBytes(40).toString("base64url"),
      MFA_KEY: crypto.randomBytes(32).toString("base64url"),
      SERVER_IDENTITY_KEY: await newIdentityKey(),
      SETUP_TOKEN,
      RELAY_VAPID_PUBLIC_KEY: vapid.publicKey,
      RELAY_VAPID_PRIVATE_KEY: vapid.privateKey,
      ...extra,
    },
    dbFile: ":memory:",
    migrationsDir: path.join(__dirname, "..", "..", "migrations"),
    publicDir: null,
  });
  const port = await app.listen(opts.port ?? 0, "127.0.0.1");
  return { app, base: `http://127.0.0.1:${port}`, port, origin };
}

/** A browser: cookies kept, JSON calls with the CSRF token once known. */
export class Browser {
  cookie = "";
  csrf = "";
  constructor(
    readonly base: string,
    readonly ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
  ) {}
  async req(method: string, p: string, body?: unknown): Promise<{ status: number; data: Record<string, unknown> }> {
    const headers: Record<string, string> = { "user-agent": this.ua, accept: "application/json", "sec-fetch-site": "same-origin" };
    if (this.cookie) headers.cookie = this.cookie;
    if (body !== undefined) headers["content-type"] = "application/json";
    if (this.csrf) headers["x-csrf-token"] = this.csrf;
    const res = await fetch(this.base + p, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const set = res.headers.getSetCookie?.() ?? [];
    for (const c of set) {
      const [kv] = c.split(";");
      if (/Max-Age=0/.test(c)) this.cookie = "";
      else this.cookie = kv;
    }
    let data: Record<string, unknown> = {};
    try {
      data = (await res.json()) as Record<string, unknown>;
    } catch {
      data = {};
    }
    return { status: res.status, data };
  }
  get(p: string) {
    return this.req("GET", p);
  }
  post(p: string, body: unknown = {}) {
    return this.req("POST", p, body);
  }
  async refreshCsrf(): Promise<Record<string, unknown>> {
    const st = await this.get("/api/community/mfa");
    this.csrf = String(st.data.csrf ?? "");
    return st.data;
  }
}

/** The current TOTP code of a base32 secret. */
export async function totpNow(secret: string, offsetSteps = 0): Promise<string> {
  return totpCode(base32Decode(secret), Math.floor(Date.now() / 30_000) + offsetSteps);
}

/**
 * The account made and protected with an authenticator app: setup, TOTP, a signed-in browser
 * whose second factor is fresh. -> { browser, secret }.
 */
export async function adminWithTotp(base: string, username = "ana", password = "correct horse battery") {
  const b = new Browser(base);
  const s = await b.post("/api/setup", { token: SETUP_TOKEN, username, password });
  if (s.status !== 200) throw new Error(`setup ${s.status} ${JSON.stringify(s.data)}`);
  return protectWithTotp(b, username, password);
}

/** The setup session `b` adds an authenticator app (setup done). -> { browser, secret }. */
export async function protectWithTotp(b: Browser, username = "ana", password = "correct horse battery") {
  await b.refreshCsrf();
  const t = await b.post("/api/community/mfa/totp/setup", {});
  const secret = String(t.data.secret);
  const c = await b.post("/api/community/mfa/totp/confirm", { code: await totpNow(secret) });
  if (c.status !== 200) throw new Error(`totp confirm ${c.status} ${JSON.stringify(c.data)}`);
  await b.refreshCsrf();
  return { browser: b, secret, username, password };
}
