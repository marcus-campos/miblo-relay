// The phone app's PIN lockout on the self-hosted server: 10 wrong PINs make the app post this
// server's own sign-out with {"reason":"pin_lockout"} (app/src/components/phone/lock-store.ts):
// the session ends and the event is logged as an account_security line (no e-mail on a self-hosted
// relay); a plain sign-out logs nothing, and a cross-site one changes nothing.
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { adminWithTotp, startServer } from "./helpers/server";
import { endSessionForPin } from "@/components/phone/lock-store";

let srv: Awaited<ReturnType<typeof startServer>>;
let admin: Awaited<ReturnType<typeof adminWithTotp>>;

beforeAll(async () => {
  srv = await startServer();
  admin = await adminWithTotp(srv.base);
});
afterAll(async () => {
  await srv?.app.close();
});

const lockoutLines = (spy: { mock: { calls: unknown[][] } }) =>
  spy.mock.calls.map((c) => String(c[0])).filter((l) => l.includes('"account_security"') && l.includes('"pin_lockout"'));

describe("PIN lockout on a self-hosted server", () => {
  it("a cross-site request neither ends the session nor logs the event", async () => {
    const b = admin.browser;
    const spy = vi.spyOn(console, "log");
    try {
      const r = await fetch(srv.base + "/api/community/auth/logout", {
        method: "POST",
        headers: { "content-type": "application/json", cookie: b.cookie, origin: "https://evil.example", "sec-fetch-site": "cross-site" },
        body: JSON.stringify({ reason: "pin_lockout" }),
      });
      expect(r.status).toBe(403);
      expect(lockoutLines(spy)).toHaveLength(0);
    } finally {
      spy.mockRestore();
    }
    expect((await b.get("/api/community/mfa")).data.signedIn).toBe(true);
  });

  it("ends the session through the sign-out and logs pin_lockout", async () => {
    const b = admin.browser;
    expect((await b.get("/api/community/mfa")).data.signedIn).toBe(true);
    const spy = vi.spyOn(console, "log");
    try {
      // The phone's own call, with this browser's cookie and a same-origin request.
      const phoneFetch = ((url: string, init: RequestInit) =>
        fetch(srv.base + url, { ...init, headers: { ...(init.headers as Record<string, string>), cookie: b.cookie, "sec-fetch-site": "same-origin" } })) as unknown as typeof fetch;
      expect(await endSessionForPin(phoneFetch)).toBe(true);
      expect(lockoutLines(spy)).toHaveLength(1);
      expect(spy.mock.calls.flat().join(" ")).not.toMatch(/\b\d{6}\b.*pin/i);
    } finally {
      spy.mockRestore();
    }
    const st = await fetch(srv.base + "/api/community/mfa", { headers: { cookie: b.cookie, accept: "application/json" } });
    expect(((await st.json()) as { signedIn: boolean }).signedIn).toBe(false);
  });

});
