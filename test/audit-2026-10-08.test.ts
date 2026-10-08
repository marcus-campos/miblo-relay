// Security audit 2026-10-08 (miblo-platform docs/audits/2026-10-08-web.md): relay regressions.
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { LIMIT_KEYS, resetLimits } from "../server/core/http";
import { startServer } from "./helpers/server";

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
