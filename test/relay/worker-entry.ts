// Test-only Worker for the relay suite on workerd (bundled by esbuild, run in Miniflare): the real
// router and the TestRelayRoom, with the Cloudflare runtime.
import { handleRelay, type RelayRouterEnv } from "../../server/core/relay/router";
import { PUSH_BUDGET_OBJECT, type RelayEnv, type RoomState } from "../../server/core/relay/room";
import { cloudflareRuntime } from "../../server/worker/runtime";
import { TestRelayRoom as Room, TEST_ROUTE } from "./test-room";

export class TestRelayRoom extends Room {
  constructor(state: unknown, env: RelayEnv) {
    super(state as RoomState, env, cloudflareRuntime);
  }
}

export default {
  async fetch(request: Request, env: RelayRouterEnv): Promise<Response> {
    const url = new URL(request.url);
    const test = TEST_ROUTE.exec(url.pathname);
    if (test) {
      const name = test[1] === "push-budget" ? PUSH_BUDGET_OBJECT : test[1];
      const stub = env.RELAY.get(env.RELAY.idFromName(name));
      const body = request.method === "POST" ? await request.text() : undefined;
      return stub.fetch(`https://relay.internal/__test/${test[2]}${url.search}`, { method: request.method, body });
    }
    // Miniflare gives every request the same client IP: a test names the network it plays with
    // X-Test-IP (the new-room limit per network), and without one there is none.
    const headers = new Headers(request.headers);
    headers.delete("CF-Connecting-IP");
    const testIp = headers.get("X-Test-IP");
    if (testIp) headers.set("CF-Connecting-IP", testIp);
    headers.delete("X-Test-IP");
    const req = new Request(request.url, { method: request.method, headers, body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body });
    return (await handleRelay(req, env)) ?? new Response("not found", { status: 404 });
  },
};
