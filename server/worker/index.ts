// The Cloudflare Worker: the same fetch handler as the Node server, over D1 (DB), one Durable
// Object per relay room (RELAY, the RelayRoom class below) and the built phone app (ASSETS).
// Deploy with deploy/cloudflare (README, "Deploy to your own Cloudflare").
import { RelayRoom as Room, type RelayEnv, type RoomState } from "../core/relay/room";
import type { Env } from "../core/env";
import { scopeOf } from "../core/env";
import { handle } from "../core/site";
import { housekeeping } from "../core/housekeeping";
import { fatalProblems } from "../core/config";
import { cloudflareRuntime } from "./runtime";

type AssetsBinding = { fetch(request: Request): Promise<Response> };
type WorkerEnv = Env & { ASSETS?: AssetsBinding };
type Ctx = { waitUntil(p: Promise<unknown>): void };

export class RelayRoom extends Room {
  constructor(state: unknown, env: RelayEnv) {
    super(state as RoomState, env, cloudflareRuntime);
  }
}

export default {
  async fetch(request: Request, env: WorkerEnv, ctx: Ctx): Promise<Response> {
    const problems = fatalProblems(env);
    if (problems.length) return new Response(`This server is not configured:\n${problems.map((p) => `- ${p}`).join("\n")}\n`, { status: 503 });
    // Cloudflare sets CF-Connecting-IP itself; nothing else may claim to be the client's address.
    const scope = scopeOf(env, (p) => ctx.waitUntil(p));
    return handle(scope, request, async (file, req) => {
      if (!env.ASSETS) return null;
      const url = new URL(req.url);
      url.pathname = file;
      url.search = "";
      const res = await env.ASSETS.fetch(new Request(url, { method: "GET" }));
      return res.ok ? res : null;
    });
  },
  async scheduled(_event: unknown, env: WorkerEnv, ctx: Ctx): Promise<void> {
    ctx.waitUntil(housekeeping(scopeOf(env)).catch(() => console.warn("housekeeping failed")));
  },
};
