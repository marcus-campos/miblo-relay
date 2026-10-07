// Test-only RelayRoom: a clock the tests can move, its alarm fired on demand, and its storage read
// back. The same class runs in both runtimes (workerd through Miniflare, and Node).
import { RelayRoom } from "../../server/core/relay/room";

export class TestRelayRoom extends RelayRoom {
  private offset = 0;

  protected override now(): number {
    return Date.now() + this.offset;
  }

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/__test/clock") {
      this.offset += Number(url.searchParams.get("advance") ?? 0);
      return new Response("ok");
    }
    if (url.pathname === "/__test/plan") {
      const until = url.searchParams.get("until");
      await this.setPlan(url.searchParams.get("set") === "plus" ? "plus" : "free", until ? Number(until) : undefined);
      return new Response("ok");
    }
    if (url.pathname === "/__test/plus") {
      return super.fetch(new Request("https://relay.internal/__plus", { method: "POST", body: await request.text() }));
    }
    if (url.pathname === "/__test/phones") {
      // v6 push: the account side's "phones changed" call.
      return super.fetch(new Request("https://relay.internal/__phones", { method: request.method }));
    }
    if (url.pathname === "/__test/alarm") {
      await this.alarm();
      return new Response("ok");
    }
    if (url.pathname === "/__test/budget") {
      const day = Math.floor(this.now() / 86_400_000);
      const n = (k: string) => Number(url.searchParams.get(k) ?? 0);
      await this.ctx.storage.put("budget", { day, free: n("free"), plus: n("plus"), alerted: [] });
      return new Response("ok");
    }
    if (url.pathname === "/__test/endpoint" || url.pathname === "/__test/payer") {
      const day = Math.floor(this.now() / 86_400_000);
      const key = url.pathname === "/__test/endpoint" ? `e:${url.searchParams.get("h")}` : String(url.searchParams.get("k"));
      await this.ctx.storage.put(key, { day, n: Number(url.searchParams.get("n") ?? 0) });
      return new Response("ok");
    }
    if (url.pathname === "/__test/roomcap") {
      const k = String(url.searchParams.get("k"));
      const state = url.searchParams.get("state");
      if (state) await this.ctx.storage.put(`r:${k}`, JSON.parse(state));
      return super.fetch(new Request(`https://relay.internal/__push-budget?op=room&k=${k}`));
    }
    if (url.pathname === "/__test/storage") {
      const all = await this.ctx.storage.list({ prefix: "" });
      const sockets = this.ctx.getWebSockets().map((ws) => ({ state: ws.readyState, att: ws.deserializeAttachment(), now: this.now() }));
      return Response.json({ entries: Object.fromEntries(all), alarm: await this.ctx.storage.getAlarm(), sockets });
    }
    return super.fetch(request);
  }
}

/** The test routes: /__test/<room>/<what> reaches that room's TestRelayRoom. */
export const TEST_ROUTE = /^\/__test\/([A-Za-z0-9_-]{22}|push-budget)\/(clock|alarm|storage|plan|budget|plus|endpoint|payer|roomcap|phones)$/;
