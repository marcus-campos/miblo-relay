// The RelayRoom's runtime on Cloudflare: a WebSocketPair and its 101 answer, and the keep-alive
// answered by the platform without waking the Durable Object (hibernation).
import type { RoomRuntime, RoomSocket, RoomState } from "../core/relay/room";

declare const WebSocketPair: { new (): { 0: unknown; 1: unknown } };
declare const WebSocketRequestResponsePair: { new (request: string, response: string): unknown };

export const cloudflareRuntime: RoomRuntime = {
  upgrade() {
    const pair = new WebSocketPair();
    const response = new Response(null, { status: 101, webSocket: pair[0] } as ResponseInit);
    return { server: pair[1] as RoomSocket, response };
  },
  autoPong(state: RoomState, ping: string, pong: string) {
    (state as unknown as { setWebSocketAutoResponse(p: unknown): void }).setWebSocketAutoResponse(new WebSocketRequestResponsePair(ping, pong));
  },
};
