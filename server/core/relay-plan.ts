// The account side's internal calls to a relay room (POST /__plus through the RELAY namespace,
// never reachable through the router): claim a room with the computer's proof, or set its plan.
// The relay never learns anything about messages; it only keeps "plus" or "free".
import { hmac, sessionSecret } from "./crypto";
import type { Env, RequestScope } from "./env";

/** The opaque key the relay charges the account's pushes to (an HMAC of the user id, 22 characters). */
export async function relayAccount(scope: RequestScope, userId: string): Promise<string> {
  return (await hmac(sessionSecret(scope) ?? "", `relay-account:${userId}`)).slice(0, 22);
}

export type RoomPlan = "free" | "plus";
export type RoomCallResult = "ok" | "bad_proof" | "not_ready" | "unavailable";

async function call(env: Pick<Env, "RELAY">, room: string, body: Record<string, unknown>): Promise<RoomCallResult> {
  const ns = env.RELAY;
  if (!ns) return "unavailable";
  try {
    const stub = ns.get(ns.idFromName(room));
    const res = await stub.fetch("https://relay.internal/__plus", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (res.ok) return "ok";
    if (res.status === 403) return "bad_proof";
    if (res.status === 409) return "not_ready";
    return "unavailable";
  } catch {
    return "unavailable";
  }
}

const untilMs = (iso: string | null) => (iso ? Date.parse(iso) : null);

/** Checks the proof inside the room (it alone knows SHA-256(writeToken)) and sets the plan. */
export function claimRoom(env: Pick<Env, "RELAY">, room: string, challenge: string, proof: string, plan: RoomPlan, until: string | null, account?: string) {
  return call(env, room, { op: "claim", challenge, proof, plan, until: plan === "plus" ? untilMs(until) : null, ...(account ? { account } : {}) });
}

export function setRoomPlan(env: Pick<Env, "RELAY">, room: string, plan: RoomPlan, until: string | null, account?: string) {
  return call(env, room, { op: "set", plan, until: plan === "plus" ? untilMs(until) : null, ...(account ? { account } : {}) });
}
