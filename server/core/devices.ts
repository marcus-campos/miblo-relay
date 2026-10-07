// Linking computers to the server's account (same API as miblo.ai's, so the plugin's
// `miblo account link` works unchanged):
// - Device authorisation, OAuth 2.0 device-flow style: the computer gets a device code (kept
//   secret on the computer, only its SHA-256 stored) and a short user code; the person types the
//   user code shown in their own terminal at /plus/link while signed in (second factor passed in
//   the last 5 minutes); the computer's next poll receives an opaque token, once. Codes last 10
//   minutes.
// - Against device-code phishing (RFC 8628 section 5.4): no link carries the code (the page never
//   takes it from a link, only from its own form), the page warns to confirm only a code the
//   person's own terminal shows right now and shows when it was asked for, the first signed-in
//   session that looks a code up holds it, and a code is used once.
// - Against code floods: a network (a keyed hash of its IP, never the IP) holds at most
//   MAX_CODES_PER_NETWORK live codes, on top of the per-IP rate limit and the global cap.
// - The token (stored as SHA-256) authenticates the computer's room registrations and phone calls.
// - A room is registered with a proof of its write token: HMAC-SHA256 keyed with
//   SHA-256(writeToken) over a challenge we signed. The room itself checks it (it saw the write
//   token when the computer connected as writer); the write token never leaves the computer.
// A self-hosted server has no plans or licenses: every linked computer's rooms get the "plus"
// plan with no end (history, replies, approvals, tasks), for as long as the computer stays linked.
import { base64url, hmac, hmacVerify, nowIso, randomToken, sessionSecret, sha256Hex } from "./crypto";
import type { D1Result, RequestScope } from "./env";
import { isRoom } from "./relay/protocol";
import { clientNetwork, limited } from "./http";
import { publicOrigin } from "./config";
import { allowRoom, claimRoom, relayAccount } from "./relay-plan";
import { bumpAccountRevs } from "./phones";

/** Device authorisation: code lifetime and the minimum polling interval. */
const DEVICE_CODE_MINUTES = 10;
const POLL_INTERVAL_SECONDS = 5;
/** Linked computers per account and relay rooms one linked computer may register. */
export const DEVICES_MAX = 10;
const ROOMS_PER_DEVICE = 4;

/** RFC 8628's suggestion: consonants only (no vowels, so no words; no digits, so never "13"). */
const USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ";
export const DEVICE_TOKEN_RE = /^mpt_[A-Za-z0-9_-]{43}$/;
const CHALLENGE_TTL_MS = 5 * 60_000;
/** Above this many live codes, new ones are refused (a flood cannot fill the table). */
const MAX_LIVE_CODES = 5000;
/** Live codes one network may hold at once (a keyed hash of the IP; the IP is never stored). */
export const MAX_CODES_PER_NETWORK = 5;

export function newUserCode(): string {
  let out = "";
  // 20 symbols: reject bytes >= 240 so the draw stays uniform.
  while (out.length < 8) {
    for (const b of crypto.getRandomValues(new Uint8Array(16))) {
      if (b < 240 && out.length < 8) out += USER_CODE_ALPHABET[b % 20];
    }
  }
  return `${out.slice(0, 4)}-${out.slice(4)}`;
}

/** "bcdf ghjk", "BCDF-GHJK" and "bcdfghjk" all mean the same code. */
export function normalizeUserCode(value: string): string | null {
  const s = value.toUpperCase().replace(/[^A-Z]/g, "");
  if (s.length !== 8 || [...s].some((c) => !USER_CODE_ALPHABET.includes(c))) return null;
  return `${s.slice(0, 4)}-${s.slice(4)}`;
}

export type DeviceStart = {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
};

/**
 * The network a request comes from, as the device flow may count it: HMAC of its IP (an IPv6
 * address by its /64, where one host can pick any address), 22 characters.
 */
export async function networkHash(scope: RequestScope, ip: string): Promise<string> {
  // The hash only bounds live codes per network; nothing about the network is kept longer.
  return (await hmac(sessionSecret(scope) ?? "", `plus-net:${clientNetwork(ip)}`)).slice(0, 22);
}

export async function startDeviceAuthorization(
  scope: RequestScope,
  input: { name: string; platform: string },
  now = Date.now(),
  origin: { net?: string | null; country?: string | null } = {},
): Promise<DeviceStart | "busy" | "network_limit"> {
  const { DB } = scope.env;
  const nowIsoStr = new Date(now).toISOString();
  const country = typeof origin.country === "string" && /^[A-Z]{2}$/.test(origin.country) && origin.country !== "XX" && origin.country !== "T1" ? origin.country : null;
  const deviceCode = randomToken(32);
  const expires = new Date(now + DEVICE_CODE_MINUTES * 60_000).toISOString();
  let userCode = newUserCode();
  // A pending code, even an expired one the cron has not deleted yet, keeps its user code: the
  // unique index (plus_device_codes_pending_user_code) refuses a second pending row with it.
  for (let i = 0; i < 5; i++) {
    const clash = await DB.prepare(`SELECT 1 FROM plus_device_codes WHERE user_code = ? AND status = 'pending'`).bind(userCode).first();
    if (!clash) break;
    userCode = newUserCode();
  }
  // One statement: the caps are checked and the code inserted together, so parallel starts from
  // one network cannot all pass a count read before any of them was written.
  const insert = DB.prepare(
    `INSERT INTO plus_device_codes (device_code_hash, user_code, status, name, platform, created_at, expires_at, net_hash, country)
     SELECT ?1, ?2, 'pending', ?3, ?4, ?5, ?6, ?7, ?8
      WHERE (SELECT COUNT(*) FROM plus_device_codes WHERE expires_at > ?5 AND status = 'pending') < ?9
        AND (?7 IS NULL OR (SELECT COUNT(*) FROM plus_device_codes WHERE net_hash = ?7 AND expires_at > ?5 AND status = 'pending') < ?10)`,
  )
    .bind(await sha256Hex(deviceCode), userCode, input.name, input.platform, nowIsoStr, expires, origin.net ?? null, country, MAX_LIVE_CODES, MAX_CODES_PER_NETWORK);
  let r: D1Result;
  try {
    r = await insert.run();
  } catch (e) {
    // A parallel start drew the same code between the check and the insert: the computer retries.
    if (/UNIQUE/i.test(String((e as Error)?.message ?? e))) return "busy";
    throw e;
  }
  if (!r.meta.changes) {
    const live = await DB.prepare(`SELECT COUNT(*) AS n FROM plus_device_codes WHERE expires_at > ? AND status = 'pending'`).bind(nowIsoStr).first<{ n: number }>();
    return (live?.n ?? 0) >= MAX_LIVE_CODES ? "busy" : "network_limit";
  }
  const base = publicOrigin(scope.env)!.origin;
  return {
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: `${base}/plus/link`,
    // No link carries the code: the member types the one their own terminal shows (RFC 8628 5.4).
    verification_uri_complete: `${base}/plus/link`,
    expires_in: DEVICE_CODE_MINUTES * 60,
    interval: POLL_INTERVAL_SECONDS,
  };
}

export type PendingCode = { user_code: string; name: string; platform: string; expires_at: string; created_at: string; country: string | null; minutesAgo: number };

/** The brute-force guard on /plus/link lookups: ten a minute per account. */
export function linkLookupLimited(userId: string): boolean {
  return limited(`lookup:${userId}`, 10);
}

/**
 * The code a signed-in member is about to confirm (for the /plus/link page), or null. The first
 * member who looks a code up holds it: for anyone else it no longer exists.
 */
export async function findPendingCode(scope: RequestScope, rawCode: string, userId: string, now = Date.now()): Promise<PendingCode | null> {
  const code = normalizeUserCode(rawCode);
  if (!code) return null;
  const row = await scope.env.DB.prepare(
    `UPDATE plus_device_codes SET viewer_user_id = COALESCE(viewer_user_id, ?1)
       WHERE user_code = ?2 AND status = 'pending' AND expires_at > ?3 AND (viewer_user_id IS NULL OR viewer_user_id = ?1)
       RETURNING user_code, name, platform, expires_at, created_at, country`,
  )
    .bind(userId, code, new Date(now).toISOString())
    .first<Omit<PendingCode, "minutesAgo">>();
  return row ? { ...row, minutesAgo: Math.max(0, Math.round((now - Date.parse(row.created_at)) / 60_000)) } : null;
}

export async function activeDeviceCount(scope: RequestScope, userId: string): Promise<number> {
  const row = await scope.env.DB.prepare(`SELECT COUNT(*) AS n FROM plus_devices WHERE user_id = ? AND revoked_at IS NULL`).bind(userId).first<{ n: number }>();
  return row?.n ?? 0;
}

export type ConfirmResult = "approved" | "denied" | "invalid_code" | "device_limit";

/** The signed-in member approves (or refuses) a computer's code. */
export async function confirmDeviceCode(scope: RequestScope, userId: string, rawCode: string, approve: boolean, now = Date.now()): Promise<ConfirmResult> {
  const code = normalizeUserCode(rawCode);
  if (!code) return "invalid_code";
  if (approve && (await activeDeviceCount(scope, userId)) >= DEVICES_MAX) return "device_limit";
  // Only the member who looked the code up on the page (and only once: pending -> approved/denied).
  const row = await scope.env.DB.prepare(
    `UPDATE plus_device_codes SET status = ?, user_id = ? WHERE user_code = ? AND status = 'pending' AND expires_at > ? AND viewer_user_id = ? RETURNING device_code_hash`,
  )
    .bind(approve ? "approved" : "denied", userId, code, new Date(now).toISOString(), userId)
    .first<{ device_code_hash: string }>();
  if (!row) return "invalid_code";
  return approve ? "approved" : "denied";
}

const FORM_HOUR_MS = 3600_000;

/**
 * The token of the /plus/link page's own form for this session (this hour): a code reaches the
 * confirmation only through that form, never from a link someone sent (RFC 8628 section 5.4).
 */
export async function linkFormToken(scope: RequestScope, idHash: string, now = Date.now()): Promise<string> {
  return (await hmac(sessionSecret(scope) ?? "", `plus-link-form:${idHash}:${Math.floor(now / FORM_HOUR_MS)}`)).slice(0, 32);
}

export async function linkFormTokenValid(scope: RequestScope, idHash: string, token: string | undefined, now = Date.now()): Promise<boolean> {
  if (typeof token !== "string" || !/^[A-Za-z0-9_-]{32}$/.test(token)) return false;
  for (const t of [now, now - FORM_HOUR_MS]) if ((await linkFormToken(scope, idHash, t)) === token) return true;
  return false;
}

/** What the account's email says about a computer just linked: its name and the country it asked from. */
export async function linkedDetail(scope: RequestScope, rawCode: string): Promise<string> {
  const code = normalizeUserCode(rawCode);
  const row = code
    ? await scope.env.DB.prepare(`SELECT name, platform, country FROM plus_device_codes WHERE user_code = ? ORDER BY created_at DESC LIMIT 1`)
        .bind(code)
        .first<{ name: string; platform: string; country: string | null }>()
    : null;
  return row ? `${row.name} (${row.platform}${row.country ? `, ${row.country}` : ""})` : "";
}

export type PollResult =
  | { ok: true; token: string; device: { id: string; name: string; platform: string }; devicesUsed: number }
  | { ok: false; error: "authorization_pending" | "slow_down" | "expired_token" | "access_denied" | "invalid_grant" | "device_limit" };

/** The computer's poll. The token is handed out exactly once; a consumed code is invalid_grant. */
export async function pollDeviceCode(scope: RequestScope, deviceCode: string, now = Date.now()): Promise<PollResult> {
  const { DB } = scope.env;
  if (!/^[A-Za-z0-9_-]{43}$/.test(deviceCode)) return { ok: false, error: "invalid_grant" };
  const hash = await sha256Hex(deviceCode);
  const row = await DB.prepare(`SELECT status, user_id, name, platform, expires_at, last_poll_at FROM plus_device_codes WHERE device_code_hash = ?`)
    .bind(hash)
    .first<{ status: string; user_id: string | null; name: string; platform: string; expires_at: string; last_poll_at: string | null }>();
  if (!row || row.status === "consumed") return { ok: false, error: "invalid_grant" };
  if (row.status === "denied") return { ok: false, error: "access_denied" };
  if (Date.parse(row.expires_at) <= now) return { ok: false, error: "expired_token" };
  const nowIsoStr = new Date(now).toISOString();
  await DB.prepare(`UPDATE plus_device_codes SET last_poll_at = ? WHERE device_code_hash = ?`).bind(nowIsoStr, hash).run();
  // RFC 8628: polling faster than the interval earns slow_down (allow a second of jitter).
  if (row.last_poll_at && now - Date.parse(row.last_poll_at) < (POLL_INTERVAL_SECONDS - 1) * 1000) return { ok: false, error: "slow_down" };
  if (row.status !== "approved") return { ok: false, error: "authorization_pending" };

  const claimed = await DB.prepare(
    `UPDATE plus_device_codes SET status = 'consumed' WHERE device_code_hash = ? AND status = 'approved' RETURNING user_id`,
  )
    .bind(hash)
    .first<{ user_id: string }>();
  if (!claimed) return { ok: false, error: "invalid_grant" };
  const userId = claimed.user_id;
  // Re-checked here: another computer may have been linked since the code was confirmed.
  if ((await activeDeviceCount(scope, userId)) >= DEVICES_MAX) return { ok: false, error: "device_limit" };
  const token = `mpt_${randomToken(32)}`;
  const id = `dev_${randomToken(12)}`;
  await DB.prepare(`INSERT INTO plus_devices (id, user_id, kind, name, platform, token_hash, created_at, last_seen_at) VALUES (?, ?, 'computer', ?, ?, ?, ?, ?)`)
    .bind(id, userId, row.name, row.platform, await sha256Hex(token), nowIsoStr, nowIsoStr)
    .run();
  return { ok: true, token, device: { id, name: row.name, platform: row.platform }, devicesUsed: await activeDeviceCount(scope, userId) };
}

export type LinkedDevice = { id: string; user_id: string; name: string; platform: string; last_seen_at: string | null };

/** The linked computer behind "Authorization: Bearer mpt_…", or null (unknown or revoked). */
export async function deviceFromRequest(scope: RequestScope, request: Request): Promise<LinkedDevice | null> {
  const m = /^Bearer (mpt_[A-Za-z0-9_-]{43})$/.exec(request.headers.get("authorization")?.trim() ?? "");
  if (!m) return null;
  const row = await scope.env.DB.prepare(`SELECT id, user_id, name, platform, last_seen_at FROM plus_devices WHERE token_hash = ? AND revoked_at IS NULL`)
    .bind(await sha256Hex(m[1]))
    .first<LinkedDevice>();
  if (!row) return null;
  const now = Date.now();
  if (!row.last_seen_at || now - Date.parse(row.last_seen_at) > 3600_000) {
    await scope.env.DB.prepare(`UPDATE plus_devices SET last_seen_at = ? WHERE id = ?`).bind(new Date(now).toISOString(), row.id).run();
  }
  return row;
}

/** A challenge for registering `room` from `deviceId`: signed, 5 minutes, bound to both. */
export async function roomChallenge(scope: RequestScope, deviceId: string, room: string, now = Date.now()): Promise<{ challenge: string; expires_in: number }> {
  const secret = sessionSecret(scope)!;
  const payload = base64url(new TextEncoder().encode(JSON.stringify({ v: 1, r: room, d: deviceId, e: now + CHALLENGE_TTL_MS, n: randomToken(12) })));
  return { challenge: `mpc1.${payload}.${await hmac(secret, `plus-room:${payload}`)}`, expires_in: CHALLENGE_TTL_MS / 1000 };
}

async function challengeValid(scope: RequestScope, challenge: string, deviceId: string, room: string, now: number): Promise<boolean> {
  const secret = sessionSecret(scope);
  const parts = challenge.split(".");
  if (!secret || parts.length !== 3 || parts[0] !== "mpc1") return false;
  if (!(await hmacVerify(secret, `plus-room:${parts[1]}`, parts[2]))) return false;
  try {
    const data = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/"))) as { r?: string; d?: string; e?: number };
    return data.r === room && data.d === deviceId && typeof data.e === "number" && now < data.e;
  } catch {
    return false;
  }
}

export type RegisterResult =
  | { ok: true; room: string; plan: "free" | "plus"; until: string | null }
  | { ok: false; error: "invalid_challenge" | "invalid_proof" | "room_not_ready" | "room_limit" | "relay_unavailable"; status: number };

export async function registerRoom(
  scope: RequestScope,
  device: LinkedDevice,
  input: { room: string; challenge: string; proof: string },
  now = Date.now(),
): Promise<RegisterResult> {
  const { DB } = scope.env;
  if (!isRoom(input.room) || !(await challengeValid(scope, input.challenge, device.id, input.room, now))) {
    return { ok: false, error: "invalid_challenge", status: 400 };
  }
  const mine = await DB.prepare(`SELECT COUNT(*) AS n FROM plus_rooms WHERE device_id = ? AND room != ?`).bind(device.id, input.room).first<{ n: number }>();
  if ((mine?.n ?? 0) >= ROOMS_PER_DEVICE) return { ok: false, error: "room_limit", status: 409 };
  const desired = { plan: "plus" as const, until: null };
  // The room may be used from now on (its writer is refused before: no open relay), even if the
  // writer has not connected yet; the claim below then needs it connected.
  if ((await allowRoom(scope.env, input.room, true)) !== "ok") return { ok: false, error: "relay_unavailable", status: 503 };
  const verdict = await claimRoom(scope.env, input.room, input.challenge, input.proof, desired.plan, desired.until, await relayAccount(scope, device.user_id));
  if (verdict === "bad_proof") return { ok: false, error: "invalid_proof", status: 403 };
  if (verdict === "not_ready") return { ok: false, error: "room_not_ready", status: 409 };
  if (verdict !== "ok") return { ok: false, error: "relay_unavailable", status: 503 };
  const ts = new Date(now).toISOString();
  // The proof shows control of the room: it moves to this computer if another one had it.
  await DB.prepare(
    `INSERT INTO plus_rooms (room, device_id, user_id, applied_plan, applied_until, synced_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(room) DO UPDATE SET device_id = excluded.device_id, user_id = excluded.user_id, applied_plan = excluded.applied_plan,
       applied_until = excluded.applied_until, synced_at = excluded.synced_at, sync_error = NULL, updated_at = excluded.updated_at`,
  )
    .bind(input.room, device.id, device.user_id, desired.plan, desired.until, ts, ts, ts)
    .run();
  return { ok: true, room: input.room, plan: desired.plan, until: desired.until };
}

/** Unregisters a room of this computer: it goes back to free right away. */
export async function removeRoom(scope: RequestScope, device: LinkedDevice, room: string): Promise<boolean> {
  if (!isRoom(room)) return false;
  const row = await scope.env.DB.prepare(`SELECT room FROM plus_rooms WHERE room = ? AND device_id = ?`).bind(room, device.id).first();
  if (!row) return false;
  await allowRoom(scope.env, room, false);
  await scope.env.DB.prepare(`DELETE FROM plus_rooms WHERE room = ?`).bind(room).run();
  await scope.env.DB.prepare(`DELETE FROM phone_grants WHERE device_id = ? AND room = ?`).bind(device.id, room).run();
  await bumpAccountRevs(scope, device.user_id).run();
  return true;
}

/** Unlinks a computer (from itself or from the account page): token dead, its rooms free. */
export async function revokeDevice(scope: RequestScope, userId: string, deviceId: string): Promise<boolean> {
  const { DB } = scope.env;
  const done = await DB.prepare(`UPDATE plus_devices SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL RETURNING id`)
    .bind(nowIso(), deviceId, userId)
    .first();
  if (!done) return false;
  const rooms = await DB.prepare(`SELECT room FROM plus_rooms WHERE device_id = ?`).bind(deviceId).all<{ room: string }>();
  for (const r of rooms.results) {
    // Best effort; the room row goes either way. The room itself goes too (no more writer).
    await allowRoom(scope.env, r.room, false);
  }
  await DB.prepare(`DELETE FROM plus_rooms WHERE device_id = ?`).bind(deviceId).run();
  // Protocol v6: the pairings it sealed to the account's phones go with it.
  await DB.prepare(`DELETE FROM phone_grants WHERE device_id = ?`).bind(deviceId).run();
  await DB.prepare(`DELETE FROM phone_requests WHERE device_id = ?`).bind(deviceId).run();
  // The phones' long polls notice (phones.ts waitForGrants).
  await bumpAccountRevs(scope, userId).run();
  return true;
}

export async function listDevices(scope: RequestScope, userId: string) {
  const rows = await scope.env.DB.prepare(
    `SELECT d.id, d.name, d.platform, d.created_at, d.last_seen_at, (SELECT COUNT(*) FROM plus_rooms r WHERE r.device_id = d.id) AS rooms
       FROM plus_devices d WHERE d.user_id = ? AND d.revoked_at IS NULL ORDER BY d.created_at`,
  )
    .bind(userId)
    .all<{ id: string; name: string; platform: string; created_at: string; last_seen_at: string | null; rooms: number }>();
  return rows.results;
}

/** What GET /api/plus/me answers to a linked computer: always "plus", with no end. */
export async function deviceSummary(scope: RequestScope, device: LinkedDevice) {
  const rooms = await scope.env.DB.prepare(`SELECT room, applied_plan, applied_until FROM plus_rooms WHERE device_id = ? ORDER BY created_at`)
    .bind(device.id)
    .all<{ room: string; applied_plan: string; applied_until: string | null }>();
  return {
    plan: "plus",
    status: "active",
    current_period_end: null,
    valid_until: null,
    devices: { used: await activeDeviceCount(scope, device.user_id), max: DEVICES_MAX },
    device: { id: device.id, name: device.name, platform: device.platform },
    rooms: rooms.results.map((r) => ({ room: r.room, plan: r.applied_plan, until: r.applied_until })),
  };
}
