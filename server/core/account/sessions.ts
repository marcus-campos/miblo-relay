// The server's one account (a self-hosted server serves one person) and its sessions: server-side
// sessions in a signed cookie, CSRF tokens, and the second factor each session passed.
//
// - Session: the cookie is "<id>.<HMAC(secret, id)>"; the database keeps SHA-256(id), the user and
//   the expiry. Deleting the row revokes it. HttpOnly, Secure (on https), SameSite=Lax, 30 days,
//   refreshed daily.
// - CSRF: every mutation needs X-CSRF-Token = HMAC(secret, "csrf:" + id) on top of the JSON-only,
//   same-origin checks of readJson().
// Adapted from the miblo.ai account code (same cookie, CSRF and second-factor model), without
// email sign-in links, communities, bans or anything else a single-person server has no use for.
import { hmac, hmacVerify, nowIso, randomToken, sessionSecret, sha256Hex } from "../crypto";
import type { RequestScope } from "../env";

export const SESSION_COOKIE = "miblo_session";
export const SESSION_DAYS = 30;

/** The account. `email` is the account's name (what the phone app shows as the signed-in person). */
export type User = { id: string; email: string; display_name: string; lang: string };

/**
 * The session's second factor: whether the account has one (a passkey or a confirmed TOTP), when
 * this session last passed it and how. A session of an account with a second factor that has not
 * passed it yet is `pending`: only the second-factor step and signing out accept it.
 */
export type SessionMfa = { enrolled: boolean; at: number | null; method: string | null };
/** `remote` is always false here (kept for the shared route helpers). */
export type Session = { user: User; idHash: string; csrf: string; mfa: SessionMfa; pending: boolean; remote: boolean };

export function cookieValue(cookieHeader: string | null, name: string): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) {
      try {
        return decodeURIComponent(v.join("="));
      } catch {
        return null;
      }
    }
  }
  return null;
}

function secure(origin: string): string {
  return new URL(origin).protocol === "https:" ? "; Secure" : "";
}

export function sessionCookie(value: string, origin: string): string {
  return `${SESSION_COOKIE}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}${secure(origin)}`;
}

export function clearSessionCookie(origin: string): string {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure(origin)}`;
}

/** Creates a session row and returns the cookie value. `mfa`: the session passed it at sign-in (a passkey). */
export async function createSession(scope: RequestScope, uid: string, userAgent: string, mfa: { method: string; cred: string | null } | null = null): Promise<string> {
  const secret = sessionSecret(scope);
  if (!secret) throw new Error("SESSION_SECRET missing");
  const id = randomToken(32);
  const now = new Date();
  const expires = new Date(now.getTime() + SESSION_DAYS * 86400_000);
  await scope.env.DB.prepare(
    `INSERT INTO sessions (id_hash, user_id, created_at, expires_at, last_seen_at, user_agent, mfa_at, mfa_method, mfa_cred) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(await sha256Hex(id), uid, now.toISOString(), expires.toISOString(), now.toISOString(), userAgent.slice(0, 120), mfa ? now.toISOString() : null, mfa?.method ?? null, mfa?.cred ?? null)
    .run();
  return `${id}.${await hmac(secret, id)}`;
}

/**
 * The signed-in session for a request's Cookie header, or null. A session still waiting for its
 * second factor reads as null unless `allowPending` (the second-factor step, signing out).
 */
export async function sessionFromCookie(scope: RequestScope, cookieHeader: string | null, opts: { allowPending?: boolean } = {}): Promise<Session | null> {
  const secret = sessionSecret(scope);
  if (!secret) return null;
  const raw = cookieValue(cookieHeader, SESSION_COOKIE);
  if (!raw || raw.length > 200) return null;
  const dot = raw.indexOf(".");
  if (dot < 1) return null;
  const id = raw.slice(0, dot);
  if (!(await hmacVerify(secret, id, raw.slice(dot + 1)))) return null;
  const idHash = await sha256Hex(id);
  const row = await scope.env.DB.prepare(
    `SELECT s.expires_at, s.last_seen_at, s.mfa_at, s.mfa_method, u.id, u.username, u.lang,
            (EXISTS (SELECT 1 FROM mfa_passkeys p WHERE p.user_id = u.id)
              OR EXISTS (SELECT 1 FROM mfa_totp t WHERE t.user_id = u.id AND t.confirmed_at IS NOT NULL)) AS mfa_enrolled
       FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = ?`,
  )
    .bind(idHash)
    .first<{ expires_at: string; last_seen_at: string; mfa_at: string | null; mfa_method: string | null; mfa_enrolled: number; id: string; username: string; lang: string }>();
  if (!row) return null;
  const now = Date.now();
  if (Date.parse(row.expires_at) <= now) {
    await scope.env.DB.prepare(`DELETE FROM sessions WHERE id_hash = ?`).bind(idHash).run();
    return null;
  }
  // Sliding expiry, written at most once a day.
  if (now - Date.parse(row.last_seen_at) > 86400_000) {
    await scope.env.DB.prepare(`UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id_hash = ?`)
      .bind(new Date(now).toISOString(), new Date(now + SESSION_DAYS * 86400_000).toISOString(), idHash)
      .run();
  }
  const mfa: SessionMfa = { enrolled: !!row.mfa_enrolled, at: row.mfa_at ? Date.parse(row.mfa_at) : null, method: row.mfa_method };
  const pending = mfa.enrolled && mfa.at === null;
  if (pending && !opts.allowPending) return null;
  const user: User = { id: row.id, email: row.username, display_name: row.username, lang: row.lang === "en" ? "en" : "pt" };
  return { user, idHash, csrf: await hmac(secret, `csrf:${id}`), mfa, pending, remote: false };
}

export async function csrfValid(session: Session, given: string | null): Promise<boolean> {
  if (!given || given.length > 100) return false;
  // Both are HMAC outputs of the same length; compare without early exit.
  const a = session.csrf;
  if (a.length !== given.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ given.charCodeAt(i);
  return diff === 0;
}

export async function revokeSession(scope: RequestScope, idHash: string): Promise<void> {
  await scope.env.DB.prepare(`DELETE FROM sessions WHERE id_hash = ?`).bind(idHash).run();
}

/** Signs out everywhere else (or everywhere, without `keep`). */
export async function revokeUserSessions(scope: RequestScope, uid: string, keep?: string): Promise<void> {
  await scope.env.DB.prepare(`DELETE FROM sessions WHERE user_id = ? AND id_hash != ?`).bind(uid, keep ?? "").run();
}

/** The account's sign-ins, for the Security section. */
export async function listSessions(scope: RequestScope, session: Session) {
  const rows = await scope.env.DB.prepare(`SELECT id_hash, user_agent, last_seen_at, mfa_at FROM sessions WHERE user_id = ? AND expires_at > ? ORDER BY last_seen_at DESC`)
    .bind(session.user.id, nowIso())
    .all<{ id_hash: string; user_agent: string; last_seen_at: string; mfa_at: string | null }>();
  return rows.results.map((r) => ({ id: r.id_hash.slice(0, 16), userAgent: r.user_agent, lastSeenAt: r.last_seen_at, mfa: !!r.mfa_at, current: r.id_hash === session.idHash }));
}

/** Ends one of the account's sign-ins by its listed id (never the current one). */
export async function revokeListedSession(scope: RequestScope, session: Session, id: string): Promise<boolean> {
  if (!/^[0-9a-f]{16}$/.test(id) || session.idHash.startsWith(id)) return false;
  const r = await scope.env.DB.prepare(`DELETE FROM sessions WHERE user_id = ? AND substr(id_hash, 1, 16) = ?`).bind(session.user.id, id).run();
  return r.meta.changes > 0;
}
