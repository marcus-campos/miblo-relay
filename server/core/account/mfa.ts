// The account's second factor, mandatory on a self-hosted server. First factor: the account's
// password (or a passkey alone, which is both). Second factor: a passkey with user verification
// (WebAuthn, the recommended one) or, for devices without passkeys, a TOTP app (RFC 6238). Ten
// single-use recovery codes restore access to the account.
//
// - Passkeys: only the public key is stored; every assertion needs user verification, the right
//   origin and relying party (PUBLIC_ORIGIN, never the request's Host), a single-use 5-minute
//   challenge made for this session, and a counter that moves forward.
// - TOTP: the secret is shown once, kept AES-GCM encrypted under the MFA_KEY secret (AAD = the user
//   id); codes are accepted for the current step ±1, and never the same step twice.
// - Recovery codes: kept as HMACs under a key derived from MFA_KEY (HKDF, its own label); each
//   works once.
// - Every check counts as an attempt per account before the code or assertion is even looked at,
//   in one atomic statement (reserveAttempt): at most MFA_MAX_FAILURES checks run per
//   MFA_FAILURE_WINDOW_MS, whatever arrives in parallel, then the second factor locks for
//   MFA_LOCK_MS; a success clears the count (on top of the per-IP limits of the routes).
// Secrets, codes and keys are never logged. Adapted from the miblo.ai account code.
import { base64url, base64urlDecode, nowIso, randomToken, sha256Hex } from "../crypto";
import type { RequestScope } from "../env";
import { verifyAssertion, verifyRegistration, type Relying, type StoredKey } from "./webauthn";
import type { Session } from "./sessions";
import { MFA_FAILURE_WINDOW_MS, MFA_LOCK_MS, MFA_MAX_FAILURES } from "./mfa-policy";

const CHALLENGE_MS = 5 * 60 * 1000;
export const TOTP_STEP_S = 30;
export const TOTP_DIGITS = 6;
export const RECOVERY_CODES = 10;
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const enc = new TextEncoder();

export type Factors = {
  passkeys: { id: string; name: string; prf: boolean; createdAt: string; lastUsedAt: string | null }[];
  totp: boolean;
  recoveryLeft: number;
};

export async function factorsOf(scope: RequestScope, uid: string): Promise<Factors> {
  const { DB } = scope.env;
  const [pk, totp, rec] = await DB.batch([
    DB.prepare(`SELECT id, name, prf, created_at, last_used_at FROM mfa_passkeys WHERE user_id = ? ORDER BY created_at`).bind(uid),
    DB.prepare(`SELECT confirmed_at FROM mfa_totp WHERE user_id = ?`).bind(uid),
    DB.prepare(`SELECT COUNT(*) AS n FROM mfa_recovery_codes WHERE user_id = ? AND used_at IS NULL`).bind(uid),
  ]);
  return {
    passkeys: (pk.results as { id: string; name: string; prf: number; created_at: string; last_used_at: string | null }[]).map((r) => ({
      id: r.id,
      name: r.name,
      prf: !!r.prf,
      createdAt: r.created_at,
      lastUsedAt: r.last_used_at,
    })),
    totp: !!(totp.results[0] as { confirmed_at: string | null } | undefined)?.confirmed_at,
    recoveryLeft: (rec.results[0] as { n: number }).n,
  };
}

// SQL conditions for a removal that must leave the account (?1) a second factor.
/** Passkey ?2 goes: another passkey or a confirmed authenticator app stays. */
const KEEPS_FACTOR_WITHOUT_PASSKEY = `(EXISTS (SELECT 1 FROM mfa_passkeys WHERE user_id = ?1 AND id != ?2) OR EXISTS (SELECT 1 FROM mfa_totp WHERE user_id = ?1 AND confirmed_at IS NOT NULL))`;
/** The authenticator app goes: a passkey stays. */
const KEEPS_FACTOR_WITHOUT_TOTP = `EXISTS (SELECT 1 FROM mfa_passkeys WHERE user_id = ?1)`;

const factorCount = (f: Factors) => f.passkeys.length + (f.totp ? 1 : 0);

/** Whether the account has a second factor (then every new session must pass it). */
export async function hasSecondFactor(scope: RequestScope, uid: string): Promise<boolean> {
  const row = await scope.env.DB.prepare(
    `SELECT (EXISTS (SELECT 1 FROM mfa_passkeys WHERE user_id = ?1) OR EXISTS (SELECT 1 FROM mfa_totp WHERE user_id = ?1 AND confirmed_at IS NOT NULL)) AS yes`,
  )
    .bind(uid)
    .first<{ yes: number }>();
  return !!row?.yes;
}

/** A self-hosted account must always keep a second factor (it guards the phone registry). */
export async function factorRequired(_scope: RequestScope, _uid: string): Promise<boolean> {
  return true;
}

/** Whether removing one factor would leave a required account without any. */
export async function lastRequiredFactor(scope: RequestScope, uid: string): Promise<boolean> {
  return factorCount(await factorsOf(scope, uid)) <= 1 && (await factorRequired(scope, uid));
}

/** Marks the session as having passed the second factor now. */
export async function markSessionMfa(scope: RequestScope, idHash: string, method: "passkey" | "totp" | "recovery", cred: string | null = null): Promise<void> {
  await scope.env.DB.prepare(`UPDATE sessions SET mfa_at = ?, mfa_method = ?, mfa_cred = ? WHERE id_hash = ?`).bind(nowIso(), method, cred, idHash).run();
}

// --- attempts and lockout ----------------------------------------------------------------------

export async function mfaLocked(scope: RequestScope, uid: string, now = Date.now()): Promise<boolean> {
  const row = await scope.env.DB.prepare(`SELECT locked_until FROM mfa_failures WHERE user_id = ?`).bind(uid).first<{ locked_until: string | null }>();
  return !!row?.locked_until && Date.parse(row.locked_until) > now;
}

/**
 * Counts one second-factor attempt for the account, atomically, before it is checked. -> true when
 * this attempt may be checked. A single INSERT ... ON CONFLICT DO UPDATE ... RETURNING: D1 runs it
 * as one write, so parallel attempts each get their own count (no lost updates) and at most
 * MFA_MAX_FAILURES of them are ever checked in a window. The attempt that reaches the limit arms
 * the lock (MFA_LOCK_MS); while it holds every attempt is refused and counted; a success clears it
 * all (clearFailures). The window restarts only once the lock is over.
 */
export async function reserveAttempt(scope: RequestScope, uid: string, now = Date.now()): Promise<boolean> {
  const nowIsoStr = new Date(now).toISOString();
  const cutoff = new Date(now - MFA_FAILURE_WINDOW_MS).toISOString();
  const lock = new Date(now + MFA_LOCK_MS).toISOString();
  const locked = `(mfa_failures.locked_until IS NOT NULL AND mfa_failures.locked_until > ?2)`;
  const fresh = `(NOT ${locked} AND mfa_failures.window_start < ?3)`;
  const next = `(CASE WHEN ${fresh} THEN 1 ELSE mfa_failures.count + 1 END)`;
  const row = await scope.env.DB.prepare(
    `INSERT INTO mfa_failures (user_id, count, window_start, locked_until) VALUES (?1, 1, ?2, CASE WHEN 1 >= ?4 THEN ?5 ELSE NULL END)
     ON CONFLICT(user_id) DO UPDATE SET
       count = ${next},
       window_start = CASE WHEN ${fresh} THEN ?2 ELSE mfa_failures.window_start END,
       locked_until = CASE WHEN ${locked} THEN mfa_failures.locked_until WHEN ${next} >= ?4 THEN ?5 ELSE NULL END
     RETURNING count, locked_until`,
  )
    .bind(uid, nowIsoStr, cutoff, MFA_MAX_FAILURES, lock)
    .first<{ count: number; locked_until: string | null }>();
  return !!row && row.count <= MFA_MAX_FAILURES;
}

export async function clearFailures(scope: RequestScope, uid: string): Promise<void> {
  await scope.env.DB.prepare(`DELETE FROM mfa_failures WHERE user_id = ?`).bind(uid).run();
}

// --- WebAuthn challenges -----------------------------------------------------------------------

async function newChallenge(scope: RequestScope, session: Session, purpose: "register" | "verify"): Promise<string> {
  const { DB } = scope.env;
  const challenge = randomToken(32);
  await DB.batch([
    DB.prepare(`DELETE FROM mfa_challenges WHERE expires_at < ?`).bind(nowIso()),
    DB.prepare(`INSERT INTO mfa_challenges (challenge_hash, session_hash, user_id, purpose, expires_at) VALUES (?, ?, ?, ?, ?)`).bind(
      await sha256Hex(challenge),
      session.idHash,
      session.user.id,
      purpose,
      new Date(Date.now() + CHALLENGE_MS).toISOString(),
    ),
  ]);
  return challenge;
}

/** Spends a challenge made for this session and purpose. */
async function takeChallenge(scope: RequestScope, session: Session, challenge: string, purpose: string): Promise<boolean> {
  if (typeof challenge !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) return false;
  const row = await scope.env.DB.prepare(
    `DELETE FROM mfa_challenges WHERE challenge_hash = ? AND session_hash = ? AND user_id = ? AND purpose = ? AND expires_at > ? RETURNING 1 AS ok`,
  )
    .bind(await sha256Hex(challenge), session.idHash, session.user.id, purpose, nowIso())
    .first<{ ok: number }>();
  return !!row;
}

/** The challenge in a clientDataJSON (base64url), or "" when unreadable. */
function challengeOf(cdj: unknown): string {
  try {
    const cd = JSON.parse(new TextDecoder().decode(base64urlDecode(String(cdj)))) as { challenge?: unknown };
    return typeof cd.challenge === "string" ? cd.challenge : "";
  } catch {
    return "";
  }
}

// --- passkeys ----------------------------------------------------------------------------------

/** Options for navigator.credentials.create(): a platform or roaming passkey, UV required, PRF asked. */
export async function registrationOptions(scope: RequestScope, session: Session, rp: Relying) {
  const existing = await scope.env.DB.prepare(`SELECT id FROM mfa_passkeys WHERE user_id = ?`).bind(session.user.id).all<{ id: string }>();
  return {
    challenge: await newChallenge(scope, session, "register"),
    rp: { id: rp.rpId, name: "Miblo" },
    user: { id: base64url(enc.encode(session.user.id)), name: session.user.email, displayName: session.user.display_name },
    excludeCredentials: existing.results.map((r) => r.id),
  };
}

export async function registerPasskey(
  scope: RequestScope,
  session: Session,
  rp: Relying,
  body: { name: string; att: string; cdj: string; prf: boolean },
): Promise<{ ok: true; id: string } | { ok: false; reason: string }> {
  const challenge = challengeOf(body.cdj);
  if (!(await takeChallenge(scope, session, challenge, "register"))) return { ok: false, reason: "bad_challenge" };
  const reg = await verifyRegistration({ att: body.att, cdj: body.cdj, challenge, rp });
  if (!reg.ok) return { ok: false, reason: reg.reason };
  const { DB } = scope.env;
  const taken = await DB.prepare(`SELECT 1 FROM mfa_passkeys WHERE id = ?`).bind(reg.credId).first();
  if (taken) return { ok: false, reason: "known_credential" };
  await DB.prepare(`INSERT INTO mfa_passkeys (id, user_id, name, alg, public_key, sign_count, prf, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(reg.credId, session.user.id, body.name, reg.key.alg, JSON.stringify(reg.key.jwk), reg.signCount, body.prf ? 1 : 0, nowIso())
    .run();
  await notify(scope, session, "passkey_added");
  return { ok: true, id: reg.credId };
}

/** Options for navigator.credentials.get(): this account's passkeys, UV required. */
export async function assertionOptions(scope: RequestScope, session: Session, rp: Relying) {
  const rows = await scope.env.DB.prepare(`SELECT id FROM mfa_passkeys WHERE user_id = ?`).bind(session.user.id).all<{ id: string }>();
  return { challenge: await newChallenge(scope, session, "verify"), rpId: rp.rpId, allowCredentials: rows.results.map((r) => r.id) };
}

export async function verifyPasskey(
  scope: RequestScope,
  session: Session,
  rp: Relying,
  wa: { cred: string; ad: string; cdj: string; sig: string },
): Promise<{ ok: true } | { ok: false; reason: string }> {
  const uid = session.user.id;
  if (!(await reserveAttempt(scope, uid))) return { ok: false, reason: "locked" };
  const challenge = challengeOf(wa.cdj);
  if (!(await takeChallenge(scope, session, challenge, "verify"))) return { ok: false, reason: "bad_challenge" };
  const row = await scope.env.DB.prepare(`SELECT id, alg, public_key, sign_count FROM mfa_passkeys WHERE id = ? AND user_id = ?`)
    .bind(String(wa.cred), uid)
    .first<{ id: string; alg: number; public_key: string; sign_count: number }>();
  if (!row) return { ok: false, reason: "unknown_credential" };
  const key: StoredKey = { alg: row.alg === -257 ? -257 : -7, jwk: JSON.parse(row.public_key) as JsonWebKey };
  const v = await verifyAssertion({ key, credId: row.id, signCount: row.sign_count, wa, challenge, rp });
  if (!v.ok) return { ok: false, reason: v.reason };
  await scope.env.DB.prepare(`UPDATE mfa_passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?`).bind(v.signCount, nowIso(), row.id).run();
  await clearFailures(scope, uid);
  await markSessionMfa(scope, session.idHash, "passkey", row.id);
  return { ok: true };
}

// --- signing in with a passkey (no email) ---------------------------------------------------------

/** mfa_challenges rows for passkey sign-in belong to no session yet: this marks them. */
const SIGNIN_SESSION = "signin";

/**
 * Options for signing in with a passkey alone: a single-use 5-minute challenge and no credential
 * list (account passkeys are discoverable: the browser offers the ones it has for this server).
 */
export async function signInOptions(scope: RequestScope, rp: Relying): Promise<{ challenge: string; rpId: string; allowCredentials: string[] }> {
  const { DB } = scope.env;
  const challenge = randomToken(32);
  await DB.batch([
    DB.prepare(`DELETE FROM mfa_challenges WHERE expires_at < ?`).bind(nowIso()),
    DB.prepare(`INSERT INTO mfa_challenges (challenge_hash, session_hash, user_id, purpose, expires_at) VALUES (?, ?, '', 'signin', ?)`).bind(
      await sha256Hex(challenge),
      SIGNIN_SESSION,
      new Date(Date.now() + CHALLENGE_MS).toISOString(),
    ),
  ]);
  return { challenge, rpId: rp.rpId, allowCredentials: [] };
}

/**
 * Signs in with a passkey: the assertion (user verification required, origin and relying party
 * pinned, counter moving forward) over a sign-in challenge names the account. It is both factors at
 * once (possession of the device and its biometric or PIN), so the new session has passed the
 * second factor with that passkey. A success clears the account's second-factor failures.
 */
export async function signInWithPasskey(
  scope: RequestScope,
  rp: Relying,
  wa: { cred: string; ad: string; cdj: string; sig: string },
): Promise<{ ok: true; uid: string; cred: string } | { ok: false; reason: string }> {
  const challenge = challengeOf(wa.cdj);
  if (!/^[A-Za-z0-9_-]{43}$/.test(challenge)) return { ok: false, reason: "bad_challenge" };
  const { DB } = scope.env;
  const spent = await DB.prepare(
    `DELETE FROM mfa_challenges WHERE challenge_hash = ? AND session_hash = ? AND purpose = 'signin' AND expires_at > ? RETURNING 1 AS ok`,
  )
    .bind(await sha256Hex(challenge), SIGNIN_SESSION, nowIso())
    .first<{ ok: number }>();
  if (!spent) return { ok: false, reason: "bad_challenge" };
  const row = await DB.prepare(`SELECT id, user_id, alg, public_key, sign_count FROM mfa_passkeys WHERE id = ?`)
    .bind(String(wa.cred))
    .first<{ id: string; user_id: string; alg: number; public_key: string; sign_count: number }>();
  if (!row) return { ok: false, reason: "unknown_credential" };
  // Checked before anything is counted: a bad assertion naming someone's credential id costs that
  // account nothing (no lockout by credential id), and a good one is never refused by a lock that
  // others' wrong codes set (only the authenticator can make it).
  const key: StoredKey = { alg: row.alg === -257 ? -257 : -7, jwk: JSON.parse(row.public_key) as JsonWebKey };
  const v = await verifyAssertion({ key, credId: row.id, signCount: row.sign_count, wa, challenge, rp });
  if (!v.ok) return { ok: false, reason: v.reason };
  // The counter moves only forward, even against a racing assertion of the same passkey.
  const moved = await DB.prepare(`UPDATE mfa_passkeys SET sign_count = ?, last_used_at = ? WHERE id = ? AND (sign_count < ? OR sign_count = 0) RETURNING 1 AS ok`)
    .bind(v.signCount, nowIso(), row.id, v.signCount)
    .first<{ ok: number }>();
  if (!moved) return { ok: false, reason: "sign_count" };
  await clearFailures(scope, row.user_id);
  return { ok: true, uid: row.user_id, cred: row.id };
}

export async function removePasskey(scope: RequestScope, session: Session, id: string): Promise<{ ok: true } | { ok: false; reason: string }> {
  const uid = session.user.id;
  const row = await scope.env.DB.prepare(`SELECT 1 FROM mfa_passkeys WHERE id = ? AND user_id = ?`).bind(id, uid).first();
  if (!row) return { ok: false, reason: "not_found" };
  if (await lastRequiredFactor(scope, uid)) return { ok: false, reason: "last_factor" };
  // The check again, inside the one statement that deletes: two removals at once can never take
  // the account down to no second factor.
  const gone = await scope.env.DB.prepare(`DELETE FROM mfa_passkeys WHERE user_id = ?1 AND id = ?2 AND ${KEEPS_FACTOR_WITHOUT_PASSKEY}`).bind(uid, id).run();
  if (!gone.meta.changes) return { ok: false, reason: "last_factor" };
  // Sign-ins that passed the second factor with it end (a lost or stolen device keeps nothing),
  // except the one removing it.
  await scope.env.DB.prepare(`DELETE FROM sessions WHERE user_id = ? AND mfa_cred = ? AND id_hash != ?`).bind(uid, id, session.idHash).run();
  await notify(scope, session, "passkey_removed");
  return { ok: true };
}

// --- TOTP (RFC 6238) ---------------------------------------------------------------------------

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(text: string): Uint8Array<ArrayBuffer> {
  const clean = text.toUpperCase().replace(/[\s=-]/g, "");
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const c of clean) {
    const i = B32.indexOf(c);
    if (i < 0) throw new Error("base32");
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

/** The TOTP code of `secret` for time step `step` (HMAC-SHA-1, 6 digits). */
export async function totpCode(secret: Uint8Array<ArrayBuffer>, step: number, digits = TOTP_DIGITS): Promise<string> {
  const counter = new Uint8Array(8);
  new DataView(counter.buffer).setBigUint64(0, BigInt(step));
  const key = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const off = mac[mac.length - 1] & 15;
  const bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
  return String(bin % 10 ** digits).padStart(digits, "0");
}

/**
 * The MFA_KEY secret's 32 bytes, or null when it is missing or malformed. TOTP secrets are
 * encrypted under it, and recovery codes are keyed by a key derived from it (never by
 * SESSION_SECRET itself, which signs sessions).
 */
async function mfaKeyMaterial(scope: RequestScope): Promise<Uint8Array<ArrayBuffer> | null> {
  let raw: Uint8Array<ArrayBuffer> | null = null;
  const configured = scope.env.MFA_KEY;
  if (configured) {
    try {
      raw = base64urlDecode(configured.replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_"));
    } catch {
      raw = null;
    }
    if (raw && raw.length !== 32) raw = null;
  }
  return raw;
}

/** The AES-GCM key that keeps TOTP secrets at rest: the MFA_KEY secret. */
async function totpKey(scope: RequestScope): Promise<CryptoKey | null> {
  const raw = await mfaKeyMaterial(scope);
  return raw ? crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]) : null;
}

/** HKDF info that separates the recovery-code key from every other use of MFA_KEY. */
export const RECOVERY_KEY_INFO = "miblo-recovery-codes-v1";

/** The HMAC key recovery codes are stored under: HKDF-SHA-256 of MFA_KEY, its own label. */
async function recoveryKey(scope: RequestScope): Promise<CryptoKey | null> {
  const raw = await mfaKeyMaterial(scope);
  if (!raw) return null;
  const base = await crypto.subtle.importKey("raw", raw, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode(RECOVERY_KEY_INFO) },
    base,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign"],
  );
}

/** Whether TOTP can be offered (it needs the MFA_KEY secret). */
export async function totpAvailable(scope: RequestScope): Promise<boolean> {
  return (await totpKey(scope)) !== null;
}

async function sealSecret(scope: RequestScope, uid: string, secret: Uint8Array<ArrayBuffer>): Promise<string | null> {
  const key = await totpKey(scope);
  if (!key) return null;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(`miblo-totp|${uid}`) }, key, secret);
  return `${base64url(iv)}.${base64url(new Uint8Array(ct))}`;
}

async function openSecret(scope: RequestScope, uid: string, sealed: string): Promise<Uint8Array<ArrayBuffer> | null> {
  const key = await totpKey(scope);
  const [iv, ct] = sealed.split(".");
  if (!key || !iv || !ct) return null;
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: base64urlDecode(iv), additionalData: enc.encode(`miblo-totp|${uid}`) }, key, base64urlDecode(ct)));
  } catch {
    return null;
  }
}

/**
 * Starts (or restarts an unconfirmed) TOTP setup: a new secret, shown once, not a factor until
 * confirmed. A confirmed app is never replaced here (that could leave the account without a
 * factor): it is removed first, which checks that another factor remains.
 */
export async function totpSetup(scope: RequestScope, session: Session): Promise<{ secret: string; uri: string } | "exists" | null> {
  if ((await factorsOf(scope, session.user.id)).totp) return "exists";
  const raw = crypto.getRandomValues(new Uint8Array(20));
  const sealed = await sealSecret(scope, session.user.id, raw);
  if (!sealed) return null;
  await scope.env.DB.prepare(
    `INSERT INTO mfa_totp (user_id, secret_ct, confirmed_at, last_step, created_at) VALUES (?, ?, NULL, 0, ?)
     ON CONFLICT(user_id) DO UPDATE SET secret_ct = excluded.secret_ct, confirmed_at = NULL, last_step = 0, created_at = excluded.created_at`,
  )
    .bind(session.user.id, sealed, nowIso())
    .run();
  const secret = base32Encode(raw);
  const label = encodeURIComponent(`Miblo:${session.user.email}`);
  return { secret, uri: `otpauth://totp/${label}?secret=${secret}&issuer=Miblo&algorithm=SHA1&digits=${TOTP_DIGITS}&period=${TOTP_STEP_S}` };
}

/** The step a code matches (now ±1 step), or null. Constant time over the candidates. */
async function matchStep(secret: Uint8Array<ArrayBuffer>, code: string, now: number): Promise<number | null> {
  if (!/^\d{6}$/.test(code)) return null;
  const step = Math.floor(now / 1000 / TOTP_STEP_S);
  let found: number | null = null;
  for (const s of [step - 1, step, step + 1]) {
    const want = await totpCode(secret, s);
    let d = 0;
    for (let i = 0; i < want.length; i++) d |= want.charCodeAt(i) ^ code.charCodeAt(i);
    if (d === 0 && found === null) found = s;
  }
  return found;
}

/**
 * Checks a TOTP code: `confirm` for the first code after setup (it becomes a factor), else an
 * ordinary check of the confirmed factor. A step is never accepted twice.
 */
export async function totpCheck(scope: RequestScope, session: Session, code: string, { confirm = false, now = Date.now() } = {}): Promise<{ ok: true } | { ok: false; reason: string }> {
  const uid = session.user.id;
  // Counted before anything is checked (guessing codes for an account without the app counts too).
  if (!(await reserveAttempt(scope, uid, now))) return { ok: false, reason: "locked" };
  const row = await scope.env.DB.prepare(`SELECT secret_ct, confirmed_at, last_step FROM mfa_totp WHERE user_id = ?`)
    .bind(uid)
    .first<{ secret_ct: string; confirmed_at: string | null; last_step: number }>();
  if (!row || (confirm ? row.confirmed_at !== null : row.confirmed_at === null)) return { ok: false, reason: "no_totp" };
  const secret = await openSecret(scope, uid, row.secret_ct);
  if (!secret) return { ok: false, reason: "totp_unavailable" };
  const step = await matchStep(secret, String(code ?? "").replace(/\s/g, ""), now);
  if (step === null || step <= row.last_step) return { ok: false, reason: step === null ? "bad_code" : "replayed_code" };
  // Only one request can move last_step past this step: a code is spent once, even in a race.
  const moved = await scope.env.DB.prepare(
    `UPDATE mfa_totp SET last_step = ?, confirmed_at = COALESCE(confirmed_at, ?) WHERE user_id = ? AND last_step < ? RETURNING 1 AS ok`,
  )
    .bind(step, nowIso(), uid, step)
    .first<{ ok: number }>();
  if (!moved) return { ok: false, reason: "replayed_code" };
  await clearFailures(scope, uid);
  if (confirm) await notify(scope, session, "totp_added");
  await markSessionMfa(scope, session.idHash, "totp");
  return { ok: true };
}

export async function totpRemove(scope: RequestScope, session: Session): Promise<{ ok: true } | { ok: false; reason: string }> {
  const f = await factorsOf(scope, session.user.id);
  if (!f.totp) return { ok: false, reason: "not_found" };
  if (await lastRequiredFactor(scope, session.user.id)) return { ok: false, reason: "last_factor" };
  // As for a passkey: the check is part of the delete (parallel removals keep one factor).
  const gone = await scope.env.DB.prepare(`DELETE FROM mfa_totp WHERE user_id = ?1 AND ${KEEPS_FACTOR_WITHOUT_TOTP}`).bind(session.user.id).run();
  if (!gone.meta.changes) return { ok: false, reason: "last_factor" };
  await notify(scope, session, "totp_removed");
  return { ok: true };
}

// --- recovery codes ----------------------------------------------------------------------------

const normalizeCode = (code: string) => String(code ?? "").toUpperCase().replace(/[^A-Z2-7]/g, "");

/** The stored form of a recovery code (exported for tests); null without MFA_KEY (fail closed). */
export async function recoveryHash(scope: RequestScope, uid: string, code: string): Promise<string | null> {
  const key = await recoveryKey(scope);
  if (!key) return null;
  return base64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(`${uid}|${normalizeCode(code)}`))));
}

/** Ten new codes (the old ones stop working), shown once: XXXXX-XXXXX, 50 bits each. */
export async function generateRecoveryCodes(scope: RequestScope, session: Session): Promise<string[] | null> {
  const uid = session.user.id;
  // No MFA_KEY: no codes at all, rather than codes keyed by something weaker.
  if (!(await recoveryKey(scope))) return null;
  const codes = Array.from({ length: RECOVERY_CODES }, () => {
    const s = base32Encode(crypto.getRandomValues(new Uint8Array(7))).slice(0, 10);
    return `${s.slice(0, 5)}-${s.slice(5)}`;
  });
  const { DB } = scope.env;
  const now = nowIso();
  await DB.batch([
    DB.prepare(`DELETE FROM mfa_recovery_codes WHERE user_id = ?`).bind(uid),
    ...(await Promise.all(codes.map(async (c) => DB.prepare(`INSERT INTO mfa_recovery_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)`).bind(uid, (await recoveryHash(scope, uid, c))!, now)))),
  ]);
  await notify(scope, session, "recovery_generated");
  return codes;
}

/** Spends one recovery code: the session passes the second factor (account access only). */
export async function spendRecoveryCode(scope: RequestScope, session: Session, code: string): Promise<{ ok: true; left: number } | { ok: false; reason: string }> {
  const uid = session.user.id;
  if (!(await recoveryKey(scope))) return { ok: false, reason: "mfa_unavailable" };
  if (!(await reserveAttempt(scope, uid))) return { ok: false, reason: "locked" };
  if (normalizeCode(code).length !== 10) return { ok: false, reason: "bad_code" };
  const hash = await recoveryHash(scope, uid, code);
  if (!hash) return { ok: false, reason: "mfa_unavailable" };
  const row = await scope.env.DB.prepare(
    `UPDATE mfa_recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL RETURNING 1 AS ok`,
  )
    .bind(nowIso(), uid, hash)
    .first<{ ok: number }>();
  if (!row) return { ok: false, reason: "bad_code" };
  await clearFailures(scope, uid);
  await markSessionMfa(scope, session.idHash, "recovery");
  await notify(scope, session, "recovery_used");
  return { ok: true, left: (await factorsOf(scope, uid)).recoveryLeft };
}

// --- notices -----------------------------------------------------------------------------------

export type SecurityEvent = "passkey_added" | "passkey_removed" | "totp_added" | "totp_removed" | "recovery_generated" | "recovery_used" | "computer_linked" | "phone_added" | "phone_revoked" | "pin_lockout";

/**
 * A security event. A self-hosted server sends no email: it logs the event's name (never a secret,
 * code or key) so the operator can see it in the server's logs.
 */
export async function notify(_scope: RequestScope, _session: Session, event: SecurityEvent, _detail = ""): Promise<void> {
  console.log(JSON.stringify({ event: "account_security", what: event, at: nowIso() }));
}
