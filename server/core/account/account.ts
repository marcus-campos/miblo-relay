// The server's single account: created once with the setup token, then signed in with its
// password and a mandatory second factor (or a passkey alone, which is both).
//
// - Setup: POST /api/setup with SETUP_TOKEN (the operator's), a name and a password. A token works
//   for one setup only (a token seen in a log cannot redo it later); an abandoned setup (no second
//   factor yet) is redone with a new token from the operator's shell (README). Once a passkey or an
//   authenticator app exists, setup is closed whatever the token.
// - Password sign-in is refused while the account has no second factor (only the setup session,
//   which made the password, can add the first one), so the password alone never reaches the
//   phone registry or the linked computers.
// - Wrong passwords lock the account for the network they came from (an IPv6 /64), not for
//   everyone: a stranger who knows the name cannot keep the owner out from the owner's own network.
//   The answer while locked is the same 401 as for a wrong name or password (no enumeration), after
//   the same work. Guessing stays slow (5 tries per 15 minutes per network, 10 a minute per network
//   at the route) and is only the first factor: the second one, mandatory, has an account-wide lock.
// - The last resort for an owner without any factor left is the operator's shell (README,
//   `reset-account`).
import { newId, nowIso, safeEqual, sha256Hex } from "../crypto";
import type { RequestScope } from "../env";
import { hasSecondFactor, reserveAttempt, clearFailures } from "./mfa";
import { dummyHash, hashIterations, hashPassword, passwordIterations, passwordProblem, verifyPassword } from "./password";

type Row = { id: string; username: string; password_hash: string; lang: string };

export async function theAccount(scope: RequestScope): Promise<Row | null> {
  return scope.env.DB.prepare(`SELECT id, username, password_hash, lang FROM users ORDER BY created_at LIMIT 1`).first<Row>();
}

/** Whether the setup step is still open (no account, or one without any second factor yet). */
export async function setupNeeded(scope: RequestScope): Promise<boolean> {
  const a = await theAccount(scope);
  return !a || !(await hasSecondFactor(scope, a.id));
}

export type SetupResult = { ok: true; uid: string } | { ok: false; error: "setup_closed" | "bad_token" | "setup_token_used" | "setup_unavailable" | string };

/** Whether this setup token was already used for a setup (it then needs a new one). */
export async function setupTokenUsed(scope: RequestScope, token: string): Promise<boolean> {
  return !!(await scope.env.DB.prepare(`SELECT 1 FROM setup_tokens_used WHERE token_hash = ?`).bind(await sha256Hex(token)).first());
}

export async function runSetup(scope: RequestScope, input: { token: string; username: string; password: string; lang: "pt" | "en" }): Promise<SetupResult> {
  const expected = scope.env.SETUP_TOKEN;
  if (!expected || expected.length < 16) return { ok: false, error: "setup_unavailable" };
  if (!(await setupNeeded(scope))) return { ok: false, error: "setup_closed" };
  if (!(await safeEqual(input.token.trim(), expected))) return { ok: false, error: "bad_token" };
  const problem = passwordProblem(input.password);
  if (problem) return { ok: false, error: problem };
  const hash = await hashPassword(input.password, passwordIterations(scope.env));
  const now = nowIso();
  // Spent now, atomically: two setups with one token, or a later one, find it used.
  const spent = await scope.env.DB.prepare(`INSERT INTO setup_tokens_used (token_hash, used_at) VALUES (?, ?) ON CONFLICT DO NOTHING`).bind(await sha256Hex(expected), now).run();
  if (!spent.meta.changes) return { ok: false, error: "setup_token_used" };
  const existing = await theAccount(scope);
  if (existing) {
    await scope.env.DB.batch([
      scope.env.DB.prepare(`UPDATE users SET username = ?, password_hash = ?, lang = ?, updated_at = ? WHERE id = ?`).bind(input.username, hash, input.lang, now, existing.id),
      // Whoever started the abandoned setup is signed out.
      scope.env.DB.prepare(`DELETE FROM sessions WHERE user_id = ?`).bind(existing.id),
      scope.env.DB.prepare(`DELETE FROM mfa_totp WHERE user_id = ? AND confirmed_at IS NULL`).bind(existing.id),
    ]);
    return { ok: true, uid: existing.id };
  }
  const id = newId("usr");
  // One account per server: the insert only happens while the table is empty.
  const r = await scope.env.DB.prepare(`INSERT INTO users (id, username, password_hash, lang, created_at, updated_at) SELECT ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM users)`)
    .bind(id, input.username, hash, input.lang, now, now)
    .run();
  if (!r.meta.changes) return { ok: false, error: "setup_closed" };
  return { ok: true, uid: id };
}

export type SignInResult = { ok: true; uid: string } | { ok: false; error: "bad_credentials" | "finish_setup" };

/**
 * Checks the password (first factor) from `network` (clientNetwork of the caller). One answer, after
 * the same work, for an unknown name, a wrong password and a locked network.
 */
export async function passwordSignIn(scope: RequestScope, username: string, password: string, network: string): Promise<SignInResult> {
  const a = await theAccount(scope);
  const lock = a ? `pw:${a.id}:${network}` : "";
  if (!a || a.username !== username || !(await reserveAttempt(scope, lock))) {
    // The same work as a real check, so the answer's timing says nothing about the name or a lock.
    await verifyPassword(password, a?.password_hash ?? dummyHash(passwordIterations(scope.env)));
    return { ok: false, error: "bad_credentials" };
  }
  if (!(await verifyPassword(password, a.password_hash))) return { ok: false, error: "bad_credentials" };
  await clearFailures(scope, lock);
  // A hash made with less work than this runtime uses now is redone while the password is at hand.
  const iterations = passwordIterations(scope.env);
  if (hashIterations(a.password_hash) < iterations) {
    await scope.env.DB.prepare(`UPDATE users SET password_hash = ? WHERE id = ?`).bind(await hashPassword(password, iterations), a.id).run();
  }
  if (!(await hasSecondFactor(scope, a.id))) return { ok: false, error: "finish_setup" };
  return { ok: true, uid: a.id };
}

/** A new password (the session passed its second factor in the last 5 minutes; the route checks it). */
export async function changePassword(scope: RequestScope, uid: string, password: string): Promise<string | null> {
  const problem = passwordProblem(password);
  if (problem) return problem;
  await scope.env.DB.prepare(`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`).bind(await hashPassword(password, passwordIterations(scope.env)), nowIso(), uid).run();
  return null;
}
