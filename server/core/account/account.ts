// The server's single account: created once with the setup token, then signed in with its
// password and a mandatory second factor (or a passkey alone, which is both).
//
// - Setup: POST /api/setup with SETUP_TOKEN (the operator's), a name and a password. It works while
//   the account has no second factor yet (an abandoned setup can be redone with the same token);
//   once a passkey or an authenticator app exists, the setup token is dead.
// - Password sign-in is refused while the account has no second factor (only the setup session,
//   which made the password, can add the first one), so the password alone never reaches the
//   phone registry or the linked computers.
// - Password attempts count per account (the second factor's lock, its own counter) and per IP.
import { newId, nowIso, safeEqual } from "../crypto";
import type { RequestScope } from "../env";
import { hasSecondFactor, reserveAttempt, clearFailures } from "./mfa";
import { hashPassword, passwordProblem, verifyPassword } from "./password";

type Row = { id: string; username: string; password_hash: string; lang: string };

export async function theAccount(scope: RequestScope): Promise<Row | null> {
  return scope.env.DB.prepare(`SELECT id, username, password_hash, lang FROM users ORDER BY created_at LIMIT 1`).first<Row>();
}

/** Whether the setup step is still open (no account, or one without any second factor yet). */
export async function setupNeeded(scope: RequestScope): Promise<boolean> {
  const a = await theAccount(scope);
  return !a || !(await hasSecondFactor(scope, a.id));
}

export type SetupResult = { ok: true; uid: string } | { ok: false; error: "setup_closed" | "bad_token" | "setup_unavailable" | string };

export async function runSetup(scope: RequestScope, input: { token: string; username: string; password: string; lang: "pt" | "en" }): Promise<SetupResult> {
  const expected = scope.env.SETUP_TOKEN;
  if (!expected || expected.length < 16) return { ok: false, error: "setup_unavailable" };
  if (!(await setupNeeded(scope))) return { ok: false, error: "setup_closed" };
  if (!(await safeEqual(input.token.trim(), expected))) return { ok: false, error: "bad_token" };
  const problem = passwordProblem(input.password);
  if (problem) return { ok: false, error: problem };
  const hash = await hashPassword(input.password);
  const now = nowIso();
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

export type SignInResult = { ok: true; uid: string } | { ok: false; error: "bad_credentials" | "locked" | "finish_setup" };

/** Checks the password (first factor). The same answer for an unknown name and a wrong password. */
export async function passwordSignIn(scope: RequestScope, username: string, password: string): Promise<SignInResult> {
  const a = await theAccount(scope);
  if (!a || a.username !== username) {
    // The same work as a real check, so the answer's timing says nothing about the name.
    await verifyPassword(password, "pbkdf2-sha256$100000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    return { ok: false, error: "bad_credentials" };
  }
  if (!(await reserveAttempt(scope, `pw:${a.id}`))) return { ok: false, error: "locked" };
  if (!(await verifyPassword(password, a.password_hash))) return { ok: false, error: "bad_credentials" };
  await clearFailures(scope, `pw:${a.id}`);
  if (!(await hasSecondFactor(scope, a.id))) return { ok: false, error: "finish_setup" };
  return { ok: true, uid: a.id };
}

/** A new password (the session passed its second factor in the last 5 minutes; the route checks it). */
export async function changePassword(scope: RequestScope, uid: string, password: string): Promise<string | null> {
  const problem = passwordProblem(password);
  if (problem) return problem;
  await scope.env.DB.prepare(`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`).bind(await hashPassword(password), nowIso(), uid).run();
  return null;
}
