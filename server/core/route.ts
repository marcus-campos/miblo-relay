// Route helpers: same-origin JSON (readJson), a signed-in session with its CSRF token and the
// second factor it needs, linked computers (Bearer mpt_…) and anonymous device-flow calls.
// Adapted from the miblo.ai account routes.
import type { z } from "zod";
import type { RequestScope } from "./env";
import { clientIp, clientNetwork, error, limited, readJson, tooMany } from "./http";
import { csrfValid, sessionFromCookie, type Session } from "./account/sessions";
import { MFA_FRESH_MS, MFA_SESSION_MS } from "./account/mfa-policy";
import { sessionSecret } from "./crypto";
import { deviceFromRequest, type LinkedDevice } from "./devices";

/**
 * What a route needs of the session's second factor:
 * - "none": any signed-in session (a pending one only with `allowPending`);
 * - "session": the account has a second factor and this session passed it within MFA_SESSION_MS;
 * - "fresh": passed it within MFA_FRESH_MS (adding a phone, linking a computer, changing factors).
 */
export type MfaNeed = "none" | "session" | "fresh";
export type MemberRequest<T> = { ok: true; session: Session; data: T } | { ok: false; response: Response };

/** Why `session` does not meet `need`, or null when it does. */
export function mfaBlock(session: Session, need: MfaNeed, now = Date.now()): Response | null {
  if (need === "none") return null;
  if (!session.mfa.enrolled) return error("mfa_setup_required", 403);
  const age = session.mfa.at === null ? Infinity : now - session.mfa.at;
  if (need === "fresh" && age > MFA_FRESH_MS) return error("mfa_fresh_required", 403);
  if (age > MFA_SESSION_MS) return error("mfa_required", 403);
  return null;
}

export async function memberRequest<S extends z.ZodType>(
  scope: RequestScope,
  request: Request,
  schema: S,
  opts: { mfa?: MfaNeed; allowPending?: boolean } = {},
): Promise<MemberRequest<z.infer<S>>> {
  if (!sessionSecret(scope)) return { ok: false, response: error("unavailable", 503) };
  const session = await sessionFromCookie(scope, request.headers.get("cookie"), { allowPending: true });
  if (!session) return { ok: false, response: error("unauthorized", 401) };
  // An account with a second factor whose session has not passed it: nothing but that step.
  if (session.pending && !opts.allowPending) return { ok: false, response: error("mfa_required", 401) };
  const parsed = await readJson(request, schema);
  if (!parsed.ok) return parsed;
  if (!(await csrfValid(session, request.headers.get("x-csrf-token")))) return { ok: false, response: error("csrf", 403) };
  const blocked = mfaBlock(session, opts.mfa ?? "none");
  if (blocked) return { ok: false, response: blocked };
  return { ok: true, session, data: parsed.data };
}

/** Account actions (sessions, phones) per minute and account. */
export function accountActionLimited(userId: string, action: string): boolean {
  return limited(`${action}:${userId}`, 30);
}

/** The second-factor routes: per-IP and per-account limits, and what the session needs for this step. */
export type MfaStep = "verify" | "setup" | "session" | "fresh";
export async function mfaRequest<S extends z.ZodType>(scope: RequestScope, request: Request, schema: S, step: MfaStep): Promise<MemberRequest<z.infer<S>>> {
  if (limited(`mfa:${clientIp(request)}`, 30)) return { ok: false, response: tooMany() };
  const r = await memberRequest(scope, request, schema, { allowPending: step === "verify" });
  if (!r.ok) return r;
  if (limited(`mfa-user:${r.session.user.id}`, 20)) return { ok: false, response: tooMany() };
  const need: MfaNeed = step === "verify" ? "none" : step === "setup" ? (r.session.mfa.enrolled ? "fresh" : "none") : step;
  const blocked = mfaBlock(r.session, need);
  if (blocked) return { ok: false, response: blocked };
  return r;
}

/** GET routes: the signed-in session (pending ones too, when asked), refused when cross-site. */
export async function sessionForGet(scope: RequestScope, request: Request, allowPending = false): Promise<{ session: Session | null } | { response: Response }> {
  if (!sessionSecret(scope)) return { response: error("unavailable", 503) };
  const site = request.headers.get("sec-fetch-site");
  if (site && site !== "same-origin" && site !== "none") return { response: error("forbidden", 403) };
  return { session: await sessionFromCookie(scope, request.headers.get("cookie"), { allowPending }) };
}

export type DeviceRequest<T> = { ok: true; device: LinkedDevice; data: T } | { ok: false; response: Response };

/** A linked computer's call: "Authorization: Bearer mpt_…" (no cookies, so no CSRF), JSON bodies. */
export async function deviceRequest<S extends z.ZodType>(scope: RequestScope, request: Request, schema: S | null): Promise<DeviceRequest<z.infer<S>>> {
  if (!sessionSecret(scope)) return { ok: false, response: error("unavailable", 503) };
  const device = await deviceFromRequest(scope, request);
  if (!device) return { ok: false, response: error("invalid_token", 401) };
  if (limited(`device:${device.id}`, 30)) return { ok: false, response: tooMany() };
  if (!schema) return { ok: true, device, data: undefined as z.infer<S> };
  const parsed = await readJson(request, schema);
  if (!parsed.ok) return parsed;
  return { ok: true, device, data: parsed.data };
}

/** The device flow's start and poll: anonymous, limited per network (polls every 5 s, starts are rare). */
export async function anonymousRequest<S extends z.ZodType>(scope: RequestScope, request: Request, schema: S, bucket: "start" | "poll"): Promise<{ ok: true; data: z.infer<S> } | { ok: false; response: Response }> {
  if (!sessionSecret(scope)) return { ok: false, response: error("unavailable", 503) };
  if (limited(`${bucket}:${clientNetwork(clientIp(request))}`, bucket === "start" ? 6 : 30)) return { ok: false, response: tooMany() };
  const parsed = await readJson(request, schema);
  if (!parsed.ok) return parsed;
  return { ok: true, data: parsed.data };
}
