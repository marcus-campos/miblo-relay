// The server's HTTP API, one fetch handler for both runtimes. Same paths and shapes as miblo.ai's,
// so the plugin (pointed here with `miblo server set`) and the phone app work unchanged:
//
//   identity      GET /.well-known/miblo-relay.json, POST /api/server/identity (identity.ts)
//   relay         /api/relay/* (relay/router.ts, relay/room.ts)
//   account       /api/setup, /api/community/auth/*, /api/community/mfa/*, /api/community/account/*
//   computers     /api/plus/device/*, /api/plus/me, /api/plus/rooms*, /api/plus/devices*
//   phones        /api/phones*, /api/plus/phones*
//
// Everything else is the phone app and the account page (static files, served by the runtime).
import type { z } from "zod";
import type { RequestScope } from "./env";
import { error, json, readJson, crossSiteError, clientIp, clientNetwork, limited, tooMany } from "./http";
import { handleRelay } from "./relay/router";
import { publicOrigin } from "./config";
import { identityDocument, signIdentity } from "./identity";
import * as S from "./schemas";
import { accountActionLimited, anonymousRequest, deviceRequest, memberRequest, mfaBlock, mfaRequest, sessionForGet } from "./route";
import { clearSessionCookie, createSession, listSessions, revokeListedSession, revokeSession, revokeUserSessions, sessionCookie, sessionFromCookie } from "./account/sessions";
import { changePassword, passwordSignIn, runSetup, setupNeeded, setupTokenUsed } from "./account/account";
import {
  assertionOptions,
  factorsOf,
  factorRequired,
  generateRecoveryCodes,
  markSessionMfa,
  notify,
  registerPasskey,
  registrationOptions,
  removePasskey,
  signInOptions,
  signInWithPasskey,
  spendRecoveryCode,
  totpAvailable,
  totpCheck,
  totpRemove,
  totpSetup,
  verifyPasskey,
} from "./account/mfa";
import { MFA_FRESH_MS, MFA_SESSION_MS } from "./account/mfa-policy";
import { relyingParty } from "./account/webauthn";
import {
  confirmDeviceCode,
  deviceSummary,
  findPendingCode,
  linkFormToken,
  linkFormTokenValid,
  linkLookupLimited,
  listDevices,
  networkHash,
  pollDeviceCode,
  registerRoom,
  removeRoom,
  revokeDevice,
  roomChallenge,
  startDeviceAuthorization,
  DEVICES_MAX,
} from "./devices";
import { answerSas, askAgain, deleteGrant, listPhones, nudgeComputersLater, phoneModel, phonesForDevice, putGrant, putRequest, registerPhone, revokePhone, waitForGrants } from "./phones";

type Handler = (scope: RequestScope, request: Request, params: string[]) => Promise<Response>;
type Route = { method: string; path: RegExp; handler: Handler };

const ID = "([A-Za-z0-9_-]{22})";

function route(method: string, path: string, handler: Handler): Route {
  return { method, path: new RegExp(`^${path}$`), handler };
}

/** An unauthenticated JSON POST (setup, sign-in, identity): same-origin JSON checks and a body schema. */
async function body<Sc extends z.ZodType>(request: Request, schema: Sc) {
  return readJson(request, schema);
}

const ROUTES: Route[] = [
  // --- the server's identity (trust on first use by the plugin) ---
  route("GET", "/\\.well-known/miblo-relay\\.json", async (scope) => {
    const o = publicOrigin(scope.env)!;
    return json(await identityDocument(scope.env.SERVER_IDENTITY_KEY, o.origin), 200, { "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*" });
  }),
  route("POST", "/api/server/identity", async (scope, request) => {
    if (limited(`identity:${clientNetwork(clientIp(request))}`, 60)) return tooMany();
    // A plain JSON call from the plugin (Node): no cookies, no CSRF; nothing here is secret.
    let data: unknown;
    try {
      data = JSON.parse((await request.text()).slice(0, 512));
    } catch {
      return error("invalid_json", 400);
    }
    const parsed = S.identityChallengeSchema.safeParse(data);
    if (!parsed.success) return error("invalid_request", 400);
    const o = publicOrigin(scope.env)!;
    return json({ sig: await signIdentity(scope.env.SERVER_IDENTITY_KEY, o.origin, parsed.data.nonce) });
  }),

  // --- setup and signing in ---
  route("GET", "/api/setup", async (scope) => json({ needed: await setupNeeded(scope), available: !!scope.env.SETUP_TOKEN, used: !!scope.env.SETUP_TOKEN && (await setupTokenUsed(scope, scope.env.SETUP_TOKEN)) })),
  route("POST", "/api/setup", async (scope, request) => {
    if (limited(`setup:${clientNetwork(clientIp(request))}`, 5)) return tooMany();
    const p = await body(request, S.setupSchema);
    if (!p.ok) return p.response;
    const out = await runSetup(scope, p.data);
    if (!out.ok) return error(out.error, out.error === "bad_token" ? 403 : out.error === "setup_closed" || out.error === "setup_token_used" ? 409 : out.error === "setup_unavailable" ? 503 : 400);
    const cookie = await createSession(scope, out.uid, request.headers.get("user-agent") ?? "");
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(cookie, publicOrigin(scope.env)!.origin) });
  }),
  route("POST", "/api/community/auth/password", async (scope, request) => {
    if (limited(`signin:${clientNetwork(clientIp(request))}`, 10)) return tooMany();
    const p = await body(request, S.passwordSignInSchema);
    if (!p.ok) return p.response;
    const out = await passwordSignIn(scope, p.data.username, p.data.password, clientNetwork(clientIp(request)));
    if (!out.ok) return error(out.error, out.error === "finish_setup" ? 409 : 401);
    const cookie = await createSession(scope, out.uid, request.headers.get("user-agent") ?? "");
    return json({ ok: true, next: "mfa" }, 200, { "Set-Cookie": sessionCookie(cookie, publicOrigin(scope.env)!.origin) });
  }),
  route("POST", "/api/community/auth/passkey/options", async (scope, request) => {
    if (limited(`signin:${clientNetwork(clientIp(request))}`, 10)) return tooMany();
    const blocked = crossSiteError(request);
    if (blocked) return blocked;
    const rp = relyingParty(scope);
    if (!rp) return error("mfa_unavailable", 503);
    return json(await signInOptions(scope, rp));
  }),
  route("POST", "/api/community/auth/passkey/verify", async (scope, request) => {
    if (limited(`signin:${clientNetwork(clientIp(request))}`, 10)) return tooMany();
    const p = await body(request, S.passkeySignInSchema);
    if (!p.ok) return p.response;
    const rp = relyingParty(scope);
    if (!rp) return error("mfa_unavailable", 503);
    const out = await signInWithPasskey(scope, rp, p.data.wa);
    if (!out.ok) return error(out.reason, 401);
    const cookie = await createSession(scope, out.uid, request.headers.get("user-agent") ?? "", { method: "passkey", cred: out.cred });
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(cookie, publicOrigin(scope.env)!.origin) });
  }),
  route("POST", "/api/community/auth/logout", async (scope, request) => {
    const blocked = crossSiteError(request);
    if (blocked) return blocked;
    const session = await sessionFromCookie(scope, request.headers.get("cookie"), { allowPending: true });
    if (session) await revokeSession(scope, session.idHash);
    return json({ ok: true }, 200, { "Set-Cookie": clearSessionCookie(publicOrigin(scope.env)!.origin) });
  }),
  route("POST", "/api/community/account/password", async (scope, request) => {
    const r = await memberRequest(scope, request, S.changePasswordSchema, { mfa: "fresh" });
    if (!r.ok) return r.response;
    const problem = await changePassword(scope, r.session.user.id, r.data.password);
    if (problem) return error(problem, 400);
    await revokeUserSessions(scope, r.session.user.id, r.session.idHash);
    return json({ ok: true });
  }),

  // --- the second factor (same API as miblo.ai's) ---
  route("GET", "/api/community/mfa", async (scope, request) => {
    const r = await sessionForGet(scope, request, true);
    if ("response" in r) return r.response;
    const { session } = r;
    if (!session) return json({ signedIn: false });
    const age = session.mfa.at === null ? Infinity : Date.now() - session.mfa.at;
    return json({
      signedIn: true,
      pending: session.pending,
      email: session.user.email,
      csrf: session.csrf,
      factors: await factorsOf(scope, session.user.id),
      totpAvailable: await totpAvailable(scope),
      required: await factorRequired(scope, session.user.id),
      mfa: { enrolled: session.mfa.enrolled, method: session.mfa.method, valid: age <= MFA_SESSION_MS, fresh: age <= MFA_FRESH_MS },
      vault: null,
    });
  }),
  route("POST", "/api/community/mfa/passkey/options", async (scope, request) => {
    let purpose: "register" | "verify" = "verify";
    try {
      purpose = S.passkeyOptionsSchema.parse(await request.clone().json()).purpose;
    } catch {
      return error("invalid_request", 400);
    }
    const r = await mfaRequest(scope, request, S.passkeyOptionsSchema, purpose === "register" ? "setup" : "verify");
    if (!r.ok) return r.response;
    const rp = relyingParty(scope);
    if (!rp) return error("mfa_unavailable", 503);
    if (purpose === "register") return json(await registrationOptions(scope, r.session, rp));
    const opts = await assertionOptions(scope, r.session, rp);
    if (!opts.allowCredentials.length) return error("no_passkey", 404);
    return json(opts);
  }),
  route("POST", "/api/community/mfa/passkey/register", async (scope, request) => {
    const r = await mfaRequest(scope, request, S.passkeyRegisterSchema, "setup");
    if (!r.ok) return r.response;
    const rp = relyingParty(scope);
    if (!rp) return error("mfa_unavailable", 503);
    const out = await registerPasskey(scope, r.session, rp, r.data);
    if (!out.ok) return error(out.reason, 400);
    await markSessionMfa(scope, r.session.idHash, "passkey", out.id);
    return json({ ok: true, id: out.id });
  }),
  route("POST", "/api/community/mfa/passkey/verify", async (scope, request) => {
    const r = await mfaRequest(scope, request, S.passkeyVerifySchema, "verify");
    if (!r.ok) return r.response;
    const rp = relyingParty(scope);
    if (!rp) return error("mfa_unavailable", 503);
    const out = await verifyPasskey(scope, r.session, rp, r.data.wa);
    if (!out.ok) return error(out.reason, out.reason === "locked" ? 429 : 401);
    return json({ ok: true });
  }),
  route("POST", "/api/community/mfa/passkey/remove", async (scope, request) => {
    const r = await mfaRequest(scope, request, S.passkeyRemoveSchema, "fresh");
    if (!r.ok) return r.response;
    const out = await removePasskey(scope, r.session, r.data.id);
    if (!out.ok) return error(out.reason, out.reason === "not_found" ? 404 : 409);
    return json({ ok: true });
  }),
  route("POST", "/api/community/mfa/totp/setup", async (scope, request) => {
    const r = await mfaRequest(scope, request, S.emptySchema, "setup");
    if (!r.ok) return r.response;
    const out = await totpSetup(scope, r.session);
    if (out === "exists") return error("totp_exists", 409);
    if (!out) return error("totp_unavailable", 503);
    return json(out);
  }),
  route("POST", "/api/community/mfa/totp/confirm", async (scope, request) => {
    const r = await mfaRequest(scope, request, S.codeSchema, "setup");
    if (!r.ok) return r.response;
    const out = await totpCheck(scope, r.session, r.data.code, { confirm: true });
    if (!out.ok) return error(out.reason, out.reason === "locked" ? 429 : 400);
    return json({ ok: true });
  }),
  route("POST", "/api/community/mfa/totp/verify", async (scope, request) => {
    const r = await mfaRequest(scope, request, S.codeSchema, "verify");
    if (!r.ok) return r.response;
    const out = await totpCheck(scope, r.session, r.data.code);
    if (!out.ok) return error(out.reason, out.reason === "locked" ? 429 : 401);
    return json({ ok: true });
  }),
  route("POST", "/api/community/mfa/totp/remove", async (scope, request) => {
    const r = await mfaRequest(scope, request, S.emptySchema, "fresh");
    if (!r.ok) return r.response;
    const out = await totpRemove(scope, r.session);
    if (!out.ok) return error(out.reason, out.reason === "not_found" ? 404 : 409);
    return json({ ok: true });
  }),
  route("POST", "/api/community/mfa/recovery/generate", async (scope, request) => {
    const r = await mfaRequest(scope, request, S.emptySchema, "fresh");
    if (!r.ok) return r.response;
    const codes = await generateRecoveryCodes(scope, r.session);
    if (!codes) return error("mfa_unavailable", 503);
    return json({ codes });
  }),
  route("POST", "/api/community/mfa/recovery/verify", async (scope, request) => {
    const r = await mfaRequest(scope, request, S.codeSchema, "verify");
    if (!r.ok) return r.response;
    const out = await spendRecoveryCode(scope, r.session, r.data.code);
    if (!out.ok) return error(out.reason, out.reason === "locked" ? 429 : out.reason === "mfa_unavailable" ? 503 : 401);
    return json({ ok: true, left: out.left });
  }),
  route("GET", "/api/community/account/sessions", async (scope, request) => {
    const r = await sessionForGet(scope, request);
    if ("response" in r) return r.response;
    if (!r.session) return error("unauthorized", 401);
    if (accountActionLimited(r.session.user.id, "sessions")) return tooMany();
    return json({ sessions: await listSessions(scope, r.session) });
  }),
  route("POST", "/api/community/account/sessions", async (scope, request) => {
    const r = await memberRequest(scope, request, S.emptySchema);
    if (!r.ok) return r.response;
    if (accountActionLimited(r.session.user.id, "sessions")) return tooMany();
    await revokeUserSessions(scope, r.session.user.id, r.session.idHash);
    return json({ ok: true });
  }),
  route("POST", "/api/community/account/sessions/revoke", async (scope, request) => {
    const r = await memberRequest(scope, request, S.sessionRevokeSchema);
    if (!r.ok) return r.response;
    if (accountActionLimited(r.session.user.id, "sessions")) return tooMany();
    if (!(await revokeListedSession(scope, r.session, r.data.id))) return error("not_found", 404);
    return json({ ok: true });
  }),

  // --- linked computers: the device flow (the plugin's `miblo account link`) ---
  route("POST", "/api/plus/device/start", async (scope, request) => {
    const r = await anonymousRequest(scope, request, S.deviceStartSchema, "start");
    if (!r.ok) return r.response;
    const ip = clientIp(request);
    const net = ip === "unknown" ? null : await networkHash(scope, ip);
    const out = await startDeviceAuthorization(scope, r.data, Date.now(), { net, country: null });
    if (out === "busy") return error("busy", 503);
    if (out === "network_limit") return error("rate_limited", 429);
    return json(out);
  }),
  route("POST", "/api/plus/device/token", async (scope, request) => {
    const r = await anonymousRequest(scope, request, S.deviceTokenSchema, "poll");
    if (!r.ok) return r.response;
    const out = await pollDeviceCode(scope, r.data.device_code);
    if (!out.ok) return error(out.error, out.error === "device_limit" ? 409 : 400);
    return json({
      token: out.token,
      token_type: "Bearer",
      device: out.device,
      account: { plan: "plus", status: "active", current_period_end: null, valid_until: null, devices: { used: out.devicesUsed, max: DEVICES_MAX } },
    });
  }),
  // The link page's form token (its own form only: a code never reaches the confirmation from a link).
  route("GET", "/api/plus/device/form", async (scope, request) => {
    const r = await sessionForGet(scope, request);
    if ("response" in r) return r.response;
    if (!r.session) return error("unauthorized", 401);
    return json({ form: await linkFormToken(scope, r.session.idHash) });
  }),
  route("POST", "/api/plus/device/lookup", async (scope, request) => {
    const r = await memberRequest(scope, request, S.deviceLookupSchema, { mfa: "session" });
    if (!r.ok) return r.response;
    if (!(await linkFormTokenValid(scope, r.session.idHash, r.data.form))) return error("form", 403);
    if (linkLookupLimited(r.session.user.id)) return tooMany();
    const pending = await findPendingCode(scope, r.data.userCode, r.session.user.id);
    if (!pending) return error("invalid_code", 404);
    return json({ code: pending });
  }),
  route("POST", "/api/plus/device/confirm", async (scope, request) => {
    const r = await memberRequest(scope, request, S.deviceConfirmSchema, { mfa: "session" });
    if (!r.ok) return r.response;
    if (!(await linkFormTokenValid(scope, r.session.idHash, r.data.form))) return error("form", 403);
    if (r.data.approve) {
      // Linking a computer needs a fresh second factor.
      const blocked = mfaBlock(r.session, "fresh");
      if (blocked) return blocked;
    }
    if (limited(`confirm:${r.session.user.id}`, 6)) return tooMany();
    const out = await confirmDeviceCode(scope, r.session.user.id, r.data.userCode, r.data.approve);
    if (out === "invalid_code") return error("invalid_code", 404);
    if (out === "device_limit") return error("device_limit", 409, { devicesMax: DEVICES_MAX });
    if (r.data.approve && out === "approved") await notify(scope, r.session, "computer_linked");
    return json({ ok: true, result: out });
  }),
  route("POST", "/api/plus/device/unlink", async (scope, request) => {
    const r = await deviceRequest(scope, request, S.emptySchema);
    if (!r.ok) return r.response;
    await revokeDevice(scope, r.device.user_id, r.device.id);
    return json({ ok: true });
  }),
  route("GET", "/api/plus/me", async (scope, request) => {
    const r = await deviceRequest(scope, request, null);
    if (!r.ok) return r.response;
    return json(await deviceSummary(scope, r.device));
  }),
  route("POST", "/api/plus/rooms/challenge", async (scope, request) => {
    const r = await deviceRequest(scope, request, S.roomSchema);
    if (!r.ok) return r.response;
    return json(await roomChallenge(scope, r.device.id, r.data.room));
  }),
  route("POST", "/api/plus/rooms", async (scope, request) => {
    const r = await deviceRequest(scope, request, S.roomRegisterSchema);
    if (!r.ok) return r.response;
    const out = await registerRoom(scope, r.device, r.data);
    if (!out.ok) return error(out.error, out.status);
    return json({ room: out.room, plan: out.plan, until: out.until });
  }),
  route("DELETE", `/api/plus/rooms/${ID}`, async (scope, request, [room]) => {
    const r = await deviceRequest(scope, request, null);
    if (!r.ok) return r.response;
    if (!(await removeRoom(scope, r.device, room))) return error("not_found", 404);
    return json({ ok: true });
  }),
  // The account page: linked computers.
  route("GET", "/api/plus/devices", async (scope, request) => {
    const r = await sessionForGet(scope, request);
    if ("response" in r) return r.response;
    if (!r.session) return error("unauthorized", 401);
    const blocked = mfaBlock(r.session, "session");
    if (blocked) return blocked;
    return json({ devices: await listDevices(scope, r.session.user.id), max: DEVICES_MAX });
  }),
  route("POST", "/api/plus/devices/revoke", async (scope, request) => {
    const r = await memberRequest(scope, request, S.revokeDeviceSchema, { mfa: "session" });
    if (!r.ok) return r.response;
    if (!(await revokeDevice(scope, r.session.user.id, r.data.deviceId))) return error("not_found", 404);
    return json({ ok: true });
  }),

  // --- protocol v6: the account's phones (computer side) ---
  route("GET", "/api/plus/phones", async (scope, request) => {
    const r = await deviceRequest(scope, request, null);
    if (!r.ok) return r.response;
    return json(await phonesForDevice(scope, r.device));
  }),
  route("PUT", `/api/plus/phones/${ID}/grant`, async (scope, request, [id]) => {
    const r = await deviceRequest(scope, request, S.grantSchema);
    if (!r.ok) return r.response;
    const out = await putGrant(scope, r.device, id, r.data);
    if (!out.ok) return error(out.error, out.status);
    return json({ ok: true });
  }),
  route("DELETE", `/api/plus/phones/${ID}/grant`, async (scope, request, [id]) => {
    const r = await deviceRequest(scope, request, null);
    if (!r.ok) return r.response;
    if (!(await deleteGrant(scope, r.device, id))) return error("not_found", 404);
    return json({ ok: true });
  }),
  route("PUT", `/api/plus/phones/${ID}/request`, async (scope, request, [id]) => {
    const r = await deviceRequest(scope, request, S.phoneRequestSchema);
    if (!r.ok) return r.response;
    const out = await putRequest(scope, r.device, id, { state: r.data.state, expiresAt: r.data.expiresAt ?? null, commit: r.data.commit, cpub: r.data.cpub, nonce: r.data.nonce ?? null });
    if (!out.ok) return error(out.error, out.status);
    return json({ ok: true });
  }),

  // --- protocol v6: the account's phones (phone side) ---
  route("GET", "/api/phones", async (scope, request) => {
    const r = await sessionForGet(scope, request);
    if ("response" in r) return r.response;
    if (!r.session) return error("unauthorized", 401);
    const blocked = mfaBlock(r.session, "session");
    if (blocked) return blocked;
    return json({ uid: r.session.user.id, phones: await listPhones(scope, r.session.user.id) });
  }),
  route("POST", "/api/phones", async (scope, request) => {
    const r = await memberRequest(scope, request, S.phoneRegisterSchema, { mfa: "fresh" });
    if (!r.ok) return r.response;
    if (accountActionLimited(r.session.user.id, "sessions")) return tooMany();
    const out = await registerPhone(scope, r.session.user.id, r.data, Date.now(), { model: phoneModel(request.headers.get("user-agent") ?? ""), place: null });
    if (!out.ok) return error(out.error, out.error === "invalid_request" ? 400 : 409);
    await notify(scope, r.session, "phone_added");
    // The account's computers hear of it at once through their relay rooms (protocol v6 push).
    nudgeComputersLater(scope, r.session.user.id);
    return json({ ok: true, phone: { id: out.phone.id, name: out.phone.name, created_at: out.phone.created_at } });
  }),
  route("POST", "/api/phones/revoke", async (scope, request) => {
    const r = await memberRequest(scope, request, S.phoneRevokeSchema, { mfa: "session" });
    if (!r.ok) return r.response;
    if (accountActionLimited(r.session.user.id, "sessions")) return tooMany();
    const gone = await revokePhone(scope, r.session.user.id, r.data.id);
    if (!gone) return error("not_found", 404);
    await notify(scope, r.session, "phone_revoked");
    nudgeComputersLater(scope, r.session.user.id);
    return json({ ok: true });
  }),
  route("GET", `/api/phones/${ID}/grants`, async (scope, request, [id]) => {
    const r = await sessionForGet(scope, request);
    if ("response" in r) return r.response;
    if (!r.session) return error("unauthorized", 401);
    const blocked = mfaBlock(r.session, "session");
    if (blocked) return blocked;
    if (accountActionLimited(r.session.user.id, "sessions")) return tooMany();
    // `?wait=<sig>`: a long poll, answered once the grants or requests change (at most 20 s).
    const out = await waitForGrants(scope, r.session.user.id, id, { since: new URL(request.url).searchParams.get("wait"), signal: request.signal });
    if (!out) return error("not_found", 404);
    return json(out);
  }),
  route("POST", `/api/phones/${ID}/again`, async (scope, request, [id]) => {
    const r = await memberRequest(scope, request, S.emptySchema, { mfa: "session" });
    if (!r.ok) return r.response;
    if (accountActionLimited(r.session.user.id, "sessions")) return tooMany();
    if (!(await askAgain(scope, r.session.user.id, id))) return error("not_found", 404);
    nudgeComputersLater(scope, r.session.user.id);
    return json({ ok: true });
  }),
  route("POST", `/api/phones/${ID}/sas`, async (scope, request, [id]) => {
    const r = await memberRequest(scope, request, S.phoneSasSchema, { mfa: "session" });
    if (!r.ok) return r.response;
    if (accountActionLimited(r.session.user.id, "sessions")) return tooMany();
    const out = await answerSas(scope, r.session.user.id, id, r.data);
    if (!out.ok) return error(out.error, out.status);
    // The same answer again (the phone repeats it until the nonce is out) tells nobody again.
    if (out.fresh) nudgeComputersLater(scope, r.session.user.id);
    return json({ ok: true });
  }),
];

/** The API's answer for a request, or null when the path is not an API path (a page or a file). */
export async function handleApi(scope: RequestScope, request: Request): Promise<Response | null> {
  const url = new URL(request.url);
  const relay = await handleRelay(request, scope.env);
  if (relay) return relay;
  const isApi = url.pathname.startsWith("/api/") || url.pathname.startsWith("/.well-known/miblo-relay");
  if (!isApi) return null;
  const method = request.method === "HEAD" ? "GET" : request.method;
  let pathMatched = false;
  for (const r of ROUTES) {
    const m = r.path.exec(url.pathname);
    if (!m) continue;
    pathMatched = true;
    if (r.method !== method) continue;
    try {
      return await r.handler(scope, request, m.slice(1));
    } catch (e) {
      // The route and the error's kind only: never a body, a header or a value.
      console.error(JSON.stringify({ event: "api_error", path: r.path.source.slice(0, 60), error: (e as Error)?.name ?? "Error" }));
      return error("server_error", 500);
    }
  }
  return pathMatched ? error("method_not_allowed", 405) : error("not_found", 404);
}
