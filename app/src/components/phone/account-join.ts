// Protocol v6 on the phone (docs/phone-relay-protocol.md, "v6: phones through the account"): this
// phone joins the person's Miblo account, and every linked computer of that account seals its
// pairing to this phone's own key once the person allowed this phone ON THAT COMPUTER (until then the
// computer only says where its confirmation stands: pending, denied or expired). Here: making the identity (an ECDH key that never leaves the
// browser, a random id, a passkey when the device has one), registering it with the account, and
// turning the grants the computers stored into pairings. No pairing, key or token ever comes from a
// link, a QR code or the server in the clear.
import { call } from "@/components/community/security";
import { b64url, computerFingerprint, openGrant, phoneRegChallenge, randomNonce, sasCode, sasCommit, verifyGrantSig, type Grant } from "@/lib/relay-crypto";
import { assertAnyPhonePasskey, assertPhonePasskey, createPhonePasskey, rpIdFor, type Assertion } from "@/lib/webauthn";
import { confOf, pakeChallenge, phoneAnswer, phoneReuseChallenge, sidOf } from "@/lib/pake";
import { listPairings, saveIdentity, savePairingFromGrant, type AccountIdentity, type PakeRun, type Pin, type SasRound, type StoredPairing } from "./store";

export type { Pin, SasRound };
/** `pk` (v7): a phone's passkey public key, so a new identity of this phone can re-use it. */
export type PhonePk = { id: string; x: string; y: string };
export type AccountPhones = { uid: string; phones: { id: string; name: string; passkey: boolean; created_at: string }[]; passkeys?: PhonePk[] };
/** v7: the computer's share of the current attempt of its code exchange. */
export type PakeRound = { n: number; rs: string; ya: string; wrong: number };
export type GrantRow = Grant & { device: { id: string; name: string }; at: string; cpub?: string | null; sig?: string | null };
export type RequestRow = {
  device: { id: string; name: string };
  state: "pending" | "confirm" | "denied" | "expired";
  expires_at: string | null;
  at: string;
  /** v7: the computer shows the code; this phone answers this attempt with what the person types. */
  pake?: PakeRound | null;
  /** The round of the code exchange (protocol v6 "Verifying a new phone"). */
  commit?: string | null;
  cpub?: string | null;
  nonce?: string | null;
};
/** `sig`: a digest of both, for the long poll (`fetchGrants`'s `wait`). */
export type GrantsResult = { grants: GrantRow[]; requests: RequestRow[]; sig?: string };

/** The account's phones (and the account id), or the HTTP status that refused them. */
export async function fetchAccountPhones(): Promise<AccountPhones | number> {
  try {
    const res = await fetch("/api/phones", { headers: { Accept: "application/json" } });
    if (!res.ok) return res.status;
    const d = (await res.json()) as AccountPhones;
    return typeof d.uid === "string" && Array.isArray(d.phones) ? d : 500;
  } catch {
    return 0;
  }
}

/**
 * The grants and requests for this phone. `wait`: the sig last seen; the server answers once they
 * changed (a computer took its next step) or after about 20 s (a long poll).
 */
export async function fetchGrants(phone: string, wait: string | null = null, signal?: AbortSignal): Promise<GrantsResult | number> {
  try {
    const q = wait && /^[0-9a-f]{32}$/.test(wait) ? `?wait=${wait}` : "";
    const res = await fetch(`/api/phones/${phone}/grants${q}`, { headers: { Accept: "application/json" }, signal });
    if (!res.ok) return res.status;
    const d = (await res.json()) as { grants?: GrantRow[]; requests?: RequestRow[]; sig?: unknown };
    const sig = typeof d.sig === "string" && /^[0-9a-f]{32}$/.test(d.sig) ? d.sig : undefined;
    return Array.isArray(d.grants) ? { grants: d.grants, requests: Array.isArray(d.requests) ? d.requests : [], ...(sig ? { sig } : {}) } : 500;
  } catch {
    return 0;
  }
}

/** What this phone shows while no computer let it in yet: the most hopeful computer's answer. */
export type Waiting =
  | { kind: "pending"; device: string; expiresAt: number }
  | { kind: "code"; device: string; deviceId: string; expiresAt: number; left: number; wrong: number }
  | { kind: "confirm"; device: string; expiresAt: number }
  | { kind: "expired"; device: string }
  | { kind: "denied"; device: string }
  | null;
export function waitingFor(requests: RequestRow[], now: number): Waiting {
  // v7: a computer showing its code (the person types it here), or holding this phone until a
  // phone it already has confirms it.
  const typed = requests.find((r) => r.state === "pending" && r.pake && Date.parse(r.expires_at ?? "") > now);
  if (typed?.pake) return { kind: "code", device: typed.device.name, deviceId: typed.device.id, expiresAt: Date.parse(typed.expires_at!), left: Math.max(0, 3 - typed.pake.wrong), wrong: typed.pake.wrong };
  const held = requests.find((r) => r.state === "confirm" && Date.parse(r.expires_at ?? "") > now);
  if (held) return { kind: "confirm", device: held.device.name, expiresAt: Date.parse(held.expires_at!) };
  const pending = requests
    .map((r) => ({ r, until: r.state === "pending" ? Date.parse(r.expires_at ?? "") : NaN }))
    .filter((x) => Number.isFinite(x.until) && x.until > now)
    .sort((a, b) => b.until - a.until)[0];
  if (pending) return { kind: "pending", device: pending.r.device.name, expiresAt: pending.until };
  // A pending one past its time is expired, whether or not that computer said so yet.
  const expired = requests.find((r) => r.state === "expired" || r.state === "pending");
  if (expired) return { kind: "expired", device: expired.device.name };
  const denied = requests.find((r) => r.state === "denied");
  return denied ? { kind: "denied", device: denied.device.name } : null;
}

/** Asks the account's computers again after a request expired (each asks the person there again). */
export async function askAgain(csrf: string, phone: string): Promise<boolean> {
  const r = await call(`/api/phones/${phone}/again`, {}, csrf);
  return r.status === 200;
}

/** What this phone calls itself in the account (and on the computers). */
export function deviceName(ua: string): string {
  if (/iPhone/.test(ua)) return "iPhone";
  if (/iPad/.test(ua)) return "iPad";
  const android = /Android[^;]*;\s*([^;)]+?)(?:\sBuild|\))/.exec(ua);
  if (android && android[1] && !/^(K|Linux)$/.test(android[1].trim())) return android[1].trim().slice(0, 30);
  if (/Android/.test(ua)) return "Android";
  return "Browser";
}

/**
 * Makes this phone's identity for account `uid`: the ECDH key pair (private key non-extractable),
 * a random id, and (`passkeys`) a passkey created over the v6 registration challenge.
 * -> the identity (not registered yet) and the registration to send.
 */
export async function makeIdentity(uid: string, name: string, passkeys: boolean, known: PhonePk[] = []): Promise<{ identity: AccountIdentity; att?: string; cdj?: string; pk?: PhonePk; pkwa?: Assertion }> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])) as CryptoKeyPair;
  const pub = b64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  const id = randomNonce(16);
  const base = { uid, id, name, priv: pair.privateKey, pub, at: Date.now(), registered: false, pins: [], rounds: [] };
  if (!passkeys) return { identity: { ...base, credId: null } };
  // v7: one passkey per phone. A passkey of this account that this device holds (the account
  // lists their public keys) is proven with an assertion over this new identity; only when none
  // answers is a new one made.
  const ids = known.map((k) => k.id).slice(0, 16);
  if (ids.length) {
    try {
      const wa = await assertAnyPhonePasskey({ rpId: rpIdFor(location.hostname), credIds: ids, challenge: await phoneReuseChallenge(id, pub) });
      const pk = known.find((k) => k.id === wa.cred);
      if (pk) return { identity: { ...base, credId: pk.id }, pk, pkwa: wa };
    } catch {
      // None of them on this device (or the person cancelled): a new passkey below.
    }
  }
  const made = await createPhonePasskey({ rpId: rpIdFor(location.hostname), challenge: await phoneRegChallenge(id, pub), phoneId: id, computer: "" });
  return { identity: { ...base, credId: made.credId }, att: made.att, cdj: made.cdj };
}

/**
 * v7: what joining does with passkeys. None of the account's on this device's list: make one (no
 * question). Some: ask once ("Usar a mesma?") unless the person already chose to re-use (remembered);
 * then re-use. A person who asks for another gets a new one.
 */
export function passkeyPlan(known: number, remembered: boolean, choice: "reuse" | "create" | null): "ask" | "reuse" | "create" {
  if (choice) return choice;
  if (!known) return "create";
  return remembered ? "reuse" : "ask";
}

export type RegisterResult = "ok" | "mfa" | "mfa_setup" | "limit" | "error";

/** Registers the identity with the account (needs the second factor passed in the last 5 minutes). */
export async function registerIdentity(csrf: string, made: { identity: AccountIdentity; att?: string; cdj?: string; pk?: PhonePk; pkwa?: Assertion }): Promise<RegisterResult> {
  const { identity: me } = made;
  const r = await call("/api/phones", { id: me.id, name: me.name, pub: me.pub, ...(made.att && made.cdj ? { att: made.att, cdj: made.cdj } : {}), ...(made.pk && made.pkwa ? { pk: made.pk, pkwa: made.pkwa } : {}) }, csrf);
  if (r.status === 200) {
    await saveIdentity({ ...me, registered: true });
    return "ok";
  }
  const err = String(r.data.error ?? "");
  if (err === "mfa_fresh_required" || err === "mfa_required") return "mfa";
  if (err === "mfa_setup_required") return "mfa_setup";
  if (err === "phone_limit") return "limit";
  return "error";
}

// --- the code and the computers this phone confirmed (security audit 1.21.0) ----------------------

const N43 = /^[A-Za-z0-9_-]{43}$/;
const CPUB = /^[A-Za-z0-9_-]{87}$/;
const ROUNDS_KEPT = 16;
/** New rounds this phone answers in an hour, all computers together (audit 1.21.0 round 2: a flood of commitments would let the server grind the code). */
export const SAS_ROUNDS_PER_HOUR = 3;
const HOUR_MS = 3_600_000;
/** A round answered but not revealed is open this long (a request waits 15 minutes). */
const ROUND_OPEN_MS = 15 * 60_000;
/** The "Novo computador" card is offered only this long after the code was shown. */
const CONFIRM_MS = 30 * 60_000;

export type ShownCode = { device: string; name: string; code: string; cpub: string; fp: string };
export type SasStep = { rounds: SasRound[]; answers: { device: string; commit: string; pnonce: string }[]; codes: ShownCode[]; mismatch: string[]; alert: boolean };

/**
 * One pass of the code exchange over the computers' requests. A pending request's commitment is
 * answered with this phone's nonce (made once, kept per commitment) only while the computer's
 * nonce is not out yet: a commitment first seen with its nonce is never answered (whoever relays
 * could have picked it after seeing the nonce). Once the nonce is out and opens the commitment
 * with this phone's own key, the code is shown; a nonce that does not (the computer was shown
 * another key for this phone) is flagged and shows nothing.
 */
export async function sasStep(me: { id: string; pub: string }, rounds: SasRound[], requests: RequestRow[], newNonce = () => randomNonce(32), now = Date.now()): Promise<SasStep> {
  const next = rounds.map((r) => ({ ...r }));
  const out: SasStep = { rounds: next, answers: [], codes: [], mismatch: [], alert: false };
  // A computer that turned this phone's code down: its rounds never lead to a "Novo computador" card.
  for (const q of requests.slice(0, 16)) {
    if (q.state !== "denied") continue;
    for (const r of next) if (r.device === q.device.id && r.code) r.denied = true;
  }
  for (const q of requests.slice(0, 16)) {
    if (q.state !== "pending" || typeof q.commit !== "string" || !N43.test(q.commit) || typeof q.cpub !== "string" || !CPUB.test(q.cpub)) continue;
    let r = next.find((x) => x.device === q.device.id && x.commit === q.commit);
    if (!r) {
      if (q.nonce) continue;
      // At most one open round per computer, and SAS_ROUNDS_PER_HOUR new rounds an hour in all:
      // more is someone trying to grind the code (the alert says so), never a person pairing.
      const open = next.some((x) => x.device === q.device.id && !x.nonce && now - x.at < ROUND_OPEN_MS);
      const lastHour = next.filter((x) => now - x.at < HOUR_MS).length;
      if (open) continue;
      if (lastHour >= SAS_ROUNDS_PER_HOUR) {
        out.alert = true;
        continue;
      }
      r = { device: q.device.id, commit: q.commit, cpub: q.cpub, pnonce: newNonce(), at: now };
      next.push(r);
    }
    if (!q.nonce) {
      if (now - r.at < ROUND_OPEN_MS) out.answers.push({ device: r.device, commit: r.commit, pnonce: r.pnonce });
      continue;
    }
    if (typeof q.nonce !== "string" || !N43.test(q.nonce) || r.cpub !== q.cpub || (await sasCommit(me.id, me.pub, r.cpub, q.nonce)) !== q.commit) {
      out.mismatch.push(r.device);
      continue;
    }
    if (!r.nonce) r.revealedAt = now;
    r.nonce = q.nonce;
    r.code = await sasCode(me.id, me.pub, r.cpub, q.nonce, r.pnonce);
    out.codes.push({ device: r.device, name: q.device.name, code: r.code, cpub: r.cpub, fp: await computerFingerprint(r.cpub) });
  }
  // Kept at least an hour (the hourly count) and at most ROUNDS_KEPT.
  out.rounds = next.sort((a, b) => b.at - a.at).slice(0, Math.max(ROUNDS_KEPT, next.filter((x) => now - x.at < HOUR_MS).length));
  return out;
}

/** Sends this phone's nonces to the account (each answer once per round; the same answer again is fine). */
export async function sendSasAnswers(csrf: string, phone: string, answers: SasStep["answers"]): Promise<void> {
  for (const a of answers) await call(`/api/phones/${phone}/sas`, a, csrf).catch(() => null);
}

/**
 * What to do with a grant: "ok" (signed by a computer this phone confirmed), "confirm" (signed by
 * the computer of a code this phone showed: the person confirms it on the phone first), or "bad"
 * (unsigned, a signature that does not verify, or a key this phone never saw: a grant the server
 * could have made itself).
 */
export async function grantVerdict(phone: string, pins: Pin[], rounds: SasRound[], g: GrantRow, now = Date.now()): Promise<"ok" | "confirm" | "bad"> {
  if (typeof g.cpub !== "string" || typeof g.sig !== "string") return "bad";
  if (!(await verifyGrantSig(phone, { ...g, cpub: g.cpub, sig: g.sig }))) return "bad";
  if (pins.some((p) => p.cpub === g.cpub)) return "ok";
  // Only the computer of a code shown in the last half hour, which did not turn it down.
  if (rounds.some((r) => r.cpub === g.cpub && r.code && !r.denied && now - (r.revealedAt ?? r.at) < CONFIRM_MS)) return "confirm";
  return "bad";
}

// --- v7: the computer shows the code, this phone types it ------------------------------------------

/** A v7 run is kept this long for its computer's first grant (a request waits 15 minutes). */
const PAKE_KEPT_MS = 30 * 60_000;
export type PakeSend = "ok" | "cancelled" | "error" | "gone";

/**
 * The person typed `code` (shown on the computer of request `q`): this phone's answer to that
 * attempt, with its passkey over it (user verification) when it has one, sent through the account.
 * The key of the run is kept (the computer's confirmation in its first grant pins it).
 */
export async function answerCode(csrf: string, me: AccountIdentity, q: RequestRow, code: string, deps: { post?: typeof call; assert?: typeof assertPhonePasskey } = {}): Promise<{ result: PakeSend; me: AccountIdentity }> {
  const post = deps.post ?? call;
  const assert = deps.assert ?? assertPhonePasskey;
  if (!q.pake || !q.cpub || !/^\d{6}$/.test(code)) return { result: "error", me };
  const sid = sidOf({ phone: me.id, pub: me.pub, cpub: q.cpub, n: q.pake.n, rs: q.pake.rs });
  const ans = await phoneAnswer(code, sid, q.pake.ya);
  let wa: Assertion | undefined;
  if (me.credId) {
    try {
      wa = await assert({ rpId: rpIdFor(location.hostname), credId: me.credId, challenge: await pakeChallenge({ phone: me.id, pub: me.pub, cpub: q.cpub, ya: q.pake.ya, yb: ans.yb, tag: ans.tag }) });
    } catch {
      return { result: "cancelled", me };
    }
  }
  const run: PakeRun = { device: q.device.id, cpub: q.cpub, isk: ans.isk, at: Date.now() };
  const next = { ...me, pakes: [...(me.pakes ?? []).filter((x) => Date.now() - x.at < PAKE_KEPT_MS && x.cpub !== q.cpub), run].slice(-8) };
  await saveIdentity(next);
  const r = await post(`/api/phones/${me.id}/pake`, { device: q.device.id, n: q.pake.n, ya: q.pake.ya, yb: ans.yb, tag: ans.tag, ...(wa ? { wa } : {}) }, csrf);
  return { result: r.status === 200 ? "ok" : r.status === 404 || r.status === 409 ? "gone" : "error", me: next };
}

/**
 * A grant from a computer this phone has not pinned yet: pinned when its sealed payload carries the
 * confirmation of a code exchange this phone ran with that very key (v7). -> the identity, pinned,
 * or null.
 */
export async function pinByCode(me: AccountIdentity, g: GrantRow, payload: { conf?: unknown }, now = Date.now()): Promise<AccountIdentity | null> {
  if (typeof g.cpub !== "string" || typeof payload.conf !== "string") return null;
  for (const r of me.pakes ?? []) {
    if (r.cpub !== g.cpub || now - r.at > PAKE_KEPT_MS) continue;
    if ((await confOf(r.isk)) !== payload.conf) continue;
    const pins = [...(me.pins ?? []).filter((p) => p.cpub !== g.cpub), { cpub: g.cpub, device: g.device.id, name: g.device.name.slice(0, 40), at: now }];
    const next = { ...me, pins, pakes: (me.pakes ?? []).filter((x) => x !== r) };
    await saveIdentity(next);
    return next;
  }
  return null;
}

/** The pairings the signed-in account (`uid`; null: signed out) may use, and whether others are here. */
export function pairingsFor(all: StoredPairing[], uid: string | null): { keep: StoredPairing[]; wipe: boolean } {
  if (!uid) return { keep: [], wipe: false };
  const keep = all.filter((p) => p.acct?.uid === uid);
  return { keep, wipe: keep.length !== all.length };
}

/** The person confirmed on the phone that they typed this computer's code there: pinned. */
export async function confirmComputer(me: AccountIdentity, c: { cpub: string; device: string; name: string }): Promise<AccountIdentity> {
  const pins = [...(me.pins ?? []).filter((p) => p.cpub !== c.cpub), { cpub: c.cpub, device: c.device, name: c.name.slice(0, 40), at: Date.now() }];
  const next = { ...me, pins };
  await saveIdentity(next);
  return next;
}

/** A computer the person turned down on the phone: its rounds are forgotten (its grants stay refused). */
export async function rejectComputer(me: AccountIdentity, cpub: string): Promise<AccountIdentity> {
  const next = { ...me, rounds: (me.rounds ?? []).filter((r) => r.cpub !== cpub) };
  await saveIdentity(next);
  return next;
}

/**
 * The account's grants for this phone: only those signed by a computer this phone confirmed are
 * opened and kept as pairings (bound to this account and that computer key). Grants of a computer
 * whose code this phone showed but the person has not confirmed here yet come back in `confirm`.
 * A pairing whose grant is no longer listed is kept (the server could withhold a grant to make
 * the phone drop a computer; a computer that revoked this phone is refused at the relay, 4411,
 * and the app says so). Residual: withholding grants delays new keys (a denial of service only).
 * -> the pairings now kept, or null when the grants could not be read (nothing changes then).
 */
export async function syncGrants(me: AccountIdentity, grants: GrantRow[]): Promise<{ pairings: StoredPairing[]; changed: boolean; confirm: ShownCode[] } | null> {
  let changed = false;
  const rooms = new Set<string>();
  const confirm: ShownCode[] = [];
  for (const g of grants.slice(0, 16)) {
    try {
      // v7: a computer this phone typed the code of: its grant's confirmation pins it.
      if (typeof g.cpub === "string" && typeof g.sig === "string" && !(me.pins ?? []).some((p) => p.cpub === g.cpub) && (me.pakes ?? []).some((r) => r.cpub === g.cpub)
        && (await verifyGrantSig(me.id, { ...g, cpub: g.cpub, sig: g.sig }))) {
        const payload = await openGrant(me.priv, me.id, g);
        const pinned = await pinByCode(me, g, payload as { conf?: unknown });
        if (pinned) me = pinned;
      }
      const verdict = await grantVerdict(me.id, me.pins ?? [], me.rounds ?? [], g);
      if (verdict === "confirm") {
        const r = (me.rounds ?? []).find((x) => x.cpub === g.cpub && x.code && !x.denied)!;
        if (!confirm.some((c) => c.cpub === g.cpub)) confirm.push({ device: g.device.id, name: g.device.name, code: r.code!, cpub: g.cpub!, fp: await computerFingerprint(g.cpub!) });
        continue;
      }
      if (verdict !== "ok") continue;
      const payload = await openGrant(me.priv, me.id, g);
      rooms.add(payload.room);
      if (await savePairingFromGrant(payload, { id: me.id, credId: me.credId, uid: me.uid }, g.device.id, g.cpub!)) changed = true;
    } catch {
      // Not for this phone, or tampered: ignored.
    }
  }
  return { pairings: (await listPairings()).filter((p) => p.acct?.uid === me.uid), changed, confirm };
}
