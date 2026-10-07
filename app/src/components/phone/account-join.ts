// Protocol v6 on the phone (docs/phone-relay-protocol.md, "v6: phones through the account"): this
// phone joins the person's Miblo account, and every linked computer of that account seals its
// pairing to this phone's own key once the person allowed this phone ON THAT COMPUTER (until then the
// computer only says where its confirmation stands: pending, denied or expired). Here: making the identity (an ECDH key that never leaves the
// browser, a random id, a passkey when the device has one), registering it with the account, and
// turning the grants the computers stored into pairings. No pairing, key or token ever comes from a
// link, a QR code or the server in the clear.
import { call } from "@/components/community/security";
import { b64url, computerFingerprint, openGrant, phoneRegChallenge, randomNonce, sasCode, sasCommit, verifyGrantSig, type Grant } from "@/lib/relay-crypto";
import { createPhonePasskey, rpIdFor } from "@/lib/webauthn";
import { listPairings, saveIdentity, savePairingFromGrant, type AccountIdentity, type Pin, type SasRound, type StoredPairing } from "./store";

export type { Pin, SasRound };
export type AccountPhones = { uid: string; phones: { id: string; name: string; passkey: boolean; created_at: string }[] };
export type GrantRow = Grant & { device: { id: string; name: string }; at: string; cpub?: string | null; sig?: string | null };
export type RequestRow = {
  device: { id: string; name: string };
  state: "pending" | "denied" | "expired";
  expires_at: string | null;
  at: string;
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
export type Waiting = { kind: "pending"; device: string; expiresAt: number } | { kind: "expired"; device: string } | { kind: "denied"; device: string } | null;
export function waitingFor(requests: RequestRow[], now: number): Waiting {
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
export async function makeIdentity(uid: string, name: string, passkeys: boolean): Promise<{ identity: AccountIdentity; att?: string; cdj?: string }> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])) as CryptoKeyPair;
  const pub = b64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  const id = randomNonce(16);
  let credId: string | null = null;
  let att: string | undefined;
  let cdj: string | undefined;
  if (passkeys) {
    const made = await createPhonePasskey({ rpId: rpIdFor(location.hostname), challenge: await phoneRegChallenge(id, pub), phoneId: id, computer: name });
    credId = made.credId;
    att = made.att;
    cdj = made.cdj;
  }
  return { identity: { uid, id, name, priv: pair.privateKey, pub, credId, at: Date.now(), registered: false, pins: [], rounds: [] }, att, cdj };
}

export type RegisterResult = "ok" | "mfa" | "mfa_setup" | "limit" | "error";

/** Registers the identity with the account (needs the second factor passed in the last 5 minutes). */
export async function registerIdentity(csrf: string, made: { identity: AccountIdentity; att?: string; cdj?: string }): Promise<RegisterResult> {
  const { identity: me } = made;
  const r = await call("/api/phones", { id: me.id, name: me.name, pub: me.pub, ...(made.att && made.cdj ? { att: made.att, cdj: made.cdj } : {}) }, csrf);
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
