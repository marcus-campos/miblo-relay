// Passkeys (WebAuthn) on the phone (docs/phone-relay-protocol.md v4, "Passkeys"; the computer's
// side is the plugin's lib/plus/webauthn.js). The phone app is served by miblo.ai, so code on this
// origin could use the pairing keys while the app is open. Every "allow" therefore needs this
// phone's platform passkey with user verification (Face ID, Touch ID, fingerprint or the device
// PIN) over a challenge bound to that one request; the computer checks it against the public key it
// enrolled at pairing. Only ES256 credentials and "none" attestation are used.
import { b64url, fromB64url } from "./relay-crypto";

/** The relying party: miblo.ai in production; the page's own host on a local test server. */
export function rpIdFor(hostname: string): string {
  return hostname === "miblo.ai" || hostname.endsWith(".miblo.ai") ? "miblo.ai" : hostname;
}

/** Whether this browser has a user-verifying platform authenticator (passkeys on this device). */
export async function platformPasskeys(): Promise<boolean> {
  try {
    if (typeof window === "undefined" || !window.PublicKeyCredential || !navigator.credentials) return false;
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

// --- CBOR (the subset WebAuthn uses) -------------------------------------------------------------

type Cbor = number | string | boolean | null | Uint8Array | Cbor[] | Map<Cbor, Cbor>;

/** Decodes one CBOR item at `offset`; throws on anything malformed or unsupported. */
export function cborDecode(buf: Uint8Array, offset = 0, depth = 0): { value: Cbor; end: number } {
  if (depth > 8) throw new Error("cbor: too deep");
  if (offset >= buf.length) throw new Error("cbor: truncated");
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const head = buf[offset];
  const major = head >> 5;
  const info = head & 0x1f;
  let pos = offset + 1;
  let len: number;
  if (info < 24) {
    len = info;
  } else if (info === 24) {
    len = view.getUint8(pos);
    pos += 1;
  } else if (info === 25) {
    len = view.getUint16(pos);
    pos += 2;
  } else if (info === 26) {
    len = view.getUint32(pos);
    pos += 4;
  } else {
    throw new Error("cbor: unsupported length");
  }
  switch (major) {
    case 0:
      return { value: len, end: pos };
    case 1:
      return { value: -1 - len, end: pos };
    case 2:
    case 3: {
      if (pos + len > buf.length) throw new Error("cbor: truncated");
      const bytes = buf.slice(pos, pos + len);
      return { value: major === 2 ? bytes : new TextDecoder().decode(bytes), end: pos + len };
    }
    case 4: {
      if (len > 64) throw new Error("cbor: array too long");
      const out: Cbor[] = [];
      for (let i = 0; i < len; i++) {
        const item = cborDecode(buf, pos, depth + 1);
        out.push(item.value);
        pos = item.end;
      }
      return { value: out, end: pos };
    }
    case 5: {
      if (len > 64) throw new Error("cbor: map too long");
      const out = new Map<Cbor, Cbor>();
      for (let i = 0; i < len; i++) {
        const k = cborDecode(buf, pos, depth + 1);
        const v = cborDecode(buf, k.end, depth + 1);
        out.set(k.value, v.value);
        pos = v.end;
      }
      return { value: out, end: pos };
    }
    case 7:
      if (info === 20) return { value: false, end: pos };
      if (info === 21) return { value: true, end: pos };
      if (info === 22) return { value: null, end: pos };
      throw new Error("cbor: unsupported simple value");
    default:
      throw new Error("cbor: tags are not supported");
  }
}

/** The credential id and P-256 public key in an attestation object; null when not an ES256 key. */
export function attestedKey(attestationObject: Uint8Array): { credId: string; x: string; y: string; uv: boolean } | null {
  try {
    const obj = cborDecode(attestationObject).value;
    if (!(obj instanceof Map)) return null;
    const ad = obj.get("authData");
    if (!(ad instanceof Uint8Array) || ad.length < 55 || !(ad[32] & 0x40)) return null;
    const idLen = (ad[53] << 8) | ad[54];
    if (55 + idLen > ad.length) return null;
    const credId = ad.slice(55, 55 + idLen);
    const cose = cborDecode(ad, 55 + idLen).value;
    if (!(cose instanceof Map) || cose.get(1) !== 2 || cose.get(3) !== -7 || cose.get(-1) !== 1) return null;
    const x = cose.get(-2);
    const y = cose.get(-3);
    if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) return null;
    return { credId: b64url(credId), x: b64url(x), y: b64url(y), uv: !!(ad[32] & 0x04) };
  } catch {
    return null;
  }
}

const FP_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/** The short fingerprint both sides show for an enrolled passkey ("ABCD-EFGH"). */
export async function fingerprint(credId: string, x: string, y: string): Promise<string> {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`miblo-fp-v4|${credId}|${x}|${y}`)));
  let bits = BigInt(0);
  for (let i = 0; i < 5; i++) bits = (bits << BigInt(8)) | BigInt(h[i]);
  let s = "";
  for (let i = 7; i >= 0; i--) s += FP_ALPHABET[Number((bits >> BigInt(i * 5)) & BigInt(31))];
  return `${s.slice(0, 4)}-${s.slice(4)}`;
}

// --- the browser calls -------------------------------------------------------------------------

export type Enrolled = { credId: string; att: string; cdj: string; fp: string };

/**
 * Makes this phone's passkey (v7: one per phone and account, re-used by every later identity and
 * every computer; before 1.23 one was made per identity): platform authenticator, user verification required,
 * discoverable when possible, ES256, no attestation. Throws when the user cancels or the device
 * cannot.
 */
export async function createPhonePasskey(p: { rpId: string; challenge: Uint8Array<ArrayBuffer>; phoneId: string; computer: string }): Promise<Enrolled> {
  const cred = (await navigator.credentials.create({
    publicKey: {
      rp: { id: p.rpId, name: "Miblo" },
      user: { id: fromB64url(p.phoneId), name: p.computer ? `Miblo · ${p.computer}` : "Miblo", displayName: p.computer ? `Miblo · ${p.computer}` : "Miblo" },
      challenge: p.challenge,
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required", residentKey: "preferred" },
      attestation: "none",
      timeout: 120_000,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("cancelled");
  const res = cred.response as AuthenticatorAttestationResponse;
  const att = new Uint8Array(res.attestationObject);
  const key = attestedKey(att);
  if (!key) throw new Error("unsupported_key");
  return { credId: key.credId, att: b64url(att), cdj: b64url(new Uint8Array(res.clientDataJSON)), fp: await fingerprint(key.credId, key.x, key.y) };
}

export type Assertion = { cred: string; ad: string; cdj: string; sig: string };

/** This phone's passkey over `challenge`, with user verification. Throws when cancelled. */
export async function assertPhonePasskey(p: { rpId: string; credId: string; challenge: Uint8Array<ArrayBuffer> }): Promise<Assertion> {
  const cred = (await navigator.credentials.get({
    publicKey: {
      rpId: p.rpId,
      challenge: p.challenge,
      allowCredentials: [{ type: "public-key", id: fromB64url(p.credId) }],
      userVerification: "required",
      timeout: 60_000,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("cancelled");
  const res = cred.response as AuthenticatorAssertionResponse;
  return {
    cred: b64url(new Uint8Array(cred.rawId)),
    ad: b64url(new Uint8Array(res.authenticatorData)),
    cdj: b64url(new Uint8Array(res.clientDataJSON)),
    sig: b64url(new Uint8Array(res.signature)),
  };
}

/** v7: one of the passkeys this phone may already have (`credIds`), over `challenge`, with user verification. Throws when none answers. */
export async function assertAnyPhonePasskey(p: { rpId: string; credIds: string[]; challenge: Uint8Array<ArrayBuffer> }): Promise<Assertion> {
  const cred = (await navigator.credentials.get({
    publicKey: {
      rpId: p.rpId,
      challenge: p.challenge,
      allowCredentials: p.credIds.map((id) => ({ type: "public-key" as const, id: fromB64url(id) })),
      userVerification: "required",
      timeout: 60_000,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("cancelled");
  const res = cred.response as AuthenticatorAssertionResponse;
  return {
    cred: b64url(new Uint8Array(cred.rawId)),
    ad: b64url(new Uint8Array(res.authenticatorData)),
    cdj: b64url(new Uint8Array(res.clientDataJSON)),
    sig: b64url(new Uint8Array(res.signature)),
  };
}

// --- the account's passkeys (second factor, and the pairing vault through PRF) -------------------

export type RegistrationOptions = {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  excludeCredentials: string[];
};
export type AssertionOptions = { challenge: string; rpId: string; allowCredentials: string[] };
export type AccountAssertion = { wa: Assertion; prf: Uint8Array<ArrayBuffer> | null };

type PrfResults = { prf?: { enabled?: boolean; results?: { first?: ArrayBuffer } } };

/** Creates an account passkey (UV required, discoverable, synced where the platform syncs), asking for PRF. */
export async function createAccountPasskey(o: RegistrationOptions): Promise<{ att: string; cdj: string; prf: boolean }> {
  const cred = (await navigator.credentials.create({
    publicKey: {
      rp: o.rp,
      user: { id: fromB64url(o.user.id), name: o.user.name, displayName: o.user.displayName },
      challenge: fromB64url(o.challenge),
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      authenticatorSelection: { userVerification: "required", residentKey: "required" },
      excludeCredentials: o.excludeCredentials.map((id) => ({ type: "public-key" as const, id: fromB64url(id) })),
      attestation: "none",
      timeout: 120_000,
      extensions: { prf: {} } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("cancelled");
  const res = cred.response as AuthenticatorAttestationResponse;
  const ext = cred.getClientExtensionResults() as PrfResults;
  return { att: b64url(new Uint8Array(res.attestationObject)), cdj: b64url(new Uint8Array(res.clientDataJSON)), prf: ext.prf?.enabled === true || !!ext.prf?.results?.first };
}

/**
 * An account passkey's assertion over the server's challenge (UV required). With `prfSalt`, the
 * same ceremony also evaluates the PRF extension: the vault key comes from it (null when the
 * authenticator or browser has no PRF).
 */
export async function getAccountAssertion(o: AssertionOptions, prfSalt?: Uint8Array<ArrayBuffer>): Promise<AccountAssertion> {
  const cred = (await navigator.credentials.get({
    publicKey: {
      rpId: o.rpId,
      challenge: fromB64url(o.challenge),
      allowCredentials: o.allowCredentials.map((id) => ({ type: "public-key" as const, id: fromB64url(id) })),
      userVerification: "required",
      timeout: 120_000,
      ...(prfSalt ? { extensions: { prf: { eval: { first: prfSalt } } } as AuthenticationExtensionsClientInputs } : {}),
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("cancelled");
  const res = cred.response as AuthenticatorAssertionResponse;
  const ext = cred.getClientExtensionResults() as PrfResults;
  const first = ext.prf?.results?.first;
  return {
    wa: {
      cred: b64url(new Uint8Array(cred.rawId)),
      ad: b64url(new Uint8Array(res.authenticatorData)),
      cdj: b64url(new Uint8Array(res.clientDataJSON)),
      sig: b64url(new Uint8Array(res.signature)),
    },
    prf: first ? new Uint8Array(first) : null,
  };
}
