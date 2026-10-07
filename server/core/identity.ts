// The server's identity key (Ed25519), for trust on first use by the plugin.
//
// `miblo server set <url>` reads the key from GET /.well-known/miblo-relay.json, shows its
// fingerprint to the person and pins it; from then on the plugin asks the server to sign a fresh
// challenge (POST /api/server/identity) before it trusts the server with anything (account link,
// phone registry, relay). A server that cannot sign with the pinned key (a different install, a
// hijacked domain with a valid certificate) is refused until the person accepts the new key with
// the gadget code. The key never leaves the server; only its public half is published.
//
//   GET  /.well-known/miblo-relay.json -> {v: 1, kind: "miblo-relay", origin, key, fingerprint, version, protocol}
//   POST /api/server/identity {nonce} -> {sig}: Ed25519 over "miblo-relay-identity-v1|<origin>|<nonce>"
import { base64url, base64urlDecode } from "./crypto";

export const IDENTITY_CONTEXT = "miblo-relay-identity-v1";
export const SERVER_VERSION = "1.0.0";
/** The phone relay protocol version this server speaks (docs/protocol.md). */
export const PROTOCOL_VERSION = 6;

type KeyPair = { privateKey: CryptoKey; publicRaw: Uint8Array<ArrayBuffer> };
const cache = new Map<string, Promise<KeyPair>>();

/** The key pair from SERVER_IDENTITY_KEY (PKCS#8, base64url). */
export function identityKey(pkcs8: string): Promise<KeyPair> {
  let p = cache.get(pkcs8);
  if (!p) {
    p = (async () => {
      const privateKey = await crypto.subtle.importKey("pkcs8", base64urlDecode(pkcs8), { name: "Ed25519" }, true, ["sign"]);
      // The public key is the JWK's x (the raw 32 bytes).
      const jwk = (await crypto.subtle.exportKey("jwk", privateKey)) as JsonWebKey;
      return { privateKey, publicRaw: base64urlDecode(String(jwk.x)) };
    })();
    cache.set(pkcs8, p);
  }
  return p;
}

/** A new identity key (PKCS#8, base64url): what the setup scripts store as SERVER_IDENTITY_KEY. */
export async function newIdentityKey(): Promise<string> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  return base64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)));
}

/** The fingerprint people compare: SHA-256 of the raw public key, the first 20 bytes as 5 groups of 8 hex digits. */
export async function fingerprint(publicRaw: Uint8Array<ArrayBuffer>): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", publicRaw));
  const hex = [...d.subarray(0, 20)].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  return hex.match(/.{8}/g)!.join("-");
}

export async function identityDocument(pkcs8: string, origin: string) {
  const { publicRaw } = await identityKey(pkcs8);
  return { v: 1, kind: "miblo-relay", origin, key: base64url(publicRaw), fingerprint: await fingerprint(publicRaw), version: SERVER_VERSION, protocol: PROTOCOL_VERSION };
}

export async function signIdentity(pkcs8: string, origin: string, nonce: string): Promise<string> {
  const { privateKey } = await identityKey(pkcs8);
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, privateKey, new TextEncoder().encode(`${IDENTITY_CONTEXT}|${origin}|${nonce}`));
  return base64url(new Uint8Array(sig));
}
