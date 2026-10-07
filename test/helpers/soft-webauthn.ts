// A software WebAuthn authenticator for tests (ES256 or RS256, "none" attestation, optional PRF):
// what navigator.credentials.create()/get() return, in the byte formats the spec fixes, so the
// server's verification (server/core/account/webauthn.ts) is checked against real structures.
import { createHash, createHmac, generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";

const sha256 = (d: Buffer | string) => createHash("sha256").update(d).digest();

export function cborEncode(v: unknown): Buffer {
  const head = (major: number, n: number) => {
    if (n < 24) return Buffer.from([(major << 5) | n]);
    if (n < 256) return Buffer.from([(major << 5) | 24, n]);
    if (n < 65536) {
      const b = Buffer.alloc(3);
      b[0] = (major << 5) | 25;
      b.writeUInt16BE(n, 1);
      return b;
    }
    const b = Buffer.alloc(5);
    b[0] = (major << 5) | 26;
    b.writeUInt32BE(n, 1);
    return b;
  };
  if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (v instanceof Uint8Array) return Buffer.concat([head(2, v.length), Buffer.from(v)]);
  if (typeof v === "string") {
    const b = Buffer.from(v, "utf8");
    return Buffer.concat([head(3, b.length), b]);
  }
  if (v instanceof Map) return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [cborEncode(k), cborEncode(x)])]);
  throw new Error("cbor: unsupported");
}

export class SoftWebAuthn {
  credId = randomBytes(16);
  signCount = 0;
  private key: { privateKey: KeyObject; publicKey: KeyObject };
  private prfSeed = randomBytes(32);

  constructor(readonly alg: -7 | -257 = -7) {
    this.key = alg === -7 ? generateKeyPairSync("ec", { namedCurve: "P-256" }) : generateKeyPairSync("rsa", { modulusLength: 2048 });
  }

  get cred(): string {
    return this.credId.toString("base64url");
  }

  private cose(): Buffer {
    const jwk = this.key.publicKey.export({ format: "jwk" }) as { x?: string; y?: string; n?: string; e?: string };
    if (this.alg === -7) {
      return cborEncode(new Map<number, unknown>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, "base64url")], [-3, Buffer.from(jwk.y!, "base64url")]]));
    }
    return cborEncode(new Map<number, unknown>([[1, 3], [3, -257], [-1, Buffer.from(jwk.n!, "base64url")], [-2, Buffer.from(jwk.e!, "base64url")]]));
  }

  private authData(rpId: string, { uv = true, attested = false } = {}): Buffer {
    const flags = 0x01 | (uv ? 0x04 : 0) | (attested ? 0x40 : 0);
    if (!attested) this.signCount += 1;
    const count = Buffer.alloc(4);
    count.writeUInt32BE(this.signCount);
    const parts: Buffer[] = [sha256(rpId), Buffer.from([flags]), count];
    if (attested) {
      const len = Buffer.alloc(2);
      len.writeUInt16BE(this.credId.length);
      parts.push(Buffer.alloc(16), len, this.credId, this.cose());
    }
    return Buffer.concat(parts);
  }

  create(o: { challenge: string; rpId: string; origin: string; uv?: boolean }): { att: string; cdj: string } {
    const cdj = Buffer.from(JSON.stringify({ type: "webauthn.create", challenge: o.challenge, origin: o.origin, crossOrigin: false }));
    const authData = this.authData(o.rpId, { uv: o.uv ?? true, attested: true });
    const att = cborEncode(new Map<string, unknown>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]));
    return { att: att.toString("base64url"), cdj: cdj.toString("base64url") };
  }

  get(o: { challenge: string; rpId: string; origin: string; uv?: boolean; type?: string }): { cred: string; ad: string; cdj: string; sig: string } {
    const cdj = Buffer.from(JSON.stringify({ type: o.type ?? "webauthn.get", challenge: o.challenge, origin: o.origin, crossOrigin: false }));
    const ad = this.authData(o.rpId, { uv: o.uv ?? true });
    const data = Buffer.concat([ad, sha256(cdj)]);
    const sig = this.alg === -7 ? sign("sha256", data, { key: this.key.privateKey, dsaEncoding: "der" }) : sign("sha256", data, this.key.privateKey);
    return { cred: this.cred, ad: ad.toString("base64url"), cdj: cdj.toString("base64url"), sig: sig.toString("base64url") };
  }

  /** What the PRF extension gives for `salt` (a per-credential secret function, like hmac-secret). */
  prf(salt: Uint8Array): Uint8Array<ArrayBuffer> {
    return new Uint8Array(createHmac("sha256", this.prfSeed).update(Buffer.from(salt)).digest());
  }
}
