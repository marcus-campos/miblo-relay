// The account's password: PBKDF2-SHA-256 with a random salt, on the Web Crypto API (Cloudflare
// Workers allow at most 100,000 iterations; the password is only the first factor, a second factor
// is mandatory, and attempts are limited per IP and per account).
import { base64url, base64urlDecode } from "../crypto";

export const PBKDF2_ITERATIONS = 100_000;
export const PASSWORD_MIN = 12;
export const PASSWORD_MAX = 200;

async function derive(password: string, salt: Uint8Array<ArrayBuffer>, iterations: number): Promise<Uint8Array<ArrayBuffer>> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password.normalize("NFKC")), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256));
}

/** "pbkdf2-sha256$<iterations>$<salt>$<hash>" (base64url). */
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return `pbkdf2-sha256$${PBKDF2_ITERATIONS}$${base64url(salt)}$${base64url(await derive(password, salt, PBKDF2_ITERATIONS))}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [kind, iter, salt, hash] = stored.split("$");
  const n = Number(iter);
  if (kind !== "pbkdf2-sha256" || !Number.isInteger(n) || n < 10_000 || n > PBKDF2_ITERATIONS || !salt || !hash) return false;
  try {
    const got = await derive(password, base64urlDecode(salt), n);
    const want = base64urlDecode(hash);
    if (got.length !== want.length) return false;
    let d = 0;
    for (let i = 0; i < got.length; i++) d |= got[i] ^ want[i];
    return d === 0;
  } catch {
    return false;
  }
}

/** Why a new password is refused, or null. */
export function passwordProblem(password: unknown): string | null {
  if (typeof password !== "string") return "password_required";
  if ([...password].length < PASSWORD_MIN) return "password_too_short";
  if (password.length > PASSWORD_MAX) return "password_too_long";
  return null;
}
