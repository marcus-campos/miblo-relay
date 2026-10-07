// The account's password: PBKDF2-SHA-256 with a random salt, on the Web Crypto API. The work factor
// depends on the runtime: 600,000 iterations on Node (OWASP's figure for PBKDF2-SHA-256); Cloudflare
// Workers allow at most 100,000, so a Worker uses that. The password is only the first factor (a
// second factor is mandatory) and attempts are limited per network and per account.
import { base64url, base64urlDecode } from "../crypto";

/** Cloudflare Workers' ceiling (and the default when the runtime says nothing). */
export const PBKDF2_ITERATIONS = 100_000;
/** What the Node runtime uses (server/node/server.ts sets it). */
export const PBKDF2_ITERATIONS_NODE = 600_000;
/** The most a stored hash may ask for (a bigger number is refused, never computed). */
const PBKDF2_MAX = 1_000_000;
export const PASSWORD_MIN = 12;
export const PASSWORD_MAX = 200;

/** The runtime's work factor: env.PBKDF2_ITERATIONS when the runtime sets it, else the Workers ceiling. */
export function passwordIterations(env: { PBKDF2_ITERATIONS?: string }): number {
  const n = Number(env.PBKDF2_ITERATIONS);
  return Number.isInteger(n) && n >= PBKDF2_ITERATIONS && n <= PBKDF2_MAX ? n : PBKDF2_ITERATIONS;
}

async function derive(password: string, salt: Uint8Array<ArrayBuffer>, iterations: number): Promise<Uint8Array<ArrayBuffer>> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password.normalize("NFKC")), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256));
}

/** "pbkdf2-sha256$<iterations>$<salt>$<hash>" (base64url). */
export async function hashPassword(password: string, iterations = PBKDF2_ITERATIONS): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return `pbkdf2-sha256$${iterations}$${base64url(salt)}$${base64url(await derive(password, salt, iterations))}`;
}

/** A hash nobody's password matches, at `iterations`: checked when there is no account (the same work). */
export function dummyHash(iterations = PBKDF2_ITERATIONS): string {
  return `pbkdf2-sha256$${iterations}$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;
}

/** The iterations a stored hash was made with (0 when it is not one of ours). */
export function hashIterations(stored: string): number {
  const [kind, iter] = stored.split("$");
  const n = Number(iter);
  return kind === "pbkdf2-sha256" && Number.isInteger(n) ? n : 0;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [kind, , salt, hash] = stored.split("$");
  const n = hashIterations(stored);
  if (kind !== "pbkdf2-sha256" || n < 10_000 || n > PBKDF2_MAX || !salt || !hash) return false;
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
