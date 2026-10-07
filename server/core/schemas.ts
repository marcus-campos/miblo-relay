// Request schemas (zod). The same shapes as miblo.ai's API, so the plugin and the phone app talk
// to a self-hosted server unchanged.
import { z } from "zod";

const noControl = (s: string) => !/[\u0000-\u001f\u007f]/.test(s);
const text = (min: number, max: number) => z.string().trim().min(min).max(max).refine(noControl, "control_chars");
const b64u = (max: number) => z.string().max(max).regex(/^[A-Za-z0-9_-]*$/);

export const emptySchema = z.object({}).passthrough();

// --- the account ---------------------------------------------------------------------------------

export const usernameSchema = z.string().trim().min(1).max(60).refine(noControl, "control_chars");
export const setupSchema = z.object({ token: z.string().min(16).max(200), username: usernameSchema, password: z.string().min(1).max(200), lang: z.enum(["pt", "en"]).default("pt") });
export const passwordSignInSchema = z.object({ username: usernameSchema, password: z.string().min(1).max(200) });
/** A WebAuthn assertion as the browser gives it (base64url fields). */
export const assertionSchema = z.object({ cred: b64u(1400).min(2), ad: b64u(2048).min(50), cdj: b64u(4096).min(20), sig: b64u(1024).min(8) });
export const passkeySignInSchema = z.object({ wa: assertionSchema });
export const passkeyOptionsSchema = z.object({ purpose: z.enum(["register", "verify"]) });
export const passkeyRegisterSchema = z.object({
  name: text(1, 40).default("Passkey"),
  att: b64u(8192).min(50),
  cdj: b64u(4096).min(20),
  prf: z.boolean().default(false),
});
export const passkeyVerifySchema = z.object({ wa: assertionSchema });
export const passkeyRemoveSchema = z.object({ id: b64u(1400).min(2) });
export const codeSchema = z.object({ code: z.string().trim().min(6).max(24) });
export const sessionRevokeSchema = z.object({ id: z.string().regex(/^[0-9a-f]{16}$/) });
export const changePasswordSchema = z.object({ password: z.string().min(1).max(200) });

// --- linked computers (device flow) ------------------------------------------------------------

export const deviceStartSchema = z.object({
  name: text(1, 60),
  platform: z.string().regex(/^[a-z0-9_-]{1,20}$/),
});
export const deviceTokenSchema = z.object({ device_code: z.string().max(100) });
export const deviceLookupSchema = z.object({ userCode: z.string().max(20), form: z.string().max(64) });
export const deviceConfirmSchema = z.object({ userCode: z.string().max(20), approve: z.boolean(), form: z.string().max(64) });
export const revokeDeviceSchema = z.object({ deviceId: z.string().regex(/^dev_[A-Za-z0-9_-]{8,40}$/) });
export const roomSchema = z.object({ room: z.string().regex(/^[A-Za-z0-9_-]{22}$/) });
export const roomRegisterSchema = z.object({
  room: z.string().regex(/^[A-Za-z0-9_-]{22}$/),
  challenge: z.string().min(10).max(512),
  proof: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
});

// --- protocol v6: phones in the account (phones.ts) ------------------------------------------------

const b64 = (min: number, max: number) => z.string().regex(/^[A-Za-z0-9_-]+$/).min(min).max(max);
export const phoneRegisterSchema = z.object({
  id: z.string().regex(/^[A-Za-z0-9_-]{22}$/),
  name: text(1, 40),
  pub: z.string().regex(/^[A-Za-z0-9_-]{87}$/),
  att: b64(16, 5500).optional(),
  cdj: b64(16, 2800).optional(),
});
export const phoneRevokeSchema = z.object({ id: z.string().regex(/^[A-Za-z0-9_-]{22}$/) });
// A computer's identity key (ECDSA P-256, raw uncompressed: 87 base64url characters, 0x04 first).
const cpubSchema = b64(87, 87).regex(/^B/);
export const phoneRequestSchema = z.object({
  state: z.enum(["pending", "denied", "expired"]),
  expiresAt: z.string().max(40).nullable().optional(),
  commit: b64(43, 43).optional(),
  cpub: cpubSchema.optional(),
  nonce: b64(43, 43).nullable().optional(),
});
export const grantSchema = z.object({
  room: z.string().regex(/^[A-Za-z0-9_-]{22}$/),
  epoch: z.number().int().min(0).max(1_000_000),
  epk: b64(87, 87),
  iv: b64(16, 16),
  ct: b64(32, 1400),
  cpub: cpubSchema,
  sig: b64(86, 86),
});
export const phoneSasSchema = z
  .object({
    device: z.string().min(1).max(64).regex(/^[A-Za-z0-9_-]+$/),
    commit: b64(43, 43),
    pnonce: b64(43, 43),
  })
  .strict();

// --- the server's identity ---------------------------------------------------------------------

export const identityChallengeSchema = z.object({ nonce: z.string().regex(/^[A-Za-z0-9_-]{22,64}$/) });
