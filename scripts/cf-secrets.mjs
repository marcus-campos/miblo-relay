// Makes this server's secrets and stores them in YOUR Cloudflare Worker (`wrangler secret bulk`,
// run from deploy/cloudflare): the session and second-factor keys, the server's identity key, the
// VAPID keys for push alerts and the one-time setup token. Prints the setup token and the identity
// fingerprint (keep them; the secrets themselves are not shown and never written to the repo).
// Run it once; running it again replaces every secret (signs everyone out, new identity: the
// plugin then asks you to accept the new fingerprint with `miblo server set`).
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const cfDir = path.join(here, "..", "deploy", "cloudflare");
if (!fs.existsSync(path.join(cfDir, "wrangler.jsonc"))) {
  console.error("deploy/cloudflare/wrangler.jsonc is missing: copy wrangler.jsonc.example and fill it in first.");
  process.exit(1);
}
const b64 = (n) => crypto.randomBytes(n).toString("base64url");

// Ed25519 identity (PKCS#8) and its fingerprint (SHA-256 of the raw key, first 20 bytes).
const id = crypto.generateKeyPairSync("ed25519");
const pkcs8 = id.privateKey.export({ format: "der", type: "pkcs8" }).toString("base64url");
const raw = Buffer.from(id.publicKey.export({ format: "jwk" }).x, "base64url");
const fp = crypto.createHash("sha256").update(raw).digest().subarray(0, 20).toString("hex").toUpperCase().match(/.{8}/g).join("-");

// VAPID (P-256): the public key raw uncompressed, the private key as its 32-byte d.
const ec = crypto.createECDH("prime256v1");
ec.generateKeys();
const setupToken = b64(24);
const secrets = {
  SESSION_SECRET: b64(48),
  MFA_KEY: b64(32),
  SERVER_IDENTITY_KEY: pkcs8,
  RELAY_VAPID_PUBLIC_KEY: ec.getPublicKey().toString("base64url"),
  RELAY_VAPID_PRIVATE_KEY: ec.getPrivateKey().toString("base64url"),
  SETUP_TOKEN: setupToken,
};
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "miblo-relay-secrets-"));
const file = path.join(dir, "secrets.json");
fs.writeFileSync(file, JSON.stringify(secrets), { mode: 0o600 });
try {
  const r = spawnSync("npx", ["wrangler", "secret", "bulk", file], { cwd: cfDir, stdio: "inherit" });
  if (r.status !== 0) process.exit(r.status ?? 1);
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
console.log(`\nSetup token (create your account at <your server>/conta): ${setupToken}`);
console.log(`Server identity fingerprint (miblo server set shows the same): ${fp}`);
