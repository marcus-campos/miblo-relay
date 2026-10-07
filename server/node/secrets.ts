// The Node runtime's secrets: taken from the environment when set, otherwise made once and kept
// in <data>/secrets.json (mode 0600). Nothing here is ever logged except the setup token, which
// is printed on the server's console while the account has no second factor yet.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { newIdentityKey } from "../core/identity";
import { generateVapidKeys } from "../core/relay/webpush";

export type Secrets = {
  SESSION_SECRET: string;
  MFA_KEY: string;
  SERVER_IDENTITY_KEY: string;
  RELAY_VAPID_PUBLIC_KEY: string;
  RELAY_VAPID_PRIVATE_KEY: string;
  SETUP_TOKEN: string;
};

const NAMES = ["SESSION_SECRET", "MFA_KEY", "SERVER_IDENTITY_KEY", "RELAY_VAPID_PUBLIC_KEY", "RELAY_VAPID_PRIVATE_KEY", "SETUP_TOKEN"] as const;

export function secretsPath(dataDir: string): string {
  return path.join(dataDir, "secrets.json");
}

function readFile(file: string): Partial<Secrets> {
  try {
    const v = JSON.parse(fs.readFileSync(file, "utf8")) as Record<string, unknown>;
    const out: Partial<Secrets> = {};
    for (const n of NAMES) if (typeof v[n] === "string" && v[n]) out[n] = v[n] as string;
    return out;
  } catch {
    return {};
  }
}

function writeFile(file: string, s: Partial<Secrets>): void {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(s, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(tmp, file);
}

/** The secrets: the environment's, else the file's, else new ones (written to the file). */
export async function loadSecrets(dataDir: string, env: NodeJS.ProcessEnv = process.env): Promise<Secrets> {
  const file = secretsPath(dataDir);
  const stored = readFile(file);
  let changed = false;
  const make = async (name: (typeof NAMES)[number]): Promise<string> => {
    changed = true;
    switch (name) {
      case "SESSION_SECRET":
        return crypto.randomBytes(48).toString("base64url");
      case "MFA_KEY":
        return crypto.randomBytes(32).toString("base64url");
      case "SERVER_IDENTITY_KEY":
        return newIdentityKey();
      case "SETUP_TOKEN":
        return crypto.randomBytes(24).toString("base64url");
      default:
        return "";
    }
  };
  if (!env.RELAY_VAPID_PUBLIC_KEY && !stored.RELAY_VAPID_PUBLIC_KEY) {
    const k = await generateVapidKeys();
    stored.RELAY_VAPID_PUBLIC_KEY = k.publicKey;
    stored.RELAY_VAPID_PRIVATE_KEY = k.privateKey;
    changed = true;
  }
  const out = {} as Secrets;
  for (const n of NAMES) {
    const fromEnv = env[n];
    if (fromEnv) out[n] = fromEnv;
    else {
      if (!stored[n]) stored[n] = await make(n);
      out[n] = stored[n]!;
    }
  }
  if (changed) writeFile(file, stored);
  return out;
}

/** A new setup token (after `reset-account`), kept in the file. */
export function newSetupToken(dataDir: string): string {
  const file = secretsPath(dataDir);
  const stored = readFile(file);
  stored.SETUP_TOKEN = crypto.randomBytes(24).toString("base64url");
  writeFile(file, stored);
  return stored.SETUP_TOKEN;
}
