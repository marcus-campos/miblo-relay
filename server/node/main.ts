// `node dist/server.mjs [serve|setup-token|reset-account|fingerprint|check]`: the self-hosted
// Miblo relay on Node. Configuration comes from the environment (README, "Configuration"); the
// secrets you do not set are made once and kept in $MIBLO_RELAY_DATA/secrets.json (0600).
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { fatalProblems, configProblems } from "../core/config";
import { scopeOf } from "../core/env";
import { setupNeeded } from "../core/account/account";
import { identityDocument } from "../core/identity";
import { createRelayServer } from "./server";
import { loadSecrets, newSetupToken } from "./secrets";
import { SqliteDb } from "./sqlite-db";

const here = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.resolve(process.env.MIBLO_RELAY_DATA ?? "./data");
const dbFile = path.join(dataDir, "relay.sqlite");
// The bundle sits in dist/ next to dist/public; migrations/ is beside dist/ (and copied into the image).
const publicDir = [process.env.MIBLO_RELAY_PUBLIC, path.join(here, "public")].find((d) => d && fs.existsSync(d)) ?? null;
const migrationsDir = [process.env.MIBLO_RELAY_MIGRATIONS, path.join(here, "..", "migrations"), path.join(here, "migrations")].find((d) => d && fs.existsSync(d))!;

async function config() {
  const secrets = await loadSecrets(dataDir);
  return {
    ...secrets,
    PUBLIC_ORIGIN: process.env.PUBLIC_ORIGIN ?? "",
    RELAY_VAPID_SUBJECT: process.env.RELAY_VAPID_SUBJECT,
    RELAY_IP_KEY: process.env.RELAY_IP_KEY,
    TRUSTED_PROXY: process.env.TRUSTED_PROXY,
    MIBLO_RELAY_DEV: process.env.MIBLO_RELAY_DEV,
  };
}

async function main(): Promise<number> {
  const cmd = process.argv[2] ?? "serve";
  const env = await config();
  if (cmd === "check") {
    const problems = configProblems(env);
    console.log(problems.length ? problems.map((p) => `- ${p}`).join("\n") : "Configuration OK.");
    return fatalProblems(env).length ? 1 : 0;
  }
  if (cmd === "fingerprint") {
    const doc = await identityDocument(env.SERVER_IDENTITY_KEY, env.PUBLIC_ORIGIN);
    console.log(`Server identity fingerprint: ${doc.fingerprint}`);
    return 0;
  }
  if (cmd === "setup-token") {
    console.log(env.SETUP_TOKEN);
    return 0;
  }
  if (cmd === "reset-account") {
    // Shell access is the operator's own trust root: the account's second factors and sign-ins go,
    // and a new setup token sets a new password and factor. Linked computers and phones stay.
    const db = new SqliteDb(dbFile);
    db.migrate(migrationsDir);
    db.sqlite.exec("DELETE FROM sessions; DELETE FROM mfa_passkeys; DELETE FROM mfa_totp; DELETE FROM mfa_recovery_codes; DELETE FROM mfa_failures; DELETE FROM mfa_challenges;");
    db.sqlite.close();
    const token = newSetupToken(dataDir);
    console.log(`Account reset. Open ${env.PUBLIC_ORIGIN}/conta and use this setup token:\n\n    ${token}\n`);
    return 0;
  }
  if (cmd !== "serve") {
    console.error("Usage: server.mjs [serve|check|fingerprint|setup-token|reset-account]");
    return 2;
  }
  const fatal = fatalProblems(env);
  if (fatal.length) {
    console.error(`miblo-relay: cannot start:\n${fatal.map((p) => `- ${p}`).join("\n")}`);
    return 1;
  }
  for (const p of configProblems(env).filter((x) => !fatal.includes(x))) console.warn(`miblo-relay: ${p}`);
  const app = await createRelayServer({ env, dbFile, migrationsDir, publicDir, accessLog: process.env.MIBLO_RELAY_ACCESS_LOG === "1" });
  const port = Number(process.env.PORT ?? 8787);
  const host = process.env.HOST ?? "0.0.0.0";
  await app.listen(port, host);
  const doc = await identityDocument(env.SERVER_IDENTITY_KEY, env.PUBLIC_ORIGIN);
  console.log(`miblo-relay ${doc.version} listening on ${host}:${port} as ${env.PUBLIC_ORIGIN}`);
  console.log(`Server identity fingerprint: ${doc.fingerprint}`);
  if (await setupNeeded(scopeOf(app.env))) {
    console.log(`\nFirst run: open ${env.PUBLIC_ORIGIN}/conta and create your account with this setup token:\n\n    ${env.SETUP_TOKEN}\n`);
  }
  if (!publicDir) console.warn("miblo-relay: no built phone app found (run `npm run build`); only the API is served.");
  const stop = () => {
    void app.close().then(() => process.exit(0));
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
  return -1;
}

main().then(
  (code) => {
    if (code >= 0) process.exit(code);
  },
  (e) => {
    console.error(`miblo-relay: ${(e as Error)?.message ?? e}`);
    process.exit(1);
  },
);
