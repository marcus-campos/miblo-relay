# Security

Please report vulnerabilities privately: GitHub, **Security › Report a vulnerability** on this
repository. Do not open a public issue. Include what is affected (server, phone app, deploy files),
how to reproduce it and the impact you see.

What the design defends against, and what it does not, is in [docs/threat-model.md](docs/threat-model.md).
Security fixes are marked in the release notes; a self-hosted server does not update itself.

## Low findings fixed on 2026-10-08

From the security audit of 2026-10-08 (miblo-platform `docs/audits/2026-10-08-web.md`), with
regression tests in `test/audit-2026-10-08.test.ts`.

| Id | Where | Fix |
|---|---|---|
| RL2 | `server/core/app.ts` passkey options, `server/core/route.ts` `mfaRequest` | The body is read once, after the rate limit, the session and the origin and size checks; the step is picked from it afterwards. |
| RL2 | `server/node/server.ts`, `deploy/cloudflare/wrangler.jsonc.example` | `request.signal` fires when the client goes away (Node: the connection closing; Workers: the `enable_request_signal` flag), so a dropped grants long poll stops within one look. Existing Cloudflare deployments: add `"compatibility_flags": ["enable_request_signal"]` to your `wrangler.jsonc`. |

## Known low-severity and accepted residual findings

| Id | Where | What remains |
|---|---|---|
| RL1 | `server/core/account/account.ts` | Wrong passwords lock password sign-in per network (an IPv6 /64), and the route allows 80 a minute per /48: an attacker with many /48s still gets 5 tries per /64 per 15 minutes. Use a long password; the mandatory second factor, locked for the whole account after 5 wrong tries, is the boundary. A lock for the whole account would let anyone lock the owner out of password sign-in, so it stays per network. |
