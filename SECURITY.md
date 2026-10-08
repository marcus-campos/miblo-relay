# Security

Please report vulnerabilities privately: GitHub, **Security › Report a vulnerability** on this
repository. Do not open a public issue. Include what is affected (server, phone app, deploy files),
how to reproduce it and the impact you see.

What the design defends against, and what it does not, is in [docs/threat-model.md](docs/threat-model.md).
Security fixes are marked in the release notes; a self-hosted server does not update itself.

## Known low-severity and accepted residual findings

From the security audit of 2026-10-08 (miblo-platform `docs/audits/2026-10-08-web.md`).

| Id | Where | What remains |
|---|---|---|
| RL1 | `server/core/account/account.ts` | Wrong passwords lock password sign-in per network (an IPv6 /64), and the route allows 80 a minute per /48: an attacker with many /48s still gets 5 tries per /64 per 15 minutes. Use a long password; the mandatory second factor, locked for the whole account after 5 wrong tries, is the boundary. |
| RL2 | `server/core/app.ts` passkey options, `server/core/phones.ts` long poll | As on miblo.ai: the passkey-options body is parsed before the other checks (CPU only, the Node runtime caps bodies at 256 KB), and a dropped long poll may run to its 20 s end. |
