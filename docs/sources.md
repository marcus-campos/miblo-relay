# Where the code comes from

This server shares its protocol code with miblo.ai's: the same files, so a self-hosted server and
miblo.ai behave the same for the plugin and the phone app.

| Here | Same as miblo.ai's | Changed for self-hosting |
| --- | --- | --- |
| `server/core/relay/*` | the relay room, its router, the protocol checks, Web Push | the room's runtime is injected (`RoomRuntime`: Cloudflare's WebSocketPair or Node's sockets); the push subject defaults to the server's origin; the relay's rate limit is in memory |
| `server/core/phones.ts` | the phone registry (protocol v6) | import paths |
| `server/core/devices.ts` | the device flow, room registration | no plans or entitlements: every linked computer's rooms get `plus` with no end; the link page is on `PUBLIC_ORIGIN` |
| `server/core/account/mfa.ts`, `webauthn.ts`, `sessions.ts` | second factor, passkeys, sessions, CSRF | one account with a password instead of email sign-in; the relying party is `PUBLIC_ORIGIN`; security notices are log lines instead of emails; no pairing vault |
| `app/src/components/phone/*`, `app/src/lib/*`, `app/src/components/community/security.tsx`, `app/src/components/ui/*` | the phone app and the account's Security section | `security.tsx` hides the pairing vault (none here); `content/security.ts` speaks of a password instead of an email |
| `app/public/sw.js`, `app/public/app/*` | the service worker, manifest and icons | the service worker caches this build's paths (`/assets/`, `/theme.js`) |

New here: `server/core/app.ts` (the routes), `server/core/site.ts` (pages, CSP), `server/core/account/account.ts` and `password.ts` (the single account), `server/core/identity.ts` (the identity key), `server/node/*` (the Node runtime), `server/worker/*` (the Worker), `app/src/selfhost/*` (the account page), `app/shims/*` (the few Next.js imports of the shared code, for the Vite build).
