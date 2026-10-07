# Threat model of a self-hosted Miblo relay

This is a review of this repository's own design: what changes when the relay, the account and the
phone app run on a server of your own instead of miblo.ai, and what does not. The protocol's own
threat model (v6) is at the end of [protocol.md](protocol.md); everything there still holds.

## The short version

- **A malicious operator is exactly as powerful as a malicious miblo.ai, which the protocol already
  tolerates.** The relay only ever sees ciphertext, the keys are made on your computer and reach a
  phone only sealed to that phone's own key, after you typed the 6-digit code the phone shows on
  your computer, and the phone only accepts grants signed by a computer it confirmed. Nothing in a
  self-hosted server is trusted more than miblo.ai is.
- **Self-hosting removes the one thing the protocol cannot protect against: the phone app's code.**
  On miblo.ai, whoever controls what miblo.ai serves runs code with the phone's keys (the protocol's
  "Residual: the phone app's code is served by miblo.ai and trusted"). On your own server, the code
  is what you built from this source (or a release whose hashes you checked), served by you.
- **What you take on:** keeping the server patched, its TLS certificate valid, its secrets and its
  database backed up, and the setup token to yourself.

## Assets

| Asset | Where it lives | Who can read it |
| --- | --- | --- |
| Session contents (status, history, replies, approvals, tasks) | encrypted on your computer; plaintext only there and on your confirmed phones | nobody else; the server relays ciphertext |
| Room keys, read tokens, phone MAC keys | your computer; each phone's grant, sealed to its ECDH key | the computer and that phone |
| The account's password | PBKDF2-SHA-256 hash in the database | nobody (offline guessing needs the database) |
| Second factors | passkeys: public keys; TOTP: AES-GCM under `MFA_KEY`; recovery codes: HMACs under a key derived from `MFA_KEY` | the server (the TOTP secret, with `MFA_KEY`) |
| Session cookies, device tokens | SHA-256 in the database | nobody |
| The server's identity key | `SERVER_IDENTITY_KEY` (Node: `secrets.json`, 0600; Cloudflare: a Worker secret) | the server |
| Metadata | who is connected when, frame sizes and times, push subscriptions, phone names and browser/system | the server, like any relay |

## Adversaries

### 1. A malicious or compromised operator (or hosting)

Same as a malicious miblo.ai, against the same defenses:

- It cannot read anything: frames are AES-256-GCM under keys it never sees.
- It cannot let a phone of its own in: a new phone gets nothing from a computer until the person
  types, on that computer, the 6-digit code the phone shows (bound to the phone's key and the
  computer's identity key by a commitment the server cannot change after the fact). It can show a
  phone of its own in the account, but the code on that phone never matches.
- It cannot put a computer of its own in front of your phone: the phone accepts only grants signed
  by a computer it confirmed with the same code.
- It cannot act on your computer: approvals, replies and tasks need the phone's passkey for each
  action, checked by the computer; they are off until turned on at the desk with the gadget code.
- It can deny service, drop or delay frames, and see metadata (above).
- **It controls the phone app's code it serves.** A server you do not run yourself (a friend's) is
  trusted for that the same way miblo.ai is. Run your own, or check the build hashes.

### 2. A network attacker

- TLS everywhere (Caddy / Cloudflare); the plugin refuses anything but https. HSTS on every answer.
- **A different server under your server's name** (a hijacked DNS record, a certificate mis-issued
  for your domain, a reinstalled server you did not expect): the plugin pinned the server's Ed25519
  identity key when you ran `miblo server set` (you compared its fingerprint with the one your
  server printed). Before any account or relay call it asks the server to sign a fresh nonce bound
  to its origin; another key gets nothing (`miblo server` warns). The phone app itself has no such
  pin (it is a web page); its trust is TLS, like miblo.ai's.
- Redirects are never followed by the plugin (`redirect: "error"`), so a server cannot bounce its
  calls to another host (miblo.ai included).

### 3. Someone on the internet against your server

- **Setup:** the account is created only with `SETUP_TOKEN` (192 bits, shown in your server's log
  or set by you), and only while the account has no second factor. Password sign-in is refused
  until a second factor exists, so an abandoned setup is never a password-only account.
- **Guessing:** 10 sign-ins a minute per address, 5 setup tries, 30 second-factor tries; the
  account's password and its second factor each lock for 15 minutes after 5 wrong tries (counted
  atomically per account, whatever arrives in parallel). Unknown names cost the same time as wrong
  passwords. The lockout can be triggered by anyone (a nuisance, not a breach); a passkey sign-in is
  not subject to the password lock.
- **CSRF / cross-site:** JSON-only writes, `Sec-Fetch-Site` and `Origin` checks, a per-session CSRF
  token, `SameSite=Lax` HttpOnly cookies (`Secure` on https).
- **Device-code phishing (RFC 8628 §5.4):** the link page never takes a code from a link (only typed
  into its own form, with a per-session form token), the first session that looks a code up holds
  it, codes live 10 minutes and are used once, linking needs the second factor passed in the last 5
  minutes.
- **Relay abuse:** the relay's limits are miblo.ai's (frame sizes and rates, pending sockets, rooms
  per network, push budgets); upgrades and deletes are limited per address.
- **Client address spoofing (Node):** the server sets the client address itself from the socket;
  with `TRUSTED_PROXY=1` it takes only the last `X-Forwarded-For` entry (the one your proxy added).
  Only enable it when nothing but your proxy can reach the port (the compose file only `expose`s it).
- **XSS:** a strict CSP (`script-src 'self' 'wasm-unsafe-eval'`, no inline scripts at all, no
  inline handlers, `frame-ancestors 'none'`), `nosniff`, `Referrer-Policy: no-referrer`.

### 4. Something on your computer (an AI agent, a script, malware)

- `miblo server set` / `reset` / `confirm` are refused from an AI agent and need the code shown on
  your Miblo's screen (the physical-presence trust root of every widening change).
- `server.json` carries a MAC under the plugin's settings key; a file edited by anything else is not
  followed, and the plugin then sends nothing at all (it never falls back to miblo.ai either). Like
  `plus.json`, a process that can read the key file can still sign: the MAC keeps an edit alone from
  being enough.
- Switching servers unlinks the computer and turns the phone companion off at the old server first,
  so no room keys or tokens of the old server are reused with the new one.

### 5. Physical or backup theft of the server's data

- The database holds no plaintext secret but the TOTP secrets' ciphertext. With `secrets.json` too
  (`MFA_KEY`, `SESSION_SECRET`, the identity key) an attacker can forge sessions on that server,
  read the TOTP secret and impersonate the server's identity: keep `secrets.json` (or the Worker
  secrets) out of backups others can read, or back up the database alone.
- Session contents are never on the server, so a stolen disk reveals none of them.

## Residual risks (accepted)

- **Trust on first use:** the first `miblo server set` trusts the key the server presents; compare
  the fingerprint with your server's own log (`node dist/server.mjs fingerprint`), not with a web
  page.
- **The phone app's origin is the only anchor on the phone:** a CA mis-issuance for your domain
  could serve another phone app; the plugin's pin protects the computer's calls, not the phone's.
  The protocol's code exchange and signed grants still keep such an app from getting a computer's
  keys without the person typing a code at the computer.
- **One process, in-memory limits (Node); per-isolate limits (Cloudflare without a rate-limit
  binding).** Enough for one person; a flood can still cost you bandwidth.
- **Updates are yours:** a self-hosted server does not update itself. Watch the repository's
  releases (security fixes are marked).
- **The plugin still reads its signed release manifest from miblo.ai** (update checks), whatever
  server is set. Nothing of the phone companion or the account goes there.
