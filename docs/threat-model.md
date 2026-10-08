# Threat model of a self-hosted Miblo relay

This is a review of this repository's own design: what changes when the relay, the account and the
phone app run on a server of your own instead of miblo.ai, and what does not. The protocol's own
threat model (v6, with the v7 rows and "v7: adversarial analysis") is at the end of [protocol.md](protocol.md); everything there still holds.

## The short version

- **A malicious operator is exactly as powerful as a malicious miblo.ai, which the protocol already
  tolerates.** The relay only ever sees ciphertext, the keys are made on your computer and reach a
  phone only sealed to that phone's own key, after you typed on the phone the 6-digit code your
  computer shows (protocol v7, Miblo 1.23: a password-authenticated key exchange the server only
  relays), and the phone only accepts grants signed by a computer it confirmed. Nothing in a
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
  types, on that phone, the 6-digit code the computer shows (v7). The code is the password of a
  CPace-style key exchange over X25519 bound to the phone's key and the computer's identity key:
  nothing the server relays reveals it, and it cannot answer for a key of its own except by
  guessing (one try per attempt, 1 in 10^6; 3 wrong answers deny the request). (Before 1.23, v6:
  the phone showed the code and the person typed it on the computer.)
- It cannot put a computer of its own in front of your phone: the phone accepts only grants signed
  by a computer it confirmed (v7: the grant carries the confirmation of its own code exchange).
- It cannot act on your computer: approvals, replies and tasks need the phone's passkey for each
  action, checked by the computer; they are off until the person turns them on and confirms on a
  phone the computer already has, typing the code the computer shows and passing the passkey's user
  verification over the hash of exactly what is shown (3 wrong codes cancel, 6 requests an hour;
  desktop browsers cannot confirm). Before 1.23 this was the gadget code.
- It can deny service, drop or delay frames, and see metadata (above).
- **It controls the phone app's code it serves.** A server you do not run yourself (a friend's) is
  trusted for that the same way miblo.ai is. Run your own, or check the build hashes.

### 2. A network attacker

- TLS everywhere (Caddy / Cloudflare); the plugin refuses anything but https. HSTS on every answer.
- **What the identity pin does, and what it does not.** The plugin pinned the server's Ed25519
  identity key when you ran `miblo server set` (you compared its fingerprint with the one your
  server printed) and asks the server to sign a fresh nonce bound to its origin before any account
  or relay call. That detects a *replaced* server: a reinstall you did not expect, or another
  machine answering for your name that does not have your server's key. It is **not bound to the
  TLS connection**: an attacker who holds a valid certificate for your domain (a hijacked DNS
  record plus a mis-issued or ACME-obtained certificate) and who can also reach your real server
  can relay the signature request to it and sit in the middle. Such an attacker is exactly a
  malicious operator (section 1): it sees ciphertext and metadata and can deny service, but the
  end-to-end protocol holds (no keys, no phone of its own let in, nothing done on your computer).
  Binding the pin to the TLS key (the server signing its certificate's SPKI and the plugin pinning
  it) needs the plugin's HTTP and WebSocket clients to expose the peer certificate; it is noted as
  future work. The phone app itself has no pin (it is a web page): its trust is TLS, like miblo.ai's.
- Redirects are never followed by the plugin (`redirect: "error"`), so a server cannot bounce its
  calls to another host (miblo.ai included).

### 3. Someone on the internet against your server

- **Setup:** the account is created only with `SETUP_TOKEN` (192 bits, shown in your server's log
  or set by you), and only while the account has no second factor. A token works for one setup
  (its hash is recorded when it is used), so a token read later from a log cannot redo an abandoned
  setup; a new one comes from the operator's shell. Password sign-in is refused until a second
  factor exists, so an abandoned setup is never a password-only account.
- **Guessing:** 10 sign-ins a minute per network (an IPv6 /64), 5 setup tries, 30 second-factor
  tries; 5 wrong passwords lock password sign-in for 15 minutes for the network they came from
  (so a stranger cannot keep the owner out), and 5 wrong second factors lock the account's second
  factor for 15 minutes (counted atomically per account, whatever arrives in parallel). A wrong
  name, a wrong password and a locked network get the same 401 after the same work. Passwords are
  PBKDF2-SHA-256 with 600,000 iterations on Node and 100,000 on Cloudflare (a Worker's ceiling);
  older hashes are redone at sign-in. The in-memory rate limiter fails closed: when a table is
  full of live counts, a new key is refused rather than an old count dropped. Accounts and linked
  computers, anonymous networks and their wide networks (IPv6 /48, IPv4 /24, counted first with 8
  times the allowance) have separate tables, so a flood from one /48 using a new /64 for every
  request neither locks the owner out nor stops the linked computer (audit 2026-10-08 R1).
- **Second factors:** removing one is a single statement that also checks another factor stays, so
  parallel removals can never leave the account without a second factor.
- **CSRF / cross-site:** JSON-only writes, `Sec-Fetch-Site` and `Origin` checks, a per-session CSRF
  token, `SameSite=Lax` HttpOnly cookies (`__Host-` prefixed and `Secure` on https: no other host
  or subdomain can set or shadow them).
- **Device-code phishing (RFC 8628 §5.4):** the link page never takes a code from a link (only typed
  into its own form, with a per-session form token), the first session that looks a code up holds
  it, codes live 10 minutes and are used once, linking needs the second factor passed in the last 5
  minutes.
- **Relay abuse:** your server is no open relay: a writer is accepted only in a room one of your
  linked computers registered (a stranger's writer gets 403). On top, the relay's limits are
  miblo.ai's (frame sizes and rates, pending sockets, rooms per network, push budgets); upgrades and
  deletes are limited per address.
- **Client address spoofing (Node):** the server sets the client address itself from the socket;
  only for a connection from an address in `TRUSTED_PROXY` (your proxy's addresses or CIDRs) does
  it take the last `X-Forwarded-For` entry (the one your proxy added). The compose file only
  `expose`s the port and trusts its own network's range; the `docker run` example publishes on
  127.0.0.1.
- **XSS:** a strict CSP (`script-src 'self' 'wasm-unsafe-eval'`, no inline scripts at all, no
  inline handlers, `style-src 'self'` with no inline styles, `frame-ancestors 'none'`), `nosniff`, `Referrer-Policy: no-referrer`.

### 4. Something on your computer (an AI agent, a script, malware)

- `miblo server set` / `reset` / `confirm` are refused from an AI agent and need the code shown on
  your Miblo's screen.
- Miblo+ widening changes (approvals, replies, history, tasks, folders, a longer timeout) and a
  second phone are confirmed on a phone you already have, with the code this computer shows and
  that phone's passkey (v7): an agent can start a request and read the code, but cannot type it on
  your phone or pass its user verification.
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
  keys without the person typing on the phone the code the computer shows; such an app could
  describe a confirmation request as something else, but the computer applies only the request it
  made itself.
- **One process, in-memory limits (Node); per-isolate limits (Cloudflare without a rate-limit
  binding).** Enough for one person; a flood can still cost you bandwidth.
- **No security e-mails:** a self-hosted server sends none: the notices the miblo.ai account e-mails (recovery code used or tried, new passkey, new phone) are only written to the server log as `{"event":"account_security"}` lines; watch the account page and that log.
- **Updates are yours:** a self-hosted server does not update itself. Watch the repository's
  releases (security fixes are marked).
- **The plugin still reads its signed release manifest from miblo.ai** (update checks), whatever
  server is set. Nothing of the phone companion or the account goes there.
