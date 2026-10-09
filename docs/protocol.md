<!--
This is the phone relay protocol as the Miblo plugin, the phone app and miblo.ai speak it. A
self-hosted Miblo relay (this repository) speaks exactly the same protocol: wherever this document
says "miblo.ai" (the relay, the account, the phone app's origin, the passkeys' relying party),
read "your server". What differs on a self-hosted server is in "Self-hosted servers" at the end and
in docs/threat-model.md.
-->

# Miblo phone relay protocol (v7)

Miblo is local-first. The phone companion is OPT-IN and END-TO-END ENCRYPTED: the relay on
miblo.ai only forwards opaque ciphertext and never sees keys or plaintext.

1.24 (see "1.24: replies in every AI tool" below): replies from the phone reach every integrated AI
tool, at the end of its turn or while idle where the tool allows it; each tool's capabilities are
published (`capabilities`), the history frame says how a reply would go in (`replyHow`), a reply
can be `queued`, remote Claude Code tasks take replies, and the desktop app types replies into
idle Terminal or iTerm2 sessions of tools that have no other way. No frame or crypto change.

v7 (Miblo 1.23, see "v7" below): the computer shows a 6-digit code and the phone types it, both
to let a new phone in (a password-authenticated key exchange over the code) and to confirm on a
phone the person already has any change that widens what phones can do (approvals, replies,
history, tasks, folders, a longer timeout or task limit), with that phone's passkey. It replaces
the 4-digit gadget code (`miblo plus confirm <code>`) and typing the phone's code on the computer
(`miblo phone approve --code`); the v6 sections below describing those are history where they
say so.

v6 (see "v6" below): phones join through the person's miblo.ai account instead of a QR code or
link (the computer and the phone are both signed in to the same account; the computer seals the
room's keys to each phone's own public key, so the server never sees them); the conversation view
gets a richer, bounded, redacted history (Markdown text, tool cards with diff counts, short
outputs); and Miblo+ adds "Nova tarefa": a new headless run of an AI tool on the computer, started
from the phone (off by default, the gadget code to turn it on, a passkey per task, a folder
allow-list enforced on the computer). QR/link pairing, `miblo phone link|enroll`, the pairing
window and the passkey fingerprint are gone; the gadget code now only turns on what acts on the
computer.

v5 (security hardening of v4, never released before it): every reply needs the phone's passkey
like every allow; the new phone's MAC key travels sealed under a key only the QR code carries;
every Miblo+ frame is sealed per enrolled phone; the relay knows each enrolled phone by its own
token, drops a revoked one and lets one phone push out only its own sockets; revoking a phone
replaces the pairing's read token and status key (the other enrolled phones get the new ones sealed
to them); push budgets are split between free and Miblo+ rooms and charged only for deliveries
that went out; the bridge's local answers are authenticated. See "v5" below and the threat model.

v4 (Miblo+, see "v4: Miblo+" below) adds history, replies and approvals on top of v2 without
changing anything a free room sees except the one-phone limit. v4 replaces v3 (never released):
each phone has its own identity (a passkey and a MAC key) enrolled with the computer at pairing,
every allow needs that passkey with user verification, history is asked for one session at a
time, and the settings that widen what a phone can do are changed only by the person at the
computer. v2 replaces v1 entirely (no v1 room or pairing is accepted; there were no field users). What
changed: the writer is verified by deriving the room from its token instead of trust on first use,
readers are checked against a hash the writer registers, the AAD binds type and channel, frames
are persisted sparingly, push has daily caps, and the phone drops replayed frames.

## Pairing secrets (created by the plugin on the user's computer)
(v6: the secrets below are unchanged, but they reach phones only inside account grants, "v6:
phones through the account"; the QR code, the link and the pairing window described in this
section and in "Phones (per-phone identity)" are history: v6 plugins and apps neither make nor
accept them.)
- `writeToken`: 256-bit random, base64url (43 chars). Only the computer knows it.
- `room`: `base64url(SHA-256("miblo-room-v2|" + writeToken))[:22]` (SHA-256 over the UTF-8 bytes of
  the string; the first 22 characters of the unpadded base64url digest). The relay recomputes it to
  verify the writer, so nobody can claim a room before its computer does.
- `readToken`: 256-bit random, base64url, given to phones (one token shared by all paired phones).
  The writer registers `readHash = base64url(SHA-256(readToken))` (43 chars) with the relay; the
  relay never sees the read token before a phone presents it. v5: enrolled phones authenticate with
  their own reader tokens instead (below); the shared one makes a guest (status, enrollment).
- `key`: 256-bit AES-GCM key, base64url. NEVER sent to the server. v5: it encrypts the status
  only; Miblo+ frames are sealed per phone.
- `epoch` (v5): how many times `readToken` and `key` were replaced (`miblo phone revoke` replaces
  both; the room and the write token stay).
- QR / link: `https://miblo.ai/app#p=<base64url(JSON {v:2, room, readToken, key, name, en?})>` —
  the fragment is never sent to the server. `/app` answers 308 to `/app/` (the fragment survives).
  `en` (v4): the secret of the computer's open pairing window (below), present only while one is
  open.
- Pairing is done only by the person at the computer: `miblo phone on|link` from a terminal or
  the Miblo desktop app, never under an AI agent (environment markers such as `CLAUDECODE`, or an
  agent process among its ancestors). A phone paired that way sees the status only; letting it
  approve and reply (its enrollment window) needed the 4-digit code a paired Miblo shows on its
  screen (history: v7 confirms on the phone, "v7: confirmations on the phone"). The `/miblo:phone` slash command is user-only and hands the command to the user instead
  of running it. Details in "Physical presence (the local gate)" below.
- The QR code (`phone-qr.svg`, 0600) is deleted as soon as one more phone connects and at the
  latest 10 minutes after it was made; each `on|link` opens a pairing window of 10 minutes for one
  phone (`phone-enroll.json`, 0600). In a terminal the QR code is drawn on screen and the link
  itself is printed only with `--show`; the desktop app gets the link to draw its own QR code.
- The plugin reads `phone.json`, `phones.json`, `phone-enroll.json` and the Miblo+ files only when
  they are plain files owned by the user, and narrows them back to 0600.

## Transport
- WebSocket `wss://miblo.ai/api/relay/<room>?role=writer|reader`.
- Writer auth (the plugin): headers `Authorization: Bearer <writeToken>` and
  `X-Read-Hash: <readHash>` on the upgrade, verified BEFORE the upgrade: HTTP 401 when the token
  does not derive the room or the hash is missing/malformed. A browser writer may instead send the
  first message `{"t":"auth","token":"<writeToken>","readHash":"<readHash>"}`.
- A writer naming a different `readHash` than the registered one replaces it, and every connected
  reader is closed with 4401 (re-pairing normally makes a new room anyway).
- Reader auth: first message `{"t":"auth","token":"<readToken>"}` (or `Authorization: Bearer` on
  the upgrade). REFUSED until the writer registered a read hash: close 4403 (HTTP 403 with the
  header); the phone retries with backoff. Then SHA-256(token) must match it (constant time), else
  4401.
- v5, enrolled phones: `{"t":"auth","token":"<readerToken>","phone":"<phone id>"}`, checked against
  the hash the writer registered for that phone. The writer registers its enrolled phones in the
  `X-Phones` header (`<id>.<hash>,<id>.<hash>`, at most 8) and again with
  `{"t":"phones","list":[{"id","h"}]}` whenever they change; a phone no longer listed, or whose
  token hash changed, is closed with 4411 and refused (4401) from then on. A new `readHash` closes only the guests (sockets that used
  the shared token), never the enrolled phones.
- Unauthenticated sockets are closed 5 s after opening (4401), and an auth message arriving later is
  refused. Pending (unauthenticated) sockets are capped per role: 2 writers, 10 readers (HTTP 429
  beyond). Header-authenticated connections are verified first and never count, so a flood of
  pending readers cannot keep the computer out.
- One Durable Object per room (WebSocket Hibernation API). Max 1 writer; readers: 1 at a time on
  the free plan (a second is refused with 4406), enrolled identities included (a lapsed Miblo+
  room keeps one phone, which may hold its own two sockets). On Miblo+ (v5): at most 5 distinct
  enrolled phones (a sixth is refused, 4406), each up to 2 sockets (its own oldest goes, 4409: one
  phone can never push another off), and at most 2 guests (the oldest guest goes).
- Frames are JSON text: `{"t":"msg","ch":"status","iv":"<b64url 12B>","ct":"<b64url ciphertext+tag>"}`.
  Plaintext (inside ct) = UTF-8 JSON `{v:1, kind:"snapshot", at:<ms>, host, sessions:[…], more,
  alerts:[…], limits:{…}, today:{…}}` — the same fields the gadget snapshot carries, never more.
  Plugin 1.20+ adds `miblos:[{name, label, online, look?, myPet?, pet?, screen?}]` (at most 6):
  the person's own paired Miblos, `label` its Miblo-XXXX network name, `look` its MIBLO1 share
  code (drawn with the firmware's renderer), `myPet` when it runs a Miblo Studio pet (from 1.21 its
  `look` still carries the preset, eyes, items and colours, with pet 0 in the pet's place), `pet`
  (1.21) the SHA-256 (base64url) of that pet's file, which travels apart (see "v6: My pet on the
  phone"), `screen` one of alert / work / idle / pet / sleep. Never a gadget's token or address.
- AAD = UTF-8 `v2|<t>|<ch>|<room>`, where `t` is the frame type (`msg` for writer frames, `up` for
  reader frames) and `ch` the channel (`status` when the frame has none). A frame moved to another
  room, type or channel fails to decrypt.
- Writer may send `{"t":"push","n":<needsYouCount>}` (no content): the relay sends a GENERIC
  Web Push ("A sessão precisa de você" / "A session needs you", localized by the phone's
  saved lang) to the room's subscriptions when n increases: at least 60 s apart, at most 30 per room
  per UTC day, and within daily budgets (counters kept in Durable Objects). v5: each delivery is
  charged to its payer, to its endpoint and to a pool. The payer is the Miblo+ account (an opaque
  HMAC of the user id the account side passes with the plan; 1 000 deliveries a day each, so a few
  accounts cannot spend everyone's) or, for a free room, the network that created it (600 a day);
  one push endpoint gets at most 40 a day however many rooms hold it; the free pool is 50 000 a day
  and the Miblo+ pool is only a runaway guard. Only deliveries the push service accepted count (the
  rest are given back); only a room a phone has joined pushes, and only to subscriptions a phone
  re-sent in the last 30 days (older ones are dropped). A network (a keyed HMAC of its IP, an IPv6
  address by its /64, never the IP; the key changes every 30 days) may create at most 10 new rooms
  a day (HTTP 429 / close 4429 beyond). Over its key's 30-day period only rooms a phone really joined
count: 30 for an IPv6 /64 (60 a /56, 120 a /48) and 300 for an IPv4 address, which a carrier
(CGNAT) or an office shares; a room never joined costs a day's slot only, given back when it goes. A pool past 80 % and an empty pool
  each log one warning a day (`relay_push_budget`, no room or IP) for alerting.
- Reader may send `{"t":"sub","sub":<PushSubscription JSON>,"lang":"pt-BR|en"}` to register Web
  Push (VAPID; public key served at /api/relay/vapid). Subscriptions are stored per room only. v5:
  the key must be a real P-256 point, and a room keeps its newest 2 (free) or 5 (Miblo+). An
  enrolled phone's subscription is stored with its phone id: it is deleted when the writer stops
  listing that phone (revoked), and `{"t":"unsub","sub":{"endpoint"}}` (push turned off in the
  app's settings) deletes that endpoint's subscription and every one that phone made in the room.
  The computer never sees an endpoint.
- Push kinds: besides the count, the writer may send `{"t":"push","k":"approval"|"task_done"|"task_failed"}`
  (a permission request went to the phones; a phone task ended or failed). The kind is all the
  relay learns, and the notification carries only fixed words for it: "Pedido de permissão" /
  "Permission request", "Tarefa concluída" / "Task finished", "A tarefa falhou" / "Task failed",
  "A sessão precisa de você" / "A session needs you" for the count. Any other kind is ignored. One
  a minute per kind, within the room's 30 a day and the same budgets; an approval also counts as
  that moment's "needs you" (no second alert right after it).
- `{"t":"fg","on":true|false}` (a phone): its app is on the screen, or not. Kept on the socket only
  (never stored). Sent when the connection opens, when the page is shown or hidden, and every
  other ping while it stays on screen; it lapses after 150 s. A phone whose app is on screen gets
  no push (it sees the card); when every phone is, nothing is sent and nothing is spent.
- `DELETE /api/relay/<room>` with `Authorization: Bearer <writeToken>` wipes the room (frame, read
  hash, push subscriptions, counters): 204 when the token derives the room (also when nothing was
  stored), 401 otherwise, whether or not the room exists.
- Limits: writer frames ≤ 64 KB, reader frames ≤ 16 KB; writer ≤ 2 frames/s (relay drops extra).

## Retention
- The last `status` frame is kept in memory and shown to readers on connect for 10 minutes. It is
  written to storage only once a reader has ever authenticated in the room, and then at most once a
  minute (a pending newer frame is flushed by the room's alarm).
- A room no reader ever joined is deleted 24 h after its writer first registered it.
- Otherwise a room is deleted after 30 days without WRITER activity (readers never extend it).
- A deleted room is registered again the next time its writer connects.

## Phone (PWA)
- Frames whose `at` is not newer than the last one accepted for that room, or more than 60 s ahead
  of the phone's clock, are dropped (the last accepted time is kept across reloads; right after a
  reload the same frame may be shown again, never an older one).
- Data older than 6 minutes (the plugin re-sends an unchanged snapshot every 4) is dimmed and
  labelled with its age, whatever the connection state.
- Served at `/app/` and `/en/app/`; the service worker's scope is `/app/` (`/en/app/`), with the
  slash. Documents get a per-response nonce CSP: `script-src 'self' 'nonce-…'` plus the Turnstile
  host, never `'unsafe-inline'`, and `script-src-attr 'none'`.

### App lock (PIN)
Every phone that uses the app has a PIN (`app/src/components/phone/AppLock.tsx`, `pin-lock.ts`,
`idle-lock.ts`, `lock-state.ts`).
- **When it is asked.** Created right after the account sign-in, before anything else shows (also
  on a phone that already had pairings from before the lock existed); asked on every open of the
  app and after the idle time the person chose in Ajustes: 1, 5 (default), 15 or 60 minutes with
  no touch, tap or key while the app is on screen (time in the background counts), or "Sempre que
  sair do app" (`visibilitychange` to hidden, `pagehide`). Ajustes changes it (the current PIN
  first, counted like any attempt) and locks now; it cannot be removed.
- **Rules.** 6 to 12 digits, digits only; refused when trivial: one digit repeated, a short
  pattern repeated (121212, 123123, 12341234), a run up or down (123456, 654321, 890123), and a few
  common picks (112233, 123321, ...).
- **Storage.** The PIN never leaves the phone and is never written anywhere. The app keeps
  PBKDF2-SHA-256 of it (a random 16-byte salt per device, at least 600 000 iterations, more on a
  device that runs that in under ~300 ms; the count is stored with the hash) in the app's
  IndexedDB `miblo-phone` (store `lock`, version 3), next to the pairings, with the wrong-PIN count,
  the wait's end and the idle choice. Compared in constant time. The fields are
  `type=password`, `inputmode=numeric`, `autocomplete=off`. Signing out of the account (which wipes
  the app's storage) or another account signing in deletes it: the next sign-in creates a new PIN.
- **Wrong PINs.** Each attempt is counted in storage before the check finishes (closing the tab or
  reloading mid-check does not undo it). 5 wrong in a row: no attempt for 1 minute (countdown on
  the screen). 10 wrong in a row (the minute does not reset the count; a reload does not either):
  the app is **blocked on this phone**: the PIN hash is deleted (nothing on the phone opens with
  the PIN any more), the app posts the existing sign-out route
  `POST /api/community/auth/logout` with `{"reason":"pin_lockout"}` (retried every 30 s and when
  the phone is back online until the server answers), which ends this browser's account session
  on the server and records the `pin_lockout` security event (miblo.ai e-mails it, at most one an
  hour per account; a self-hosted relay writes it to its log as an `account_security` line). The screen says "Este celular foi bloqueado por PIN errado.
  Entre de novo na sua conta (digital/rosto ou app autenticador) para desbloquear". Unblocking is
  a normal account sign-in with the account's second factor, seen by the app only after the
  sign-out succeeded (a session from before cannot count), then a new PIN before the app opens. A
  right PIN sets the count back to zero.
- **What locked means.** While locked (or blocked, or before the PIN exists) the app renders only
  the lock screen: nothing read from the phone's storage or received from a computer (sessions,
  approvals, replies, confirmations, codes, computer names) is on screen. The functions that act
  refuse too, whatever the screen shows: `RelayClient.sendUp` (approvals, confirmations, replies,
  tasks, stop, history requests) and `answerCode`, `confirmComputer`, `rejectComputer`, `askAgain`,
  `sendSasAnswers` (answered again on the next poll) and pairing again. The tab title and the app
  icon carry no count while locked. The
  relay connections stay open meanwhile, so an approval that arrives while locked is there after
  the PIN (kept in memory only, as before).
- **What it is not.** A gate on the app and the session, not encryption: the pairing keys stay
  non-extractable CryptoKeys exactly as before, not wrapped by the PIN. Someone who can read the
  browser's storage (a forensic copy of the phone, malware, devtools on an unlocked device) can
  try all 10^6 six-digit PINs against the stored hash offline in hours or less, or simply ignore
  the lock and use the keys. The PIN stops a person holding the unlocked phone from using the app
  and its session; the device's own screen lock and encryption stay the protection against a
  forensic attacker. The 1-minute wait follows the phone's clock (changing the clock shortens it;
  the 10-attempt limit does not depend on the clock). Web Push alerts keep arriving while locked
  (they are generic and never carry content).
- **Privacy.** Nothing of the PIN, its hash or the count is sent anywhere; the only network effect
  is the sign-out after 10 wrong PINs (and its `pin_lockout` notice).

## Privacy
- No IPs or contents stored by the relay (Cloudflare's Workers Logs, while on, record each request's
  URL, with the room id, and IP for a few days: docs/data-inventory.md, section 6). A free room is
  not linked to an account; a Miblo+ room is (D1 `plus_rooms`: the account side applies the plan),
  and v6 phones belong to an account. Contents stay end-to-end encrypted either way.
- Turning the feature off in the plugin deletes the room and forgets the secrets.

## Relay details (as implemented)
- A new writer replaces the current one (old socket closed 4409). A 6th reader makes the oldest
  reader close with 4409 (a phone that vanished never locks the others out).
- Close codes: 4400 malformed frame, 4401 bad/missing auth (or none within 5 s), 4402 plan (v1.1),
  4403 writer not registered yet (readers retry), 4404 room deleted, 4406 no more phones on this
  plan (free: 1 at a time; the phone retries in a minute), 4409 replaced, 4411 this phone was
  revoked (v5; the phone stops and says so), 4429 too many new rooms from this network (v5), 1009
  frame too large (also per channel, v3). HTTP 401/403 mirror 4401/4403 for header auth; HTTP 429
  = too many connections/requests.
- `{"t":"ping"}` is answered with `{"t":"pong"}` at any time (keep-alive; no auth needed).
- Push: payload = encrypted JSON `{"t":<kind>,"title":"Miblo","body":<the fixed words>,"lang":"pt-BR|en"}`
  with `kind` = `needs_you`, `approval`, `task_done` or `task_failed` (aes128gcm, TTL 1 h,
  `Topic: needs-you`, or `task` for a task's end). The service worker shows its own fixed words
  for the kind (whatever else the payload says), one notification for "needs you" and approvals
  (replaced, buzzing again only when none is showing) and one for tasks, and a tap opens the app's
  own page (`/app/?open=<kind>`, the "Agora" tab). Endpoints must belong to a browser push service.
- Shared test vector: claude_gadget `plugin/test/fixtures/relay-frame.json` = miblo-platform
  `web/tests/fixtures/relay-frame.json` (identical files; both test suites decrypt it).

## v1.1 (reserved for Miblo+; implemented by v3)
- Per-room `plan` flag kept by the relay, default `"free"` (Miblo+ = `"plus"`, set by the account
  side in a later version; there is no client API to change it).
- Frames may carry an optional plaintext envelope field `ch`: `"status"` (default when absent),
  `"history"`, `"chat"`, `"reply"`. The relay forwards `ch` as is. Only `status` frames are kept as
  the last frame; other channels are forwarded and never stored.
- Reader → writer encrypted frames `{"t":"up","iv","ct"(,"ch")}` (AAD `v2|up|<ch>|<room>`):
  forwarded to the writer only, never stored; ≤ 1 per second per reader (extra dropped), ≤ 16 KB.
- On the free plan the relay closes the socket with 4402 "plan" on any `ch` other than `status`
  and on any `up` frame.

## v4: Miblo+

Miblo+ rooms (plan set by the account side, docs/miblo-plus.md; `POST /__plus` inside the
Durable Object, lapsing on its own at `until`) carry, besides the status:

| `ch` | direction | plaintext `kind` | what |
|---|---|---|---|
| `history` | writer → phones | `history` | one session's last messages (full replacement, newest wins) |
| `history` | phone → writer (`up`) | `open` | "send me this session's history" (when its conversation is opened, and every 2 minutes while it stays open) |
| `reply` | phone → writer (`up`) | `reply` | text typed on the phone for one session (beta), signed by the phone |
| `reply` | writer → phones | `reply_ack` | `sent` (handed to Claude Code), `delivered` (seen in the transcript) or `refused` |
| `approval` | writer → phones | `approval`, `approval_done`, `enrolled` | a permission prompt to answer; its outcome; the answer to an enrollment |
| `approval` | phone → writer (`up`) | `decision`, `enroll`, `approval_sync` | allow / deny, signed (an allow also with the passkey); this phone's enrollment; "send me the approvals still waiting" |
| `chat` | – | – | reserved |

All plaintexts are UTF-8 JSON (`v: 4` or `v: 5`). v5: none of these frames uses the shared pairing
key any more (it encrypts the status only); they are sealed per phone ("v5: sealed frames" below).

### Relay rules
- Free rooms: any `ch` but `status`, and any `up` frame, close the socket with 4402. One phone
  at a time (4406 for a second one).
- Miblo+ rooms: `ct` caps per channel (base64url characters; larger closes 1009):
  writer `history` 60 KiB, `chat` 16 KiB, `reply` 2 KiB, `approval` 48 KiB, `status` 64 KiB;
  phone `up` `history` 1 KiB, `reply` 8 KiB, `approval` 4 KiB (an `up` without one of those
  channels is dropped). `up` frames: at most 1 per second per phone, and per phone and minute
  12 `history`, 20 `reply`, 30 `approval`; extra ones are dropped.
- Nothing of `history`, `chat`, `reply` or `approval` is stored: forwarded to the sockets
  connected at that moment, dropped when there are none (only the last `status` frame is kept,
  as in v2).
- Presence: the relay sends the writer `{"t":"presence","readers":n,"phones":[ids]}` (plaintext
  metadata it already has; `phones`, v5: the enrolled phones among them) when it connects and
  whenever the connected phones change.
- v6 push: the relay sends the writer `{"t":"phones_changed"}` when the account side tells the room
  that the account's phones changed ("Push: phones changed" under v6).
- v5: a Miblo+ frame from the writer is forwarded only to the enrolled phones its `to` names, each
  with its own wrap (`{"t":"msg","ch","iv","ct","k"}`); a frame with `g: 1` (an answer to an
  enrollment) only to guests; any other Miblo+ frame is dropped. An `up` frame from an enrolled
  phone reaches the writer with `p`, the phone the relay authenticated; a guest may send `up` only
  on `approval` (an enrollment), at most 6 a minute.

### Phones (per-phone identity)
Every paired phone shares the pairing's read token and status key: they all read the same status.
Everything else is per phone (v5):
- At pairing the phone makes a random `phone` id (16 bytes, 22 base64url), a MAC key (32 random
  bytes) and a passkey (below), and sends `{v, kind:"enroll", phone, name, macKey, att, cdj, ts}`
  on `approval`, sealed under `enrollKey` = HKDF-SHA256(ikm = the window secret `en`, salt = the
  room, info `"miblo-enroll-key-v5"`), AAD `v5|enroll|<room>`. `en` travels in the QR code alone,
  so no other holder of the pairing key (another phone, a revoked one, an old link), not even with
  the relay's help, can read the new phone's MAC key. The computer accepts it only while a pairing
  window is open, only with that window's secret (also part of the passkey's challenge), at most 5
  phones; the window then closes (one phone per QR code) and the QR file is deleted. It answers
  `{v, kind:"enrolled", phone, ok, fp | reason}` under the same key (AAD `v5|enrolled|<room>`,
  `g: 1`), after registering the new phone with the relay.
- From its MAC key each side derives the phone's `readerToken` = base64url(HMAC-SHA256(macKey,
  `"miblo-reader-v5|" + room + "|" + phone`)) (its token at the relay) and its `phoneKey` =
  HMAC-SHA256(macKey, `"miblo-phone-key-v5|" + room + "|" + phone`) (AES-256-GCM, its sealed frames).
- `fp`: the passkey's fingerprint, `XXXX-XXXX` = base32 (`ABCDEFGHJKLMNPQRSTUVWXYZ23456789`) of the
  first 40 bits of SHA-256(`"miblo-fp-v4|" + credId + "|" + x + "|" + y`). The phone computes it
  from its own attestation; `miblo phone list` shows the computer's copy for the user to compare.
- The status frame of a Miblo+ computer adds `plus: {on, approvals, history, replies, phones}`,
  `phones` being the enrolled ids: a phone whose id is gone knows it was revoked.
- `miblo phone list` (also `--json`) / `miblo phone revoke <id>`: the computer forgets that phone
  at once (`phones.json`); the relay is told (it closes the phone with 4411 and refuses it from then
  on); its decisions and replies are refused, the requests waiting on the phones go back to the
  computer's own prompt, and the pairing's read token and status key are replaced (`epoch` + 1;
  the open pairing window and the QR code go too). Each phone still enrolled gets the new ones
  sealed to it, `{v:5, kind:"rekey", epoch, readToken, key}`, the next time it is connected
  (presence lists it), on the `status` channel (a status frame with `to`, which the relay forwards
  to the named phones on every plan and never keeps, so a lapsed Miblo+ room re-keys too), at most
  3 times per connection; on Miblo+ the phone confirms with `{kind:"rekeyed", epoch}`; it keeps
  them, and in its pairing vault. The computer keeps revoked ids in `phones-revoked.json` (always
  left out, so no racing write can bring one back) and each phone's changing state (counter, last
  use, key generation) in `phone-state.json`, apart from the list of phones. A revoked phone, an old pairing link and a phone that never enrolled (status
  only) are left with keys that no longer work: the last one scans a new QR code.
- `miblo phone off` forgets the pairing, every phone, the window and the reply nonces.

### v5: sealed frames
- Computer → phones: `{t:"msg", ch, iv, ct, to:{<phone>: <wrap>}}`. `ct` = AES-256-GCM(content
  key, payload) with a fresh random 32-byte content key and AAD `v5|msg|<ch>|<room>`; each wrap =
  base64url(iv ‖ AES-256-GCM(phoneKey, content key)) with AAD `v5|ck|<ch>|<room>|<phone>`. The
  relay hands each phone its own wrap as `k`. A phone not named (a revoked one, one that never
  enrolled, a guest) gets nothing; the shared pairing key opens none of it.
- Phone → computer: `{t:"up", ch, iv, ct}` under its own `phoneKey`, AAD `v5|up|<ch>|<room>|<phone>`;
  the relay adds `p`. The computer opens it with that phone's key only, and refuses a decision or a
  reply whose `phone` field is not that phone. History requests (`open`) therefore come from
  enrolled phones only.
- Test vector: `tests/fixtures/plus-vector.json` (`v5`), identical in the plugin; both suites open
  each other's frames.

### Passkeys (every allow, every reply)
The phone app is served by miblo.ai, so a compromised origin, deploy or dependency could run code
next to the pairing keys while the app is open. So an allow, and every reply, needs more than the
keys:
- Enrollment: `navigator.credentials.create` with a platform authenticator, `userVerification:
  "required"`, `residentKey: "preferred"`, ES256, `attestation: "none"`, rp `miblo.ai`, challenge
  = SHA-256(`"miblo-enroll-v4|" + room + "|" + phone + "|" + en + "|" + macKey`). The computer
  checks the client data (type `webauthn.create`, the challenge, origin `https://miblo.ai`, not
  cross-origin), the authenticator data (rpIdHash of `miblo.ai`, UP and UV flags, an ES256 P-256
  key) and keeps the credential id and public key.
- Every request carries a fresh `nonce`; an allow's challenge is
  SHA-256(`"miblo-approve-v4|" + id + "|" + tool + "|" + hash + "|" + room + "|" + nonce`), computed
  by the phone from what it received and shows. The decision carries `wa: {cred, ad, cdj, sig}`
  (base64url). The computer checks the credential is the enrolled one, the client data (type
  `webauthn.get`, that challenge, the origin), the authenticator data (rpIdHash, UP and UV), the
  ECDSA signature over `ad ‖ SHA-256(cdj)`, and a sign counter that moved forward (a counter of 0 on
  both sides, as synced passkeys report, is accepted).
- Every reply (v5) carries `wa` too, over SHA-256(`"miblo-reply-wa-v5|" + room + "|" + phone + "|"
  + session + "|" + nonce + "|" + ts + "|" + rt + "|" + base64url(SHA-256(text))`), with the same
  checks. The phone asks for the biometric or PIN when Send is tapped; code on the page that holds
  the MAC key cannot type into Claude Code on its own.
- Phones and browsers without a user-verifying platform authenticator cannot enroll: the app says
  why, and approvals and replies stay unavailable there (the status works).
- Test vectors: `tests/fixtures/plus-vector.json` (identical in the plugin) holds a registration
  and an assertion made by a software authenticator; `scripts/plus-e2e.mjs` uses Chromium's virtual
  authenticator (CDP WebAuthn domain).

### Payloads
- `history`: `{v, kind:"history", at, session, harness, title, reply, rt?, msgs:[{id, role, text, at}]}`.
  `rt` (v5, when `reply`): a reply token (16 random bytes) the computer issued for that session;
  a reply must answer one it issued in the last 10 minutes (each session keeps its newest 4).
  `session` is the 8-character id of the status frame; `role` is `assistant`, `tool` (a one-line
  tool summary), `user` (a prompt typed at the computer) or `phone` (a reply that reached the
  session); at most 50 messages, 2 000 code points each (240 for tools), about 40 KB in all (the
  oldest go first). `reply` is true when the session can take replies now. Sources: Claude Code
  transcripts (assistant text, tool calls, prompts; never thinking, tool output, subagents or
  meta entries) and Codex rollouts; other harnesses send no history.
- `open`: `{v, kind:"open", session, at, nonce}`. The writer sends that session's history at once
  (at most every 2 s) and its updates for 5 minutes after the last `open`; nothing for sessions no
  phone opened. Nothing of it is stored on the relay, in the pairing vault or on the phone (memory
  only).
- The status frame of a Miblo+ computer adds `plus: {on: true, approvals, history, replies, phones}`;
  without it the phone shows the upsell and sends nothing Miblo+ (after a 4402 it waits 10 minutes).
- `reply` (each reply token answers one reply; the computer refuses replies to a session whose
  latest hook event reports a permission mode that acts without asking (`bypassPermissions`,
  `auto`, `acceptEdits`, `dontAsk`) or none, unless the person ran `miblo plus replies permissive on`
  in a terminal; every delivered reply is shown on the computer, on the gadget for a minute
  ("Celular: …") and as a desktop notification, as is every request allowed from the phone
  ("Aprovado: …"); before delivery, invisible characters (controls, zero-width and direction
  marks, U+034F, variation selectors such as U+FE0F, tag characters) are removed, blank look-alikes
  (U+00A0, U+1680, U+2800, Hangul fillers, the typographic spaces) become spaces, U+2028/U+2029
  line breaks, and every run of 3 or more blanks is shortened (two spaces, or one empty line). The
  gadget and the notification show the text whole only when it is exactly what was delivered;
  otherwise with the true delivered length ("(57)"), flagged "(57!)" (and said in words in the
  notification) when the summary hides part of it (cut, or many blanks squeezed), showing its start
  and its end, and the computer's audit log keeps the whole delivered text. The permission mode is the
  one the session's latest hook event reported: a switch made while Claude Code is idle is seen with
  its next event): `{v, kind:"reply", phone, session, text, nonce, ts, rt, mac, wa}`; text ≤ 4 000 UTF-8
  bytes; `mac` = base64url(HMAC-SHA256(phone's macKey, `"miblo-reply-v5|" + room + "|" + phone + "|"
  + session + "|" + nonce + "|" + ts + "|" + rt + "|" + base64url(SHA-256(text))`)); `wa` the
  passkey assertion above. The writer accepts it from an enrolled phone (the one whose key sealed
  the frame) with a valid MAC, once per `nonce` (kept 10 min, also across a bridge restart in
  `plus-nonces.json`, 0600), with `ts` within 2 minutes of its clock and not older than the
  bridge's start, for a Claude Code session it tracks, answering a reply token it issued for that
  session, with a valid user-verified assertion of that phone's passkey over that text, to a session
  with a live channel server; otherwise `reply_ack` `refused` (to that phone only) with `reason`
  (`unknown_phone`, `bad_mac`, `stale`, `unknown_session`, `not_claude`, `bad_token`,
  `passkey_<why>`, `no_channel`, `too_long`, `off`, `busy`). Replies are off by default.
- `approval`: `{v, kind:"approval", at, id, session, tool, input, full, hash, nonce, expires}`.
  `id`, `nonce`: 128-bit random (22 base64url). `input`: the tool input as canonical JSON (keys
  sorted at every level), whole when `full` (≤ 30 KiB), else only its start. `hash` =
  base64url(SHA-256(canonical input)). `expires` ≤ `at` + 1 h (the computer's "how long a prompt waits" setting, 15 s to 1 h). `approval_done`:
  `{v, kind, at, id, outcome}` with `allow`, `deny`, `timeout` or `answered`.
  The phone shows the card, with its deadline as a time of day and the time left, until `expires`
  or until `approval_done` comes. The relay keeps no approval frame (a phone not connected at that
  instant misses it), so the computer keeps the frame it sent for as long as the request waits and
  sends it again, unchanged and sealed to that phone alone: to an enrolled phone that appears in
  the relay's presence, and when a phone asks with `approval_sync` `{v, kind:"approval_sync",
  phone, at}` (the phone sends it each time its connection opens with Miblo+ on, and when the app
  is unlocked; the computer answers a phone at most every 5 s). The phone keeps one card per `id`
  and never brings back one it answered. A prompt that arrives while no phone is connected still
  falls back to the computer at once (`no_phone`), as before.
- `decision`: `{v, kind:"decision", phone, id, session, tool, hash, decision:"allow"|"deny", nonce,
  ts, mac, wa?}` with `mac` = base64url(HMAC-SHA256(phone's macKey, `"miblo-decision-v4|" + room +
  "|" + phone + "|" + id + "|" + session + "|" + tool + "|" + hash + "|" + decision + "|" + nonce +
  "|" + ts`)) and, for an allow, `wa` (above). The phone keeps the frame key and its MAC key as
  non-extractable CryptoKeys; pairings saved before v4 have no phone identity: the app asks to pair
  again for Miblo+.

### Approvals (Claude Code)
1. Claude Code runs the plugin's synchronous `PermissionRequest` hook (`approve.js`, hook
   timeout 130 s). With approvals off (default), no Miblo+, no phone pairing, no bridge, or any
   error, it prints nothing and Claude Code shows its own prompt.
2. The bridge asks the phones only when Miblo+ is active, at least one phone is enrolled and a
   phone is connected (presence); otherwise it answers at once and Claude Code asks as usual.
3. The phone checks that the input it received hashes to `hash`, then shows that input without
   dropping or hiding any character: the command first and in full (no scroll box of its own),
   every line break as `↵`, tabs as `⇥`, and every control, bidi or zero-width character as a
   visible escape (`⟨U+202E⟩`, `⟨ESC⟩`, `⟨CR⟩`), and every combining mark past the second on one
   character too (v5: stacked marks could paint over other text); line and character counts;
   warnings for multi-line, long (> 300 characters) and non-ASCII text anywhere (command, path,
   description, diff, any field); the AI-written `description` apart, labelled and secondary; for
   file edits the target path prominently and the whole diff. Every box clips its own ink
   (`overflow: hidden; contain: paint`). Any hidden or control character, or stacked marks, makes
   the card deny-only. Approve is enabled only
   once the end of the request has been on screen, needs a second tap, then the passkey with the
   user's biometric or PIN. Deny needs a second tap and no passkey.
4. The writer accepts a decision only for a pending, unsettled request with the same session,
   tool and hash, from an enrolled phone with a valid MAC, an unseen nonce, `ts` within 2 minutes,
   before `expires`; and an allow only for a `full` input with a valid passkey assertion. The
   request is then settled (single use). Timeout (15–120 s, default 60) answers nothing: Claude
   Code's own prompt. Nothing ever allows by default.
5. Every request, refusal and outcome is appended to `<data>/approvals.log` on the computer
   (JSONL, 0600, capped at 256 KiB): time, request id, session, tool, input hash, which phone
   (id and name), outcome, why, and a short summary made on the computer (the first 200
   characters of the command or the file path, hidden characters spelled out). `miblo plus audit`
   shows it.
6. Turning approvals (or replies, or history) on and changing the timeout (15 s to 1 h) are
   confirmed on a phone the computer already has, with the code the computer shows and that
   phone's passkey ("v7: confirmations on the phone"); never under an AI agent. Before 1.23: the
   4-digit gadget code ("Physical presence" below).

### Replies (Claude Code, beta)
Claude Code's documented way to add input to a running session is a channel (MCP server with the
`claude/channel` capability emitting `notifications/claude/channel`), a research preview. The
plugin's channel server (`miblo-phone`, `channel.js`) is not in the plugin manifest: `miblo plus
replies on` (from a terminal) registers it in Claude Code at user scope (`claude mcp add --scope
user miblo-phone -- sh <plugin>/bin/miblo-run --no-wait channel.js --data <data>`) only while the
computer is linked to Miblo+ with replies on (off by default); `replies off`, `unlink`, a revoked
link and uninstalling remove it (`claude mcp remove`). It long-polls the bridge for replies to its
own session (matched by the Claude Code process the hooks also report) and emits them with
`meta.miblo_nonce`. Claude Code takes them in only when the session was started with
`claude --dangerously-load-development-channels server:miblo-phone`; otherwise it drops them
silently, so the phone shows `sent` (handed to Claude Code) and never `delivered` (seen in the
transcript), plus a hint after 20 s. Before 1.24 no terminal keystrokes were injected and the
other tools got no replies; from 1.24 see "1.24: replies in every AI tool" (the channel stays
only for Claude Code sessions started before the update).

### The bridge's local port
Hooks and the CLI reach the bridge on 127.0.0.1 with a per-user key (`bridge.key`, 0600): every
request answers a single-use challenge from `/health`. Challenges live 10 s; at most 400 are made a
second, at most 4 a second for one connection, and at most 2 048 are open. Another local user who
floods `/health` can delay the hooks but never act: a hook that gets no challenge sends nothing,
and the PermissionRequest hook then prints nothing, so Claude Code shows its own permission prompt
on the computer. v5: the bridge's answer to a signed request carries `x-miblo-resp` =
HMAC-SHA256(key, `"miblo-resp:" + challenge + ":" + status + ":" + hex SHA-256(body)`), and the
clients use an answer only when it verifies: if the bridge stops between `/health` and the request
and another local user takes the port, its "allow" (or a reply for the channel server) is ignored.
The data folder is 0700 and every file in it 0600 (tightened when the bridge starts).

### Physical presence (the local gate)
History (v6 and before): from 1.23 the trust root for widening is a confirmation on the person's
phone ("v7: confirmations on the phone"); the agent checks below remain as friction, and the
gadget's Plus code is no longer asked by the CLI or the desktop app.
Everything that lets a phone act on the computer (turning Miblo+ approvals, replies, replies into
permissive sessions or history on, changing the approval timeout, enrolling a phone's approval
identity) needs the person AT THE DESK, proven by the gadget:
- the CLI asks a paired Miblo, authenticated with its pairing token, to show a 4-digit code
  (`POST /api/plus-code {"kind":"phone"|"permissive"|"settings","nonce"}`, next firmware release:
  PresenceGate `Purpose::Plus`). The code is drawn only on the gadget's screen, under a title
  saying what it is for ("Código: celular aprova", "Código: resposta livre", "Código: ajustes
  celular"; short enough never to be cut in any of the 7 languages); it is never in any reply. The
  nonce is new for each request: while a Plus code is on the screen the gadget refuses (429 busy)
  a request with another kind or nonce, so one code confirms one change. The person types the code
  into the terminal or the desktop app, and the CLI sends it back with the request's nonce
  (`POST /api/plus-check {"code","nonce"}`): 200 once (the code leaves the screen), 403 otherwise
  (another nonce counts as a wrong code); 5 wrong codes lock this purpose out with the firmware's
  escalating lockout (1 min doubling up to 24 h, kept across a restart), separate from the update,
  settings, Wi-Fi and reset codes. An AI agent on the computer cannot see the screen;
- no paired Miblo reachable: refused ("a paired Miblo must be on and on the network"); a Miblo
  whose firmware has no Plus code (404): refused with "update your Miblo" ("Atualize seu Miblo");
- in a terminal the code is asked at once, on the controlling terminal; from the desktop app (or
  anything that is not a plain terminal) the request is kept (`local-request.json`, 0600, one at a
  time, 10 minutes, single use, with its nonce and the kind the gadget's title shows, validated
  again before the code is spent) and the app collects the code, then runs `miblo plus confirm
  <code>`, which says exactly what it turns on and under which gadget title before applying it and
  refuses a stored request that no longer matches. The CLI never prints the code;
- extra friction only, not the trust root: under an AI agent (environment markers such as
  `CLAUDECODE`, or an agent process among the ancestors) widening is refused before any code is
  shown, and `plus confirm` is refused too; the user-only slash commands never run these and never
  ask the user for the code. Process names and ancestry can be faked (a renamed `screen`, a
  symlink, a copy), which is why they no longer decide anything;
- pairing a phone for the STATUS ONLY (sessions, limits, alerts) needs no code: such a phone
  carries no pairing-window secret and can never enroll an approval identity, approve, reply or
  read conversations (those are sealed to enrolled phones). On a computer linked to Miblo+, `miblo
  phone on|link` in a terminal asks for the gadget code and, typed right, opens the enrollment
  window; `miblo phone enroll` (terminal or app) does just that.
Residual, documented: an attacker who is physically at the desk (or can see the gadget, say
through a camera pointed at it) and controls the computer can pass. Allows and replies still need
the enrolled phone's passkey, and every enrollment shows its fingerprint (`miblo phone list`).

## v6

### v6: phones through the account

Pairing is account-based for every plan (free and Miblo+). Nothing is scanned or pasted, and the
gadget code is never asked to add a phone.

1. **The computer joins the account.** `miblo account link` (alias `miblo plus link`; the desktop
   app's "Entrar com sua conta Miblo") runs the device flow of docs/miblo-plus.md section 1 for any
   account, free or Miblo+. `miblo phone on` needs a linked computer; it makes the room secrets
   (as in v2) and registers the room with the account (`POST /api/plus/rooms`, any plan).
2. **The phone joins the account.** The phone app is signed in to the same account and has passed
   its second factor in the last 5 minutes (the account must have one: a phone is only added to an
   account with two factors). It makes, once per browser:
   - an ECDH P-256 key pair (the private key a non-extractable CryptoKey in IndexedDB, never
     exported, never in the vault);
   - a random phone id (16 bytes, 22 base64url);
   - when the device has a user-verifying platform authenticator, a passkey (rp `miblo.ai`, UV
     required, ES256, `attestation: "none"`) over challenge
     SHA-256(`"miblo-phone-v6|" + phone + "|" + pub`) (`pub`: the raw uncompressed public key, 65
     bytes, base64url). Without passkeys the phone still joins: it shows the status and the history
     and can never approve, reply or start a task.

   and registers `POST /api/phones {id, name, pub, att?, cdj?}` (session, CSRF, fresh second
   factor). The account keeps at most 5 phones not revoked (409 `phone_limit`), emails "New phone
   on your Miblo account" with the phone's name and a link to revoke it, and lists it in the
   account page ("Celulares", revoke button).
3. **The person allows it on the computer.** While the phone companion is on, the bridge reads the
   account's phones as soon as the server says they changed (below, "Push: phones changed"), every
   3 s while one of its requests waits for the phone, and otherwise every 10 minutes
   (`GET /api/plus/phones`, Bearer `mpt_…`: `{phones:[{id, name, pub,
   att, cdj, model, place, created_at, asked_at}], revoked:[{id, revoked_at}]}`; `model`: browser
   and system from the registering request's User-Agent, `place`: its city and country, both
   approximate and only shown to the person). A phone it does not know yet gets **nothing**: its
   registration is checked like any passkey registration (type `webauthn.create`, the v6
   challenge, origin `https://miblo.ai`, rpIdHash, UP and UV, ES256 P-256; a credential already
   used by another phone or request is refused) and it is queued as a request
   (`phones-pending.json`, 0600: the phone id, its `pub` and checked passkey, name, model, place),
   shown as "Permitir? <name>" on the gadget and as a desktop notification ("Novo celular quer
   acessar: <name> (<model>, <place>)", with the commands), and the computer tells the account
   `PUT /api/plus/phones/<id>/request {state: "pending", expiresAt, commit, cpub, nonce}` (the
   code exchange below) so the phone shows "Aguardando confirmação no computador" with the
   computer's name, the time left and, a few seconds later, the 6-digit code to type there. A
   request waits 15 minutes:
   - (v6; from 1.23 see "v7: a new phone types the computer's code")
     **Permitir** in the desktop app, or `miblo phone approve <id> --code <code>` in the person's
     own terminal (which asks for the code on the controlling terminal when it is not given),
     typing the code the waiting phone shows (below, "Verifying a new phone"). A code that does
     not match turns the phone away at once (`code_mismatch`: one try per request; the phone asks
     again for a new round). Refused (exit 3, nothing changes) under an AI agent, from a script or
     detached process and inside a terminal multiplexer: the same local-context detection as the
     other widening commands (lib/local-gate.js, a heuristic: friction, not the boundary, which is
     the code). Before admitting, the CLI reads the account's list again: a
     phone no longer listed is dropped (`gone`), one listed with another key is turned away
     (`key_changed`). The phone is then admitted with exactly the id, `pub` and passkey the
     request was made with: the computer makes its MAC key (32 random bytes, protocol v5 "Phones":
     reader token and frame key are derived from it as before), adds it to `phones.json`,
     registers its reader token with the relay and writes the audit log; at most 5 phones.
   - **Recusar** (`miblo phone deny <id>`, allowed from anywhere: it only narrows): the request is
     `denied`, the phone gets nothing and is never asked about again while the account lists it.
   - Nothing within 15 minutes: `expired`, nothing for the phone. The phone's "Pedir de novo"
     (`POST /api/phones/<id>/again`, session, CSRF, second factor) sets `asked_at`; a computer
     whose request expired before that asks the person again for another 15 minutes.
   Each state goes to the account (`state`: `pending` | `denied` | `expired`); the phone reads
   them with its grants (`GET /api/phones/<id>/grants` -> `{grants, requests: [{device:{id, name},
   state, expires_at, at}], sig}`), waiting on it (`?wait=<sig>`, below) while no computer let it
   in or one asks the person. A grant replaces the
   computer's request. If the account later lists an admitted phone with a different `pub`, the
   computer revokes it (as `miblo phone revoke`); grants are always sealed to the `pub` the person
   allowed, never to what the account shows now. Phones migrating from v5 (below) come back
   through the same confirmation.

   Contract for the desktop app (v6; the v7 contract is in "v7" below): `miblo phone pending --json` -> `[{id, short, name, model,
   place, passkey, joinedAt, seenAt, expiresAt, codeReady}]` (times in ms; only requests still
   waiting; `codeReady`: the phone shows its code now, so Permitir can ask for it);
   `miblo phone approve <id> --code <6 digits> --json` (`--code=<6 digits>` too; spaces and `-`
   inside the code are ignored) -> exit 0 `{ok:true, phone:{id, name}}`, 2 `{ok:false,
   error:"not_found"}` or `{ok:false, error:"code_required"}` (no code given: ask the person for
   the code the phone shows), 3 `{ok:false, error:"refused"}` (not the person at the computer), 1
   `{ok:false, error}` with `code_not_ready` (the phone has not shown a code yet: wait a few seconds
   with the phone app open) | `code_mismatch` (the phone was turned away; it must ask again) |
   `expired` | `denied` | `gone` | `key_changed` | `too_many` | `off` | `cancelled` |
   `known_phone`; `miblo phone deny <id> --json` -> 0 `{ok:true, phone:{id, name}}` or 2
   `not_found`. `<id>`: the whole id or its first 4 to 22 characters (unique).
4. **The grant.** For each allowed phone the computer seals the pairing to the phone's key, signs
   it with its identity key and stores it in the account: `PUT /api/plus/phones/<id>/grant {room,
   epoch, epk, iv, ct, cpub, sig}` (`cpub`, `sig`: below, "Signed grants"):
   - `eph`: a fresh ECDH P-256 key pair per grant; `epk` its raw public key (base64url);
   - `z` = ECDH(eph, phone's `pub`); `k` = HKDF-SHA256(ikm `z`, salt UTF-8 `"miblo-grant-v6|" +
     phone + "|" + room`, info UTF-8 `epk`, 32 bytes);
   - `ct` = AES-256-GCM(`k`, `iv`, payload, AAD UTF-8 `"v6|grant|" + phone + "|" + room + "|" +
     epoch`), payload `{v:6, kind:"grant", room, readToken, key, macKey, epoch, name, at}`.
   The phone reads its grants with `GET /api/phones/<id>/grants` (session, second factor in the
   last 12 hours) every time the app opens, with a long poll while it waits for one (below, "Push:
   phones changed"; every 15 s as a fallback) and every 2 minutes after, opens only those signed by a computer it confirmed (below), checks the room and the
   generation (never older than the one it holds) and keeps the computer as a pairing (as v5,
   with its phone identity), bound to the signed-in account and to that computer's key (a room
   another computer key holds is never taken over). The server stores only ciphertext: it never
   sees a room key, a read token or a MAC key, and it cannot make a grant the phone accepts.
5. **Revoking.** From the account page or the phone app (`POST /api/phones/revoke {id}`, session,
   CSRF, second factor): the account marks the phone revoked, deletes its grants and emails it;
   each computer sees it in its next read (at once: the change pushes it) and revokes the phone locally exactly as `miblo phone
   revoke` does (relay drops it with 4411, its requests go back to the computer, the read token
   and status key are replaced, `epoch` + 1, and the other phones get new grants). A phone that
   disappears from the account's list (account deleted) is revoked the same way. `miblo phone
   revoke <id>` on the computer also deletes that computer's grant (`DELETE
   /api/plus/phones/<id>/grant`); that computer never asks about the id again.
6. **Migration from v5.** The first v6 bridge or CLI run revokes every phone enrolled through a QR
   code (`phones.json` entries without `acct`) and replaces the read token and status key once
   (`phone-v6.json`, 0600, records it): old links, QR codes and vault copies stop working. A v6
   phone app deletes pairings it did not get from the account and says "Entre na sua conta Miblo
   para continuar"; it joins again as above as soon as the computer is linked, and the person
   allows it on the computer like any new phone.

The relay only adds the content-free `phones_changed` hint (below): phones authenticate with their
own reader tokens, the status uses the pairing key (now only ever inside grants), Miblo+ frames
are sealed per phone.

#### Push: phones changed

So that a new phone shows its code within a few seconds (and a revocation reaches the computers
at once) without every linked computer reading the account all the time:

- **Server to computers.** When a phone joins (`POST /api/phones`), answers a commitment with a
  new nonce (`POST /api/phones/<id>/sas`; the same answer repeated tells nobody again), asks again
  (`POST /api/phones/<id>/again`) or is revoked (`POST /api/phones/revoke`), the account side, after
  answering the phone, calls each relay room registered by a linked (not unlinked) computer of
  that account: `POST /__phones` on the room, reachable only through the rooms' namespace (the
  router forwards 22-character room paths only). The room sends its authenticated writer the fixed
  frame `{"t":"phones_changed"}` and stores nothing; with no writer connected it is dropped. A
  room that cannot be reached never fails the phone's request.
- **The hint carries nothing.** No phone id, no state, no data: the computer treats it only as
  "read the account now" and runs its usual authenticated `GET /api/plus/phones` (Bearer), with
  every check above. Only the relay writes to the writer's socket (a phone's frames always arrive
  wrapped as `{"t":"up"}`), over the connection the computer opened to the server it trusts; a
  forged or hostile hint can at most make the computer read sooner, which the bridge bounds: hints
  close together make one read (200 ms), reads a hint starts are at least 1 s apart and at most 20
  in 10 minutes (more are ignored; the timers still run). A new relay connection counts as a hint
  (one may have been missed while it was down).
- **The computer's timers.** Every 3 s while a request waits for the phone (its nonce has not
  come, or the account has not taken the request's state), otherwise every 10 minutes: a fallback
  for a missed hint and for a server without push (a self-hosted server older than this one: a new
  phone then waits up to 10 minutes for the computer, so update the server with the plugin). A
  bridge without push ignores the frame (an unknown `t`) and keeps reading on its own timer.
- **The phone's long poll.** `GET /api/phones/<id>/grants` answers with `sig` (a digest of its
  grants and requests); `?wait=<sig>` holds the answer until they differ or 20 s passed. While it
  waits the server reads only the phone's change counter (`account_phones.rev`, one primary-key
  read every 500 ms, moved by every write that changes what the phone reads: a computer's request
  or grant, the phone's revocation, a computer unlinked) and reads the grants and requests again
  only when it moved: about 43 reads per waiting phone per 20 s instead of about 120, so the phone sees a computer's commitment, nonce and grant about half a
  second after it was stored, with one request (and one count against the account's rate limit)
  per change or per 20 s. A `wait` that is not a sig is answered at once.
- **Measured** (`test/api.test.ts`, this server on Node with a real relay socket and a computer
  that answers each hint at once): from the phone tapping "join" to its code, about 1 s; with the
  plugin's own reaction and 100 ms round trips (its `test/phone-push.test.js`), about 2.1 s.

#### Verifying a new phone (the code) and signed grants
(The commit-reveal code below is v6, kept for history: v7 replaces it with the PAKE in "v7: a new
phone types the computer's code". Signed grants, the computer's identity and pairings bound to the
account are unchanged.)

Security audit 1.21.0, findings 1 and 2: the account lists the phone's `pub`, and the server
could have listed its own key instead (every grant would then be sealed to the server), or sealed
grants of its own to the phone's key (the phone would then follow a room and keys the server
chose). Both are closed with a short authentication string the person compares by typing it, and
a long-term key of each computer that the phone pins. Shared vector: `plus-v6-vector.json`
`trust` (plugin and web).

- **The computer's identity.** Each computer makes once an ECDSA P-256 key pair
  (`computer-identity.json`, 0600, kept when the companion is turned off): `cpub`, the raw
  uncompressed public key, base64url (87). Its fingerprint, shown on the phone: the first 8 bytes
  of SHA-256(raw `cpub`) as 4 groups of 4 hex digits.
- **One round per request** (a new phone, or one that asked again):
  1. The computer makes a nonce `N` (32 random bytes, base64url) and sends the commitment
     `commit = b64url(SHA-256("miblo-sas-commit-v6|" + phone + "|" + pub + "|" + cpub + "|" + N))`
     with `cpub` (`PUT …/request {state:"pending", expiresAt, commit, cpub, nonce:null}`), `pub`
     being the key the account showed it.
  2. The phone, seeing a pending request whose nonce is not out yet, makes its nonce `P` (32
     bytes, kept per commitment in its identity, IndexedDB) and answers `POST
     /api/phones/<id>/sas {device, commit, pnonce: P}` (session, CSRF, second factor; set once per
     round: the same answer again is fine, another is 409). A commitment the phone first sees with
     its nonce already out is never answered (whoever relays could have chosen what the phone saw
     after learning `N`).
  3. The computer reads `P` with the phone (`GET /api/plus/phones`: `request: {commit, pnonce}`),
     fixes it for the round (the first one seen), and only then publishes `N` (`nonce: N`; the
     account stores it only once the phone's nonce is in).
  4. The phone checks `commit` against its **own** `pub`, the `cpub` it answered and `N` (a
     mismatch: the computer was shown another key for this phone; the phone warns and shows no
     code), and shows `code = uint32_be(SHA-256("miblo-sas-v6|" + phone + "|" + pub + "|" + cpub +
     "|" + N + "|" + P)[0..4]) mod 10^6`, 6 digits, with the computer's name and fingerprint.
  5. The person types it on the computer (Permitir, or `phone approve --code`). The computer
     computes the same over the `pub` it was shown; equal (constant-time): the phone is admitted
     with that `pub`; different: turned away.
  Whoever relays must fix what it tells each side before it can know the other side's nonce
  (the computer's is committed before the phone's arrives; the phone's is sent before the
  computer's is out), so a substituted `pub` or `cpub`, or a ground nonce, gives the two screens
  the same code only by chance (10^-6, and one try per round).
- **Limits on rounds** (audit round 2: a server inventing computers could otherwise make the phone
  answer commitment after commitment, ~3 a second, and grind its code against the code a real
  computer expects). The phone answers at most 3 new rounds in any hour, all computers together,
  and one open (unrevealed) round per computer at a time; past that it answers nothing and shows
  "Muitas tentativas de parear: alguém pode estar tentando entrar". The computer opens at most 3
  rounds per phone in an hour (a request and its "ask again"s) and reveals its nonce once per
  round, only after the phone's nonce is fixed. So the server gets a handful of 10^-6 tries an
  hour.
- **Signed grants.** `sig` = ECDSA P-256 SHA-256 (r||s, 64 bytes, base64url) by the computer's
  key over `"miblo-grant-sig-v6|" + phone + "|" + room + "|" + epoch + "|" + epk + "|" + iv + "|"
  + ct + "|" + cpub`. The phone opens a grant only when `sig` verifies and `cpub` is a computer it
  confirmed; a computer whose code it showed in the last 30 minutes, that did not turn the request
  down, and that grants it is offered first on the phone
  ("Novo computador: <name>. Ele diz que você permitiu este celular com o código 123 456. Foi você,
  no seu computador?" with the fingerprint): only "Sim, fui eu" pins it; "Não reconheço" forgets
  that round. Unsigned grants, signatures that do not verify and keys the phone never saw are
  ignored, so the server can neither make a grant nor bump a generation; an older generation is
  never taken either.
- **Pairings and the account.** Each pairing keeps the uid of the account that made it and the
  computer key that signed it. Only the signed-in account's pairings are shown and connected;
  signed out, they are hidden; another account signing in deletes everything of the previous one
  (pairings, keys, identities, confirmed computers). Signing out on miblo.ai (the header's Sair,
  the community's) deletes the phone app's IndexedDB `miblo-phone` and its localStorage entries
  in that browser, and its Web Push subscription is unsubscribed. A grant the account stops
  listing does not delete the pairing (the server could otherwise make the phone drop a
  computer); a computer that revoked the phone is refused at the relay (4411). Residual: the
  server can withhold grants and delay new keys (a denial of service only).

**Trust model.** In v5 an attacker needed the QR code or the gadget code to add a phone. In v6 the
account carries the phone's identity, but a computer seals nothing to a phone the person did not
allow at that computer, typing the code that very phone shows (so the server cannot put its own
key in the phone's place), and a phone takes keys only from computers it confirmed (so the server
cannot hand it a room of its own): whoever controls the person's miblo.ai account (or miblo.ai itself) can
add a phone to the account, and that phone gets nothing until someone at the computer taps
Permitir (or runs `phone approve` in a terminal of their own). So an account takeover alone reads
nothing; the attacker must also be at the computer, or get the person to allow a phone they do not
recognise (the request shows the phone's name, browser, system and approximate place, and expires
after 15 minutes). An AI agent on the computer cannot allow one (exit 3), and the binding of the
approval to the phone's id and key means the server cannot swap the key after the person said yes.
Further mitigations as before: a phone can only be added to an account that has a second factor
and passed it in the last 5 minutes; every new phone is emailed and listed (account page, `miblo
phone list`); acting on the computer (approvals, replies, tasks) stays off until the person turns
it on at the desk with the gadget code, and every single action still needs that phone's passkey
with the user's biometric or PIN; everything a phone does is shown on the computer and kept in the
audit log. Known limit: until the desktop app is signed and its team pinned, the CLI tells the app
by its process name only ("unverified-app"), which a program on the computer could imitate; the
terminal path asks on the controlling terminal itself.

### v6: history for the chat view

`history` frames from v6 plugins carry `v: 6` and, per message, an optional `tool` object; old
apps keep reading `role` and `text` (the tool's one-line summary is still in `text`).

- `history`: `{v:6, kind:"history", at, session, harness, title, state, reply, rt?, task?, msgs}`.
  `state` (v6): `working`, `needs`, `idle`, `done` or absent; the phone shows "working…" while
  `working`.
- message: `{id, role, text, at, md?, tool?}`. `role`: `assistant`, `user`, `phone`, `tool`.
  `md: 1` when `text` is Markdown written by the AI (assistant messages); the phone renders it with
  its own strict renderer (below); other text is shown as plain text.
- `tool` (role `tool`): `{name, kind, path?, cmd?, add?, del?, n?, out?, err?, diff?}`:
  `name` the tool (≤ 64), `kind` one of `edit`, `write`, `read`, `run`, `search`, `web`, `agent`,
  `todo`, `other`; `path` the file (≤ 200 code points, the home folder as `~`); `cmd` the command
  (≤ 400); `add`/`del` lines added and removed (edits and writes); `n` how many items (a glob or a
  multi-file read); `out` the end of the tool's result (≤ 1 200 code points, ≤ 20 lines; commands
  only); `err` true when the result was an error; `diff` at most 40 lines `[["+"|"-", line]]`
  (≤ 160 code points each) of an edit.
- Limits (unchanged frame budget): at most 50 messages, 4 000 code points of text each, about
  40 KB of messages in all (the oldest go first). Thinking, subagent messages, meta entries and
  images are never sent.
- **Redaction** (plugin `lib/plus/redact.js`, before anything leaves the computer; also the
  snapshot's tool detail for the gadget and the phone, and the task audit log): invisible
  characters stripped first (a zero-width space inside a token splits nothing); always on a whole
  text, never line by line (a key or a quoted value over several diff or patch lines goes in
  full); private key blocks (also cut off at the end); tokens with a known shape (`sk-…`, `xai-`,
  `gsk_`, `hf_`, `gh?_`, `github_pat_`, `glpat-`…, `xox?-`, Slack and Discord webhooks, AWS key
  ids, `AIza…`, `ya29.`, `SG.`, `dop_v1_`, Stripe `sk/rk/pk_live|test_`, `whsec_`, npm, PyPI,
  Miblo `mpt_…`, JWTs…); `Authorization: <scheme> …`, `Cookie:`/`Set-Cookie:`; values given to a
  name made of password, pass, pwd, passphrase, secret, private key, token, key, auth, cookie,
  cred(ential) in env, JSON, YAML, code, query strings and long flags (`--password x`), a quoted
  value up to its closing quote; `mysql -pX`, `… login -p X`, `sshpass -p X`, `curl -u user:X`;
  credentials inside URLs (`scheme://user:pass@`, `scheme://:pass@`); any other long
  high-entropy string (32+ base64 or hex characters with mixed classes). Ordinary code passes
  unchanged (calls, member access, types, keywords, camelCase identifiers, `${…}`, environment
  references, git and content hashes, UUIDs, paths: a corpus of such code is in the plugin's
  tests). Each match becomes `[redacted]`. Then the v4 cleaning and the caps.
- **The phone's renderer** (`chat-markdown.tsx`): Markdown parsed into React elements only (never
  HTML, never `dangerouslySetInnerHTML`): headings, paragraphs, lists, quotes, bold, italic,
  strikethrough, inline code, fenced code blocks (monospace, horizontal scroll, a copy button),
  tables, rules. Raw HTML stays visible text. Images are never loaded (`![alt](url)` shows as
  "[imagem: alt]"). Links: only `http(s)`, shown as their text followed by the domain, opened
  only after a tap that shows the whole address and asks to confirm, with `rel="noopener
  noreferrer nofollow"` and `target="_blank"`. Tool calls are compact cards ("Editou src/x.ts
  (+12 −3)", "Rodou: npm test", "Leu 3 arquivos" for a run of reads), opened on tap (the command,
  the diff, the output); long texts and outputs fold.

### v6: talking to the AI from the phone

Two capabilities, both Miblo+, both off by default:

**1. Responder (a running session).** Only where the tool documents a way for another program to
add input to a session that is running:

| Tool | Reply into a running session |
|---|---|
| Claude Code | yes: channels (research preview), v5 "Replies"; the session must have been started with `--dangerously-load-development-channels server:miblo-phone` |
| Codex CLI | no: `codex exec resume` starts a new run of a session; nothing attaches to a running TUI |
| Gemini CLI | no |
| GitHub Copilot CLI | no |
| Cursor CLI | no |
| OpenCode | no (its server API drives sessions it runs, not a running TUI) |

Resuming a running session headlessly would make two writers of one conversation, so Miblo does
not offer it. The phone shows the composer in every session; where replies are not possible it is
disabled with one line saying why and a "Como ligar" link.

**2. Nova tarefa (a new headless run).** The phone starts a new, non-interactive run of an AI tool
on the computer, in a folder the person allowed on the computer, and follows its output as a
session.

| Tool | Command the computer runs (argv, no shell) | Mode |
|---|---|---|
| Claude Code | `claude -p --permission-mode default --setting-sources user --strict-mcp-config --output-format stream-json --verbose`, prompt on stdin | default mode: anything that would ask goes to the phone's approvals through Miblo's PermissionRequest hook (when approvals are on); whatever nobody allows is denied (Claude Code's headless docs: a `-p` run with no permission host denies every call that would prompt). The task folder's own `.claude/settings*.json` (allow rules, hooks a repository ships) and MCP servers never load |
| Codex CLI | `codex exec --json --sandbox read-only --skip-git-repo-check -`, prompt on stdin | read-only sandbox (it reads and answers, never writes) |
| Gemini CLI | not offered (security audit 1.21.0): run without a terminal it may carry out tools without asking, whatever `--approval-mode` says; back once verified on a device | – |
| GitHub Copilot CLI | `copilot -p <prompt> -s --no-ask-user --deny-tool=shell --deny-tool=write`, stdin closed | read-only (shell and writes denied) |
| Cursor CLI | not offered: what print mode may run without `--force` is not documented | – |
| OpenCode | not offered: `opencode run` allows edits and commands by default | – |

Rules (plugin `lib/plus/tasks.js`):
- **Off by default.** `miblo plus tasks on` (and adding a folder, raising the time limit) needs the
  gadget code (`kind: "phone"` for turning tasks on, `settings` for the rest), from the person's
  own terminal or the desktop app, never under an AI agent. Turning off works from anywhere.
- **Folders.** `miblo plus tasks folder add <path>` stores the folder's real path (symbolic links
  resolved) and an id (the first 12 base64url characters of SHA-256 of the real path); at most 12.
  The phone names a folder by its id only. Before every run the computer resolves the stored path
  again and refuses when it is no longer a directory or its real path changed (a link swapped in).
  The run's working directory is that real path.
- **Tools.** Only the ones above, found on the computer (`PATH` and the usual install folders);
  the phone names a tool by id. The computer builds the argv itself; the person's text is one
  stdin stream (or the value of Copilot's `-p`), never interpolated into a command or a shell.
- **Each task needs the passkey.** The phone asks `task_info` (on `reply`, sealed to its key);
  the computer answers on `history` (`{v:6, kind:"task_info", at, on, tools:[{id, name, mode}],
  folders:[{id, name, path}], tt, maxMin, tasks:[…]}`, `tt` a 16-byte task token valid 10 minutes,
  single use, the newest 4 per phone). The task: `{v:6, kind:"task", phone, tool, folder, text,
  nonce, ts, tt, mac, wa}` on `reply`, text ≤ 4 000 UTF-8 bytes, `mac` = HMAC-SHA256(macKey,
  `"miblo-task-v6|" + room + "|" + phone + "|" + tool + "|" + folder + "|" + nonce + "|" + ts + "|"
  + tt + "|" + base64url(SHA-256(text))`), `wa` a UV assertion of that phone's passkey over
  SHA-256(`"miblo-task-wa-v6|"` + the same fields). The phone shows the tool, the mode, the folder's
  path and the text before asking for the biometric. The computer checks, in order: tasks on, an
  enrolled phone with a passkey, the MAC, a new nonce (kept 10 minutes, also across restarts), `ts`
  within 2 minutes and not older than the bridge, the token, the tool, the folder, the passkey, the
  limits; then answers `task_ack` (`started` with the task id and session, or `refused` with a
  reason) on `reply`.
- **Automatic tasks (1.26).** A setting `tasksAuto` (default off, needs tasks on) lets a Claude Code
  task run with no approvals: `claude -p --permission-mode bypassPermissions` and the other flags
  unchanged, in the allowed folder, under the same limits and "Parar"; nothing prompts, so the
  approval hook never fires, and the task can do everything Claude Code can do in that folder
  without asking. It is turned on only from the person's terminal (`miblo plus tasks auto on`,
  `miblo plus set tasksauto=on`) or the desktop app's Phone switch, confirmed on a phone (v7
  `what.on` = `"tasksAuto"`), never under an AI agent; `plus.json` signs it with `mac3`. Off
  (`tasks auto off`, the app, `remote off`) applies at once and stops a running automatic task.
  The status frame's `plus` and `task_info` say `tasksAuto: true` / `auto: true` while it is on;
  only then does the new-task sheet show "Automático (sem aprovações)" (Claude Code only). The task
  then carries `auto: true`, and both the MAC text and the passkey challenge end in `"|auto"`
  (appended only when true; shared vector `autoTask`). The computer refuses `auto` while the setting
  is off (`auto_off`) or for another tool (`auto_unsupported`), audited as `task_auto_refused`; a
  reply continues an automatic task in the same mode only while the setting is still on. Automatic
  tasks carry `auto: true` in `task_info.tasks[]` and the history's `task`, and `auto: 1` in the
  audit (`task` `started` / `continued`).
- **Limits.** One task at a time per computer, at most 10 started per hour and 30 per day; a task
  is stopped after `taskMaxMin` minutes (default 30, 5 to 120) or 8 MB of output.
- **Stop.** "Parar" on the phone sends `{v:6, kind:"task_stop", phone, task, nonce, ts, mac}`
  (`"miblo-stop-v6|" + room + "|" + phone + "|" + task + "|" + nonce + "|" + ts`; no passkey:
  stopping only narrows). The computer sends SIGINT to the run's process group, SIGTERM after 5 s
  and SIGKILL after 10 s (Windows: `taskkill /T`). `miblo plus tasks stop` stops it on the
  computer; `miblo plus remote off` is the kill switch: replies and tasks off, running tasks
  stopped, the reply channel removed from Claude Code; it works from anywhere.
- **Shown and kept.** Every task is shown on the gadget ("Tarefa: …") and as a desktop
  notification with the tool and folder, and the audit log keeps the phone, the tool, the folder,
  the argv (the text as `<prompt>`), the whole text, the outcome and the exit code.
- **Output.** The run's output (Claude Code's stream-json, Codex's JSON events, or plain text) is
  turned into history messages on the computer with the same caps and redaction, and sent as the
  history of session `t` + 7 characters while a phone has it open; `task: {id, tool, folder,
  state: running|done|failed|stopped, started, ended?, code?}` says where it is. Nothing is stored
  on the relay; the computer keeps the last 5 tasks' messages in memory only.
- **The computer may be locked.** Decision: tasks run while the screen is locked, since that is
  when a person away from the desk uses them; the gadget code that turned them on, the passkey per
  task, the folder allow-list, the tool's safest mode and the time limit are what bound them, and
  everything shows on the computer and in the audit log.
- **Tests never run a real AI tool**: the plugin suite and the end-to-end check use fake binaries
  that print canned output.

### v6: My pet on the phone

A Miblo that runs My pet (pet 21, a Miblo Studio pet) is drawn on the phone from its own file, by
the firmware's renderer (WebAssembly), in the mood its screen shows:

1. The bridge reads the file from the gadget while the phone companion is on: `GET /api/pet` (the
   paired computer's token) gives `{installed, v, id}` (`id`: the file's CRC-32, 8 hex, firmware
   1.21+), and only when `id` changed `GET /api/pet-file` (same token; 404 when none) returns the
   file. At most 8192 bytes (MPET1) or 4096 (MPET2); checked with the firmware's own validation
   (lib/mpet.js validateMpet: every field, the checksum, MPET2's draw budget) and against `id`.
   A firmware without the route, a refused file or a failed read leaves no `pet`.
2. The snapshot names it only: `miblos[].pet` = SHA-256(file), base64url (43).
3. The file goes apart, on the status channel sealed to each phone (`to`, as a rekey: allowed on
   every plan, never retained by the relay): `{v:6, kind:"pet", at, hash, file}` (`file` base64url),
   once per phone and pet while the phone stays connected (the relay's presence), again after it
   reconnects.
4. The phone keeps a file only when SHA-256(file) is `hash` and it fits 8192 bytes (in memory and
   localStorage, 6 at most), draws it with `miblo_pet_load` (the firmware's validation again) and
   `miblo_pet_render(mood, frame, look…)` at the file's own speed; anything refused, or a pet not
   received yet, shows the resting eyes.

## v7

### v7: a new phone types the computer's code

Why it changed: in v6 the phone showed the code and the person typed it on the computer. Turned
around naively (the computer shows SAS(N, P)) whoever relays could play the phone towards the
computer: it sees both nonces, so it knows the code. v7 uses a password-authenticated key exchange
(CPace-style over X25519) with the code as the password. Implementations: plugin
`lib/plus/pake.js`, web `src/lib/pake.ts`; shared vector `plus-v7-vector.json` (plugin and web,
identical).

- `CI` = phone | pub | cpub; `sid` = `"miblo-pake-v7|" + phone + "|" + pub + "|" + cpub + "|" + n +
  "|" + rs` (`n` the attempt, `rs` 16 random bytes of the computer for it).
- `G` = Elligator2(SHA-512(lv("miblo-cpace-g-v7") lv(code) lv(sid))[0..32], bit 255 cleared);
  computer `Ya = X25519(a, G)`, phone `Yb = X25519(b, G)`, `K = X25519(a, Yb) = X25519(b, Ya)`;
  `ISK = SHA-256(lv("miblo-cpace-isk-v7") lv(sid) lv(K) lv(Ya) lv(Yb))`; the phone's proof `tag =
  HMAC(ISK, "miblo-pake-phone-v7")`; the computer's `conf = HMAC(ISK, "miblo-pake-computer-v7")`.
1. A phone of the account appears (as in v6): the computer queues it (`phones-pending.json`), makes
   a random 6-digit code (shown only on the computer: `miblo phone pending`, the desktop app, the
   notification) and sends its share: `PUT /api/plus/phones/<id>/request {state:"pending",
   expiresAt, cpub, pake:{n, rs, ya, wrong}}` (never the code).
2. The person types the code on the phone. The phone computes `Yb`, `tag` and a passkey assertion
   (UV) over SHA-256(`"miblo-pake-wa-v7|" + phone + "|" + pub + "|" + cpub + "|" + ya + "|" + yb + "|"
   + tag`) and answers once per attempt: `POST /api/phones/<id>/pake {device, n, ya, yb, tag, wa?}`
   (session, CSRF, second factor; another answer for the same attempt: `409 already_answered`).
   The server stores it (`phone_requests.pake_answer`, migration 0033) and nudges the computer.
3. The computer checks `tag` with its own `a` and code, the keys it saw (`pub`, `cpub`), the
   passkey the phone registered with (rp, origin, UP, UV, counter). Wrong: a new attempt (`n+1`,
   new `rs`, `wrong+1`); **3 wrong answers deny the request**. Right: the phone is admitted with
   exactly that id, `pub` and passkey; `conf` travels inside the first grant (signed, as in v6),
   and the phone pins the `cpub` whose grant carries the `conf` of its own exchange (no "Sim, fui
   eu" step needed). On a Miblo+ computer that already has a phone with a passkey the request is
   `held` (account state `confirm`) until one of those phones confirms it (below, `what.kind:
   "admit"`).
4. **One passkey per phone.** A phone that already has a Miblo passkey re-uses it (after asking
   once): the new identity lists its public key (`account_phones.pk {id, x, y}`) with an assertion
   over the identity (`pkwa`) instead of a registration (`att`, `cdj`). `GET /api/phones` lists the
   account's passkey public keys so the app can tell.
- Desktop contract: `miblo phone pending --json` -> `[{id, short, name, model, place, passkey,
  joinedAt, seenAt, expiresAt, code, held, wrong, left}]` (`code`: the 6 digits the person types
  on that phone; `held`: typed right, waiting for a confirmation on another phone). `miblo phone
  deny <id> --json` as in v6; `miblo phone approve` answers exit 2 `{ok:false,
  error:"phone_types_code"}`.

### v7: confirmations on the phone

Everything that widens what a phone can do on the computer (approvals, replies, replies into
permissive sessions, history, new tasks, a task folder, a longer approval timeout or task limit)
and a second phone on a Miblo+ computer are confirmed on a phone that computer already has
(plugin `lib/plus/confirm.js`). Turning anything off never asks.
1. The bridge makes one request: 128-bit `id`, `nonce`, a random 6-digit code (shown only on the
   computer), `what` (plain data: `{kind:"settings", on:[…], timeoutS, taskMaxMin, folders:[…]}` or
   `{kind:"admit", phone:{id, name, model, place}}`) and `cap` = SHA-256(canonical JSON of `what`),
   for 2 minutes. One at a time (`busy`), at most 6 an hour (`rate_limited`); none without a phone
   with a passkey (`no_phone`).
2. It is sealed to every phone with a passkey (the `approval` channel, each under its own key),
   re-sent when a phone connects and every 10 s while it waits; the relay keeps nothing.
3. The phone renders `what` in its own words; the person types the code and confirms with the
   passkey. Desktop browsers cannot approve ("Confirme pelo celular"). Answer `{v:7,
   kind:"confirm_answer", phone, id, cap, nonce, ts, proof, mac, wa}`: `proof = HMAC(macKey,
   "miblo-confirm-code-v7|room|phone|id|request nonce|code")`, `mac = HMAC(macKey,
   "miblo-confirm-v7|room|phone|id|cap|verdict|nonce|ts|proof")`, `wa` = passkey assertion (UV)
   over SHA-256(`"miblo-confirm-wa-v7|room|phone|id|cap|request nonce|proof"`). The code never
   travels. `confirm_deny` (MAC only) cancels.
4. The computer checks, in order: a phone with a passkey (relay-authenticated, its key opened the
   frame), the pending request (id, not expired), the same `cap`, the MAC, a fresh nonce, the clock
   (2 min), the proof against its own code (**3 wrong codes cancel the request**), then the passkey
   (rp, origin, UP, UV, counter). Only then is the change applied (`plus.json` signed) or the phone
   admitted, and the phones are told the outcome.
- Desktop and CLI contract: a widening command with `--json` answers at once `{confirm:{id,
  state:"waiting", code, expiresAt, what, left, phones}}` (exit 0) or `{confirm:null, error}`
  (exit 3: `no_phone` | `not_active` | `not_linked` | `off` | `busy` | `rate_limited` |
  `bridge`); `miblo plus confirm status [--wait <s>] --json` -> `{confirm}` (state `waiting` |
  `applied` | `wrong_code` | `cancelled` | `denied` | `expired` | `failed`, the code only while
  waiting; with `status` once settled); `miblo plus confirm cancel --json`. `miblo plus confirm
  <4 digits>` is refused (exit 2) with a pointer to the new flow. `plus status --json` and `GET
  /api/plus/me` carry the account `email` (the desktop app: "Conectado como <email>", Sair =
  `miblo account unlink`).

### v7: adversarial analysis

| Who | Cannot | Because |
|---|---|---|
| The relay, miblo.ai or the network (MITM) | learn either code | only `Ya`, `Yb`, `tag`, HMAC proofs and passkey assertions travel; none reveals the code |
| same | answer "typed right" for a phone key of its own | the PAKE key matches only with the same code and the same `phone`, `pub`, `cpub`; one online guess per attempt (10^-6), 3 attempts per request, then denied |
| same | forge or replay a confirmation | per-phone MAC key (never on the server), single-use nonces, 2-minute clock window, `id` and `cap` in the MAC |
| same | have the person confirm another change | the passkey signs `cap`, the hash of exactly the `what` the computer made; the computer applies only its own request |
| same | confirm without the person | passkey assertion with user verification (Face ID, Touch ID, fingerprint or PIN) |
| same | flood or grind | one request at a time, 6 an hour; 3 wrong per request |
| An AI agent on the computer | confirm | it can start a request and read the code, but cannot type it on the phone nor pass the passkey's UV; the CLI also refuses agents |
| A desktop browser signed in to the account | approve | the phone app refuses (`phoneOnly`) |

Residual: a compromised miblo.ai serves the phone app, so it could describe a request as something
other than its `what`; the computer applies only the request it made, which the person (not an
agent) asked for on that computer and which the computer shows as applied. Someone holding the
person's unlocked phone and seeing the computer's screen can confirm as the person. A lost phone
keeps its rights until revoked. Every use of a recovery code, failed attempts at one (at most one
e-mail an hour) and every new passkey send the account's security notice e-mail.

## 1.24: replies in every AI tool

The plugin's side of this section is kept in the claude_gadget repository
(`docs/phone-relay-protocol.md`, "Phone relay protocol: the plugin side of replies in every AI
tool"); this copy is updated from it. Nothing changes on the relay or in the frames' crypto: the
`reply` frame is the v5 one, sealed and passkey-signed as before, for any tool's session.

Principle: each AI keeps working its own way without depending on Miblo, and Miblo does not
interfere. Approvals and every other control exist only where the tool itself asks (its native
prompt, relayed). Messaging is the one thing Miblo builds where a tool lacks it. The journey: "Você
responde pelo celular. Se a sessão está trabalhando, a resposta entra quando ela termina a vez; se
está parada, ela acorda e responde." No channel, no new window, no system dialog (the "Replies
(Claude Code, beta)" channel above stays only for Claude Code sessions started before the update).

### 1.24: capabilities per tool

`miblo plus status --json` (`capabilities`) and the bridge's `GET /plus/status` (`capabilities`)
carry the plugin's `lib/harness/index.js` `CAPABILITIES`:

| Tool | `replyTurnEnd` | `replyIdle` | `approvals` | `modeKnown` |
| --- | --- | --- | --- | --- |
| `claude` (Claude Code) | true (Stop hook, `additionalContext`) | `official` (asyncRewake waiter) | true | true |
| `codex` | true (Stop hook, `decision: block`) | `official` (`codex queue`) | true (PermissionRequest hook) | true |
| `opencode` | true (its Miblo plugin, at `session.idle`) | `official` (SDK `session.prompt`) | true (SDK permission reply) | false |
| `copilot` (Copilot CLI) | true (`agentStop`, `decision: block`) | `typing` | false | false |
| `gemini` (Gemini CLI) | true (`AfterAgent`, `decision: deny`) | `typing` | false | false |
| `cursor` (its agent) | true (`stop`, `followup_message`) | `typing` | false | false |

- `replyIdle`: `official` (the tool's own way), `typing` (the tool has none: Miblo types the reply
  into the session's own terminal when it runs in tmux or GNU screen, or the desktop app types it
  into Terminal or iTerm2 on macOS, below; otherwise the reply goes in at the next turn end),
  `none`.
- `modeKnown: false`: the tool's hooks report no permission mode, so replies go there only when the
  person turned on `miblo plus replies permissive` (refusal `unknown_mode` otherwise).
- No approvals for Copilot CLI (its hook fires before its own rules: Miblo would ask for calls
  Copilot allows by itself), Gemini CLI (no hook decides a prompt) or Cursor (Miblo's hook would
  become the blocker).
- The desktop app shows this table per tool on its Phone tab (tool · approvals · replies: "no fim
  da vez" / "também parada" / "parada: digitada no terminal pelo app" / "—").

### 1.24: routing a reply

The bridge verifies a `reply` exactly as before (enrolled phone, MAC, single-use `rt` from the
session's history frame, fresh nonce, 2 min clock, passkey with user verification over the text,
permission mode) and then routes it:

1. the session is working and the tool has `replyTurnEnd`: queued; the tool's end-of-turn hook
   takes it (`reply_ack` `queued` with `how: "turn_end"`, then `sent`, then `delivered`);
2. idle, `official`: handed to the session's waiter (Claude Code, OpenCode) or to `codex queue`
   (`sent`, then `delivered`);
3. idle, `typing`, the session in tmux or screen and the text one line: typed into its terminal
   after checking it (`sent`, then `delivered`; a failed check falls back to 4);
4. otherwise: queued for its next turn end (`queued`, `how: "turn_end"`); on macOS the desktop app
   may take it sooner (below);
5. a Claude Code session whose hooks predate 1.24: the old channel, as before (`sent` /
   `delivered` from the transcript).

`reply_ack` (to the phone that sent it):

| `state` | Meaning | Phone text (PT / EN) |
| --- | --- | --- |
| `queued` (new), `how: "turn_end"` | waits for the session to finish its turn | "Na fila: entra quando a sessão terminar a vez." / "Queued: goes in when the session finishes its turn." |
| `sent` | a hook, waiter, `codex queue` or the typing took it | "Enviada" / "Sent" |
| `delivered` | handed to the tool (or seen in the transcript) | "Entregue" / "Delivered", with how it went in (the `replyHow` the phone saw when sending: "agora" / "no fim da vez") |
| `refused` | with `reason` (below) | per reason, in plain words |

New refusal reasons: `unsupported` (no reply path for that tool), `idle_unsupported` (idle, no
path, and no turn end either), `old_session` (Claude Code session started before the update, no
channel: "Respostas valem para sessões abertas depois da atualização."), `expired` (queued an hour
and never taken), `session_ended`, `deliver_failed` (`codex queue` failed). `not_claude` and
`no_channel` are no longer sent by 1.24 bridges (the latter only for an old session whose channel
went away between checks); the phone keeps their texts for older computers.

### 1.24: history frames (`replyHow`)

`history` (v6) gains `replyHow` next to `reply`: `now` (goes in at once), `turn_end` (goes in when
the session finishes its turn), or the refusal a reply would get (`unknown_mode`,
`permissive_session`, `old_session`, `idle_unsupported`, `unsupported`, `off`). `reply` is true for
`now` and `turn_end`, and `rt` comes with it. A phone that finds no `replyHow` (a computer before
1.24) keeps the v6 behaviour (replies only in Claude Code, through the channel).

What the phone shows under the reply field, before sending (`SessionReplyCard.tsx`):

| `replyHow` | session state | Line (PT / EN) |
| --- | --- | --- |
| `now` | any | "Entra agora." / "Goes in now." |
| `turn_end` | working | "Entra quando a sessão terminar a vez." / "Goes in when the session finishes its turn." |
| `turn_end` | idle / done / needs | "Esta IA não recebe respostas parada: entra na próxima vez." / "This AI takes no replies while idle: it goes in next time." |
| `idle_unsupported` | | no field; "Sessão parada: o {tool} não aceita mensagens de fora enquanto está parado." |
| `unknown_mode`, `permissive_session` | | no field; the auto-mode text ("Esta sessão roda em modo automático; respostas só em sessões que pedem permissão.") |
| `old_session` | | no field; "Respostas valem para sessões abertas depois da atualização." |
| `unsupported` | | no field; "Esta IA não recebe respostas pelo celular." |
| `off` | | no field; replies are off on the computer (as before) |

There is no "reopen" from the phone: a session that cannot take a reply says why, and nothing is
closed or restarted for it.

### 1.24: remote tasks take replies

A Claude Code task's `history` frame now carries `reply: true`, `replyHow` (`turn_end` while it
runs, else `now`) and `rt` once Claude Code reported its session id. The phone sends an ordinary
`reply` frame with `session` = the task id; the computer verifies it the same way and continues
the task headless with `claude -p --resume <session>` and the task's flags, under the same time
limit and "Parar". A reply sent while a run works goes in when that run ends (`queued`); a stop
drops it (`refused`, `stopped`). Codex and Copilot tasks: `reply: false`, `replyHow:
"unsupported"`. Refusals add `unsupported`, `busy`, `rate_limited`, `folder_changed`,
`unknown_tool`, `stopped`.

`miblo plus tasks open <id> [--json]` (the person only, never an AI agent) opens the person's
terminal running `claude --resume <session>` in the task's folder:
`{"state":"opened","terminal","session"}` or
`{"state":"error","error":"agent|unknown_task|not_resumable|folder_changed|no_terminal|failed"}`.
The desktop app's task cards ("Abrir") run it.

### 1.24: the bridge's local routes (authenticated port)

All behind the bridge key ("The bridge's local port" above: per-request challenge, the answer
MACed with `x-miblo-resp`):

- `POST /plus/reply/take {session_id, harness}` -> `{messages:[{nonce, text}]}`: the replies queued
  for that session, handed out once (`sent`). The end-of-turn hook (`bin/reply-hook.js`) and the
  desktop app's typing.
- `POST /plus/reply/wait {session_id, waiter, harness}` -> `{messages}` (empty after 25 s: poll
  again) or `{retire: true}` (a newer waiter, a prompt, a tool call, the end of the session,
  replies off). The idle waiters (`bin/reply-wait.js`, OpenCode's plugin).
- `POST /plus/reply/done {nonces}` -> `{ok, n}`: those replies were handed to the tool (`delivered`).
- `GET /plus/status` adds `capabilities`, `tasks` and `appTyping: [{session, harness, tty, pid}]`:
  idle sessions of a `typing` tool on macOS without tmux or screen, which only the desktop app can
  type into; until it does, their replies go in at the turn end.
- Approvals: `POST /plus/approval` (unchanged) now also comes from Codex's hook and OpenCode's
  plugin, with `session_id` `codex:<id>` / `opencode:<id>`.

### 1.24: the desktop app types into Terminal or iTerm2 (macOS)

Only the signed desktop app may send Apple Events (the Automation permission, asked by macOS the
first time; the app explains it once before it ever types). Every few seconds, while replies are
on and the person has accepted that explanation, the app:

1. reads `GET /plus/status` over the authenticated port (the bridge key in the data folder; the
   answer is used only when its `x-miblo-resp` verifies) and the sessions of `miblo status`;
2. for each `appTyping` entry, finds the tracked session with the same `pid`, and goes on only
   when that session is idle (`idle` or `done`, never `running`, `perm` or `question`) and is of a
   `typing` tool;
3. checks with `ps` that the pid's terminal is the entry's `tty` and that the pid leads that
   terminal's foreground process group (`pgid == tpgid`), and finds the terminal app among the
   pid's ancestors (Terminal.app or iTerm2; anything else: nothing is typed);
4. takes the queued replies (`/plus/reply/take` with the session's id), types each one-line text
   with AppleScript into the tab or session whose tty is that `tty` (Terminal `do script … in`,
   iTerm2 `write text`; the tty and the text are `osascript` arguments, never part of the script),
   then `/plus/reply/done` for the ones typed;
5. shows "Resposta do iPhone digitada na sessão X" in the app and as a system notification.

A reply the app took but could not type (the check failed between the take and the typing, the
person denied Automation) cannot go back to the queue: the phone stays at "Enviada" and the app
says so ("Não deu para digitar a resposta na sessão X"). The app never types a text with a line
break or a control character.

## v8: the panic button

A red **Pânico** button on the phone (Meu computador, under the sessions; Miblo+ rooms only, a phone
with a passkey) turns the computer's bridge off and ends every AI session Miblo knows there. Only
the computer can turn it back on. Plugin: `lib/plus/panic.js`; phone: `panic-model.ts`,
`PanicButton.tsx`.

1. The person holds the button for 2 s (letting go earlier does nothing), then confirms with the
   phone's passkey and user verification (biometric or PIN).
2. The phone sends, on the `reply` channel, sealed to its own key:
   `{ v: 8, kind: "panic", phone, nonce, ts, mac, wa }` with `mac` = HMAC-SHA256(phone MAC key,
   `miblo-panic-v8|room|phone|nonce|ts`) and `wa` an assertion over
   SHA-256(`miblo-panic-wa-v8|room|phone|nonce|ts`).
3. The computer checks it exactly like a reply: the phone the relay authenticated, enrolled, with a
   passkey; the MAC; a new nonce (a replay gets no answer); `ts` within 2 minutes and not older than
   the running bridge; the assertion (rp, origin, UP and UV, counter). No reply token: a panic
   answers no conversation, and it only narrows what runs on the computer.
4. Refused: `{ v: 8, kind: "panic_ack", at, nonce, state: "refused", reason }` to that phone.
   Accepted: `{ kind: "panic_ack", state: "accepted", by: "phone", nonce, at }` to every enrolled
   phone, then the computer ends the sessions (SIGTERM, SIGKILL 3 s later, to each tracked session's
   process tree; `taskkill /T`, then `/T /F` on Windows), shows "Miblo desligado pelo celular" on
   the gadgets and in a desktop notification, writes `<data>/panic.json` (the lock, written at the
   start already) and sends `{ state: "done", ended }` before the bridge exits. A panic started at
   the computer (`miblo panic`, the desktop app) sends the same `accepted` and `done` with
   `by: "computer"` and no nonce.
5. The phone shows "Ponte desligada. Para religar, use o app Miblo no computador." and offers no
   reply, approval or task for that computer (kept across reloads, by room, with the answer's `at`).
   It shows the computer back once a status frame arrives whose `at` is newer than that: the bridge
   sends no status while it ends the sessions, and the relay's retained status is older.
6. While `panic.json` exists nothing starts the bridge (its start-up, the hooks, the CLI, the
   desktop app's `apps start`). The desktop app's red banner ("Ponte desligada pelo celular às
   HH:MM", **Religar a ponte**) or `miblo panic clear` in the person's own terminal (refused under
   an AI agent) deletes it, audits `panic_cleared` and starts the bridge. No frame turns it back
   on: with the bridge off nothing on the computer listens to the relay.

What it does not guarantee: a process the hooks never reported to the bridge (an agent not set up
with Miblo, a session started while the bridge was down, a Windows session of a tool whose pid the
bridge cannot resolve) is not ended; a process whose name is not an AI tool's is never signalled,
so a forged pid cannot aim it at another program.

## Webhooks (Miblo+, 2026-10-09)

On this server (self-hosted): the room part below (`/__hook`, `/__hook_ask`, `/__hooks`, the
writer's `hook_ack`/`hook_answer`, the queue and the room's life) is ported byte for byte and
tested on both runtimes; on Node an inspector question waits its turn at the room's gate and then
runs beside it, so the writer's answer can arrive. The `/h/<id>` endpoint and the account's hook
API are not built here yet: a computer pointed at this server says webhooks need miblo.ai for now.
On Node a stored value is capped at 128 KB, so the largest deliveries (a 64 KB body with every
forwarded header at its 1 KB cap) would not fit; that matters once `/h/` exists here.

Personal webhooks that become alerts on the Miblo (claude_gadget docs/screen-sdk-architecture.md
"Webhooks" is the whole design; this is the relay's part). The room never opens anything here.

- **Receive** (`web/src/server/hooks/receive.ts`, before OpenNext): `POST|PUT /h/<hookId>` (32
  base64url). Order: 405 → per-IP limit (`HOOK_IP_LIMITER`) → `Content-Length` and the streamed body
  ≤ 64 KB (413) → content type JSON (also `+json`), form, `text/*` or none (415) → the hook by
  base64url(SHA-256(hookId)) on a linked computer (404) → per hook and per account limits
  (`HOOK_LIMITER`, `HOOK_ACCOUNT_LIMITER`, 429 `Retry-After: 60`) → Miblo+ (402
  `plus_required`, nothing forwarded) → the computer's key and newest room (503
  `computer_not_ready`) → sealed → room → 202 `{"ok":true,"id":"<d>"}`. D1 gets counts, the last
  time and status (`sent`, `queued`, `plus_required`, `rate_limited`, `computer_not_ready`).
- **Envelope** (`web/src/lib/hooks/envelope.ts`, vector `tests/fixtures/hooks-vector.json`,
  identical in the plugin): label `"<prefix>|<room>|<id>"`; ECDH P-256 with an ephemeral key;
  HKDF-SHA256(salt = the ephemeral point raw, info = label) → AES-256-GCM, AAD = label; `{epk, iv,
  ct}` base64url. Delivery: prefix `miblo-hook-v1`, id `d`, sealed to the computer's key, plaintext
  `{v:1, hook, d, at, ct, h, b, n}` (`b` the body bytes base64url). Answer: prefix
  `miblo-hook-answer-v1`, id `q`, sealed by the computer to the page's key.
- **Room, internal calls** (binding only; the router forwards 22-character room paths only):
  - `POST /__hook {d, e}` → 202 `{queued, sent}`; 402 on a free room; 400 malformed (`d` 22
    base64url, `e.ct` ≤ 160 KiB). Kept as `hk:<room time>:<d>`, at most 50 (the oldest go), 24 h
    (the alarm drops older ones), and sent to the authenticated writer as
    `{"t":"hook","d","at","e"}` now and to every writer that authenticates later, oldest first.
  - `POST /__hook_ask {q, hook, op, d?, epk}` (`op`: list, get, test, replay; `hook` = `h` + 9 of
    `[a-z0-9]`) → the writer gets `{"t":"hook_ask","q","hook","op","d"?,"epk"}`; the room waits up
    to 8 s for `{"t":"hook_answer","q","e"}` (`e.ct` ≤ 60 KiB) and answers `{e}`; 503
    `{"error":"bridge_offline"}` without a writer, 504 `no_answer`, 429 `busy` past 4 questions in
    flight, 402 on a free room. Never stored.
  - `POST /__hooks` → the writer gets `{"t":"hooks_changed"}` (fixed, nothing in it) and reads the
    account's hooks itself; `{writers: n}`.
- **Writer frames:** `{"t":"hook_ack","d":[ids]}` (≤ 50; the room deletes them) and
  `{"t":"hook_answer","q","e"}`, up to 10 a second on their own budget (not the 2 frames a second
  of the other writer frames).
- **Room life:** a Miblo+ room no phone ever joined is no longer deleted 24 h after it was made: it
  lives like a joined room (30 days without its computer), since a computer may use it for
  webhooks alone.
- **Account API:** linked computer (Bearer): `PUT /api/plus/hooks/key {pub}` (204), `GET|POST
  /api/plus/hooks`, `PATCH|DELETE /api/plus/hooks/<hid>`, `POST /api/plus/hooks/<hid>/rotate`. The
  account page (session, second factor, CSRF, Miblo+): `GET|POST /api/account/hooks`, `POST
  /api/account/hooks/<hid>` (rename), `…/rotate`, `…/delete`, `…/ask {epk, op, d?}` → `{e, room,
  q}`. Every change from the page tells the computer's room (`/__hooks`).
- **Threat notes:** the worker sees each payload in transit (TLS ends there) and seals it before
  anything else; the inspector is not end-to-end against miblo.ai (the server serves the page that
  makes the key), but it shows only what already crossed the worker; a malicious server could ask
  the computer for its delivery history or make it replay one through the person's mapping
  (alerts only: a mapping cannot act on the computer).

## Threat model (v6; v7 and v8 rows at the end)

Free and Miblo+ are held to the same bar: the phone companion exposes the computer's activity to
the cloud only as ciphertext, and nothing on the phone or the relay can act on the computer
without the person's own keys, enrollment and (for an allow) biometric.

| Threat | Mitigation | Tested in |
|---|---|---|
| Malicious or compromised relay reads or forges messages, replies or approvals (free and Miblo+) | AES-GCM under the pairing key for the status (never on the server), AAD binds room, type and channel; Miblo+ frames sealed per enrolled phone; decisions and replies also carry the phone's own HMAC; an allow and a reply also a passkey assertion | web `phone-plus.test.ts`, `relay-crypto.test.ts`; plugin `plus.test.js`, `phone.test.js` |
| Compromised miblo.ai origin (XSS, deploy, dependency) types into Claude Code through replies, with the phone's keys and no biometric | every reply needs a passkey assertion with user verification over room, phone, session, nonce, time, a single-use reply token the computer issued for that session in the last 10 minutes, and the text's hash, checked like an allow (rp, origin, UP+UV, counter); a MAC-only reply is refused | plugin `plus.test.js` (MAC only, other text, no UV, other credential, bad, old or spent token, counter), e2e (MAC-only and other-text replies refused, the real one carries UV) |
| Residual: a compromised origin swaps what one biometric signs. A WebAuthn prompt shows nothing of its challenge, and the page builds it, so code on miblo.ai can wait for the person to tap Send (or Approve, or open the vault) and have that biometric sign its own reply or allow instead | not preventable while the phone app is served by miblo.ai (long term: an installed app with pinned code). What bounds it: one biometric is one action (counter, single-use nonce and reply token); replies reach only sessions that still ask before acting unless the person opted in in a terminal, so an injected text cannot act without a permission prompt there; every delivered reply and every allowed request is shown on the computer at once (gadget, desktop notification, audit log with the computer's own summary), so a swap is visible | plugin `plus.test.js` (permissive sessions refused, opt-in, token spent, shown on the computer), `show-on-computer.test.js`, e2e (reply and allow shown) |
| A holder of the shared pairing key (another phone, a revoked one, an old link, a vault copy) with the relay's help reads a new phone's MAC key and forges its replies or denials | the enrollment is sealed under a key derived from the pairing window's secret, which only the QR code carries; the shared key opens no enrollment and no Miblo+ frame | plugin `plus.test.js` (shared-key enroll refused, vector), web `phone-plus.test.ts` (vector) |
| A revoked or stolen phone keeps receiving approvals and history, or pushes the owner's phones off the relay | the relay knows each enrolled phone by its own token, closes a revoked one (4411) and refuses it; Miblo+ frames reach only the phones they name; one phone pushes out only its own sockets; guests have their own two places; revoke replaces the read token and status key, re-sent sealed to the remaining phones | web `relay.test.ts` (per-phone auth, sealed routing, 4411, eviction), plugin `plus.test.js` (rekey), e2e (revoke) |
| Compromised miblo.ai origin, deploy or dependency signs "allow" with the keys while the app is open | every allow needs a passkey assertion with user verification over H(id, tool, hash, room, nonce), checked on the computer against the key enrolled at pairing (rp, origin, UP+UV, counter); page code cannot get one without the user's biometric or PIN for that exact challenge | plugin `plus.test.js` (no/forged/replayed/other-challenge/no-UV/cloned), e2e (virtual authenticator) |
| Same, residual: a compromised origin shows a misleading card and asks for the biometric for a different request, or enrolls its own key while the user pairs | not fully preventable on the phone; enrollment only inside the 10-minute, one-phone window opened after the gadget's presence code, with the fingerprint shown on both sides (`miblo phone list`); every request and outcome in the computer's audit log with the computer's own summary of what ran; the challenge binds exactly one request | plugin `plus.test.js` (enrollment window, audit summary) |
| An AI agent (steered by a phone reply, a web page or repository content) turns approvals or replies on, changes the timeout or enrolls a phone, also by faking a person's terminal (a renamed multiplexer, a symlinked or copied binary, a pty it drives) | the trust root is physical presence: a 4-digit code only the paired Miblo's screen shows (asked with the pairing token, never in a reply), typed back by the person, bound to that one request (a nonce per request: another request is refused while the code shows, and the code confirms only its own); 5 wrong codes lock it out, escalating up to 24 h; no Miblo online or an old firmware: refused. Terminal and agent checks remain as extra friction (refused under agent markers or an agent ancestor; asked on the controlling terminal). Status-only pairing needs no code: such a phone can never act. Residual: someone at the desk (or watching the gadget) who also controls the computer; allows and replies still need the phone's passkey | firmware `test_security` (Purpose::Plus: own lockout, single use; PlusBinding), `test_ui_main` (code titles never cut), plugin `presence.test.js` (over HTTP: code never returned, busy for another request, other nonce refused, single use, lockout, 401 without the token, old firmware, offline), `plus.test.js`, `phone.test.js` (wrong code, cancel, no Miblo, old firmware, app flow, agent refused before a code is shown) |
| A network shared by many people (CGNAT, an office) is locked out of new rooms by its neighbours | only rooms a phone joined count over the 30-day period (300 for an IPv4 address); rooms never joined cost a day's slot only and give it back when they go; the day cap and each room's own limits do the rest | web `relay.test.ts` (30 joined rooms on one IPv4, the neighbour pairs the next day; never-joined rooms given back) |
| A phone reply hides a payload from the gadget or the notification with look-alike blanks or padding | invisible characters removed, look-alike blanks made spaces, runs of 3+ blanks shortened before delivery; the summaries show the true delivered length and flag one that hides part of the text; the audit log keeps it whole | plugin `show-on-computer.test.js` |
| Relay replays an old decision, reply or history frame | decisions single-use (settled request) with unique nonces and `ts` ±2 min; reply nonces kept 10 min across restarts and anything older than the bridge refused; history newest-wins per session | plugin `plus.test.js`, web `phone-plus.test.ts` |
| Relay withholds or delays frames | an approval expires (≤ 1 h, the setting; phone and computer alike) and then Claude Code asks locally; never auto-allow. A frame a phone missed (app closed, socket down) is sent again by the computer, unchanged and sealed to that phone, while the request waits | plugin `plus.test.js` (resend, approval_sync), web `phone-push.test.ts` |
| A push notification leaks what the computer is doing, or tells the relay | the writer names only a fixed kind; the relay sends fixed words for it and the service worker shows its own words whatever the payload says; no session, tool, command or text; the computer never learns the endpoint; a revoked phone's subscription is deleted with it | web `relay.test.ts` (kinds, unknown kinds ignored, revoke, unsub, the phone on screen), `phone-push.test.ts` (service worker) |
| Confused deputy: a decision for one session or command applied to another | MAC and checks bind phone, id, session, tool and input hash; the passkey challenge binds id, tool, hash, room and nonce; replies matched to exactly one tracked session | plugin `plus.test.js`, e2e |
| Approval spoofing: hidden text in a command (newlines, bidi overrides, zero-width, ESC), stacked combining marks painting over the card, or a misleading AI description | the phone checks the hash of what it received and shows every character (escapes for invisible ones and for marks past two per character, deny-only when present), every box clips its own ink, the command first and whole, counts and non-ASCII warnings on every field, the description labelled as AI text and secondary, Approve only after the end was on screen | web `phone-plus.test.ts`, e2e (bidi and stacked marks deny-only, card clipped, file path and diff) |
| Prompt injection via message text shown on the phone | history cleaned of controls, bidi and zero-width characters and rendered as React text only; labelled as AI text | web `phone-plus.test.ts`, e2e (`<img onerror>` stays text) |
| Prompt injection into Claude through replies | replies off by default, turned on only locally; only from enrolled phones (their own key and MAC), each confirmed with the phone's passkey over its text, only to Claude Code sessions with the plugin's channel that still ask for permissions (permissive ones only after a separate opt-in in a terminal); each reply shown on the computer | plugin `plus.test.js`, e2e |
| Stolen or lost phone | `miblo phone revoke <id>` (or the desktop app): the relay drops it, its frames are refused, pending requests go back to the computer, the status key is replaced; approvals and replies still need its passkey (biometric/PIN); `miblo phone off` rotates every key and deletes the room | plugin `plus.test.js`, `phone.test.js`, e2e (revoke) |
| A revoked phone keeps reading | it no longer gets in at the relay (its token is dropped) and the shared read token and status key were replaced; Miblo+ frames were never readable by it after the revoke | web `relay.test.ts`, plugin `plus.test.js`, e2e |
| The bridge stops between `/health` and a request, and another local user answers on its port ("allow") | every answer to a signed request is MACed with the bridge key over the challenge, status and body; an unverified answer is ignored (Claude Code asks locally) | plugin `bridge-auth.test.js` |
| Another local user reads the day's stats, limits or log | the data folder is 0700 and its files 0600, tightened at every bridge start | plugin `bridge.test.js` |
| (v5 only) Pairing QR code or link leaks | v6 has no QR code or link: the keys reach phones only sealed to their own public keys in account grants; the first v6 run replaced the read token and status key, so old links and QR codes open nothing | plugin `account-phones.test.js` (migration) |
| Another local user exhausts the bridge's challenges | per-connection limits, a larger budget, short lives; the fallback is always Claude Code's own prompt | plugin `bridge-auth.test.js` |
| Another local user plants or reads pairing files | read only when owned by the user, narrowed to 0600, links not followed | plugin `plus.test.js` |
| Forged hook payload makes the bridge read another file | transcripts read only when their real path is a `.jsonl` under the harness's own folder | plugin `plus.test.js` |
| A free room abused for Miblo+ or many phones | the relay enforces the plan (4402) and one phone at a time (4406) | web `relay.test.ts`, e2e (upsell) |
| Flooding through the relay | per-channel caps (1009), per-second and per-minute `up` budgets (guests: enrollments only, 6 a minute), writer 2 frames/s | web `relay.test.ts` |
| An anonymous attacker (or a few paying accounts) spends the daily Web Push budget so nobody gets "needs you" | per-payer quotas (each Miblo+ account; each tier, /64, /56 and /48 or the IPv4 address, of the network that made a free room, with a small per-room fallback so neighbours behind one address cannot silence a room), at most 40 a day per endpoint in its one canonical spelling (no fragment, query, port or case variants) whatever the rooms, separate pools; rooms that never had a phone give their network the day's slot back and never count over the period (IPv4: 300 joined rooms a period, CGNAT); only accepted deliveries count; made-up keys refused; only fresh subscriptions of joined rooms; 2 (free) or 5 subscriptions a room; 10 new rooms a day per network (an IPv6 host by its /64) and 30 joined rooms a period; a warning in the logs at 80 % and when a pool runs out. Accepted residual (owner decision): each IPv6 /48 can spend at most 3 000 deliveries a day through its quota plus 3 000 through room fallbacks, and an IPv4 address 600 + 600; so about nine /48s (a few free tunnel-broker accounts) or about 42 IPv4 addresses, each with genuine endpoints, can still empty the 50 000-a-day free pool until midnight UTC. Miblo+ notifications (per-account quotas) are not affected, and approvals and replies keep working with the app open | web `relay.test.ts` |
| The server (or anyone with write access to the account's D1 rows) puts its own key in a waiting phone's place, so the computer seals the pairing to the server (v6, audit 1.21.0 finding 1) | the person types on the computer the 6-digit code the waiting phone shows; the code covers the phone's id and key, the computer's identity key and two nonces committed in turn, so a substituted key (or a ground nonce) matches only by chance (10^-6), one try per round, a wrong code turns the phone away; the phone also checks the commitment against its own key and warns | plugin `phone-trust.test.js` (swap, grinding, wrong code, shared vector), `phone.test.js` (CLI contract), web `phone-trust.test.ts`, `phones-api.test.ts` (round storage, once-only nonce), `scripts/plus-e2e.mjs` (code read on the phone, typed on the computer) |
| The server grinds the phone's code by flooding it with commitments of invented computers (v6, audit round 2) | the phone answers at most 3 new rounds an hour and one open round per computer, then warns ("Muitas tentativas de parear"); the computer opens at most 3 rounds per phone an hour and reveals its nonce once per round; the "Novo computador" card only for a code shown in the last 30 minutes whose computer did not refuse it | web `phone-grind.test.ts` (from the audit's `grind.test.ts`), plugin `phone-trust.test.js` |
| The server seals a grant of its own to the phone's key (a room, keys and MAC key it chose, any generation) (v6, audit finding 2; the audit's `forge.test.ts`) | every grant is signed with the computer's ECDSA identity key; the phone opens only grants signed by a computer it confirmed (pinned after it showed that computer's code and the person tapped "Sim, fui eu"), never an unsigned one, a copied signature or an unknown key; a room another key holds is never taken over; generations only move forward | plugin `phone-trust.test.js`, web `phone-trust.test.ts` (forged grant refused), e2e (new computer confirmed on the phone) |
| Another person signs in to miblo.ai in the same browser (or the owner signs out) and finds the previous account's pairings (v6, audit finding 3) | pairings carry the account uid and show only for it; signed out they are hidden; another account signing in deletes the previous one's pairings, keys and identities; signing out wipes the app's IndexedDB and storage | web `phone-trust.test.ts` (pairingsFor) |
| Someone holding the owner's unlocked phone opens the app and approves, replies, confirms a change or reads the sessions | the app lock (PIN): mandatory, asked on every open and after the idle time; nothing rendered and nothing sent while locked (`sendUp`, `answerCode`, `confirmComputer`, `askAgain` and the pairing answers check it, not only the screen); 5 wrong: 1-minute wait; 10 wrong (persisted across reloads): blocked on the phone, PIN hash deleted, account session ended on the server, `pin_lockout` notice (a log line on a self-hosted relay); back only by a full sign-in with the second factor and a new PIN. Residual: an attacker who reads the browser storage can brute-force the PIN offline or use the keys directly (it is not encryption) | web `pin-lock.test.ts` (rules, counters, reload, idle, send gates), `pin-lockout.test.ts` (sign-out route, notice once an hour, cross-site refused) |
| **Residual: the phone app's code is served by miblo.ai and trusted.** Whoever controls what miblo.ai serves (a compromised deploy, dependency or account on the hosting) runs code with the phone's keys: it can show a fake code, confirm a computer of its own, swap what one biometric signs, or read what the app decrypts while open | not preventable while the app is a web page (long term: an installed app with pinned code). What bounds it: the server alone (no code change) is held off by the code and the signed grants above; a code-level compromise still cannot act on the computer without the person's passkey for each action, cannot let a phone in without the person typing a code at the computer, and every allow, reply and task is shown on the computer (gadget, notification, audit log with the computer's own summary); approvals, replies and tasks are off until turned on at the desk with the gadget code; a strict CSP (scripts only from the site with a per-response nonce, plus Cloudflare's Turnstile and analytics; no inline handlers); the phone's private keys non-extractable CryptoKeys; the e2e check fails on any CSP violation | web `hardening.test.ts`, `scripts/plus-e2e.mjs` (CSP), plugin `plus.test.js` |
| A program on the computer edits `plus.json` to turn on approvals, replies or tasks, or adds a folder (audit finding 6) | the widening settings count only under an HMAC keyed by `plus-settings.key` (0600); an unsigned, edited or pre-1.21 file reads with all of them off until the person turns them on again with the gadget code (deleting the key never re-arms it); folders are checked again on every read (real path, directory, id, never the disk, home or above, a hidden home folder, app data such as `~/Library` or `%APPDATA%`, or a system tree), and a folder swapped between that check and the start of a task kills it at once. Residual: a process with the user's rights that reads the key; the few milliseconds between the start and the second check | plugin `plus-config-integrity.test.js` |
| The account server names a hostile page as the device-link page (audit finding 7) | only an https page on the account's exact origin is shown or opened, else the link page itself; the browser is opened without a shell (Windows: url.dll's handler, never `cmd /c start`) | plugin `open-url.test.js` |
| Sniffing the LAN gives the gadget token, or a captured request is replayed (audit finding 5) | firmware 1.21.0+: every request signed (HMAC over the gadget's boot id, a once-only counter, method, path and body hash); the snapshot and the personal bodies sealed (ChaCha20-Poly1305); the token never travels, and on the first signed session it is swapped (X25519) for one that never did, which is then refused as a bearer token; a gadget once seen with it never gets the token in clear. Residual: the gadget's answers and pet drawings are in clear on the LAN; a firmware before 1.21.0 still gets the bearer token | firmware `test_lanauth` (RFC 8439 vector, shared vector, replay, boot), fuzz `lanauth`; plugin `lan-auth.test.js` |
| Pairing vault or account taken over | see docs/miblo-plus.md, "Account security" and "Pairing vault": E2E vault keyed by passkey PRF, mandatory second factor, fresh checks, notices | web `account-security.test.ts`, `vault.test.ts`, e2e |
| Account takeover, or a compromised miblo.ai, adds a phone of its own (v6) | the phone gets nothing until the person allows it at the computer, typing the code that phone shows (Permitir in the desktop app, or `miblo phone approve --code` in their own terminal; never under an AI agent, a script or a multiplexer); the request shows name, browser, system and approximate place and expires in 15 minutes; denied or expired phones get nothing; a phone joins only an account with a second factor passed in the last 5 minutes and is emailed and listed; acting stays off until turned on at the desk with the gadget code; a revoke on the account or the computer cuts it off at once (4411, new status key, new grants for the others) | plugin `account-phones.test.js` (queued not admitted, expiry and ask again, deny, revoke from the account), `phone.test.js` (pending/approve/deny contract, refused contexts, terminal confirmation), web `phones-api.test.ts` (request states, ask again, fresh second factor, limit, email), `scripts/plus-e2e.mjs` (waiting on the phone, refused from an agent, allowed in the app) |
| A gadget (or something answering as one on the LAN) serves a hostile pet file (v6) | the request carries the paired computer's token; the file is capped by version (8192/4096 bytes) and validated with the firmware's own rules (checksum, every field, the MPET2 draw budget) on the computer and again by the renderer on the phone; the phone keeps it only under its SHA-256 and draws it in sandboxed WebAssembly that imports nothing; it travels sealed to each phone | plugin `miblo-mirror.test.js`, web `phone-pet-cache.test.ts`, `scripts/plus-e2e.mjs` |
| The account (or miblo.ai) swaps a waiting or allowed phone's public key (v6) | the request binds the phone id to the `pub` and passkey it was made with; `approve` re-reads the account and refuses another key (`key_changed`, request turned away); grants are sealed to the stored `pub` only; an admitted phone the account later lists with another key is revoked | plugin `account-phones.test.js`, `phone.test.js` |
| miblo.ai reads a phone's room key, read token or MAC key from the grants it stores (v6) | grants are ECDH-ES (P-256) + HKDF + AES-GCM to the phone's own key, whose private half is a non-extractable key on the phone; AAD binds phone, room and generation | plugin `account-phones.test.js`, web `phone-grant.test.ts` (shared vector, tampered and moved grants refused) |
| A forged or replayed phone registration (someone else's passkey, another phone's public key) (v6) | the computer checks the passkey registration against a challenge binding the phone id and its public key, rp `miblo.ai`, origin, UP and UV; a known id or credential is not admitted twice; a revoked id never again | plugin `account-phones.test.js` |
| Compromised origin, or a stolen unlocked phone, starts work on the computer through "Nova tarefa" (v6) | off by default and turned on only at the desk with the gadget code; a passkey assertion with UV over the tool, folder, text, nonce, time and a single-use token the computer issued; folders only from the computer's allow-list; the tool's safest mode (Claude Code's default mode with its prompts going to the phone's approvals and the rest denied, the folder's own settings and MCP servers not loaded; Codex read-only; Copilot read-only; Gemini CLI not offered); one task at a time, 10 an hour, a time limit; every task shown on the gadget, as a notification and in the audit log; `miblo plus remote off` and "Parar" stop it. Residual as for replies: a compromised origin can swap the text the person's biometric signs | plugin `tasks.test.js` (every refusal, passkey, replay, rate, time limit, stop, kill switch), web `phone-tasks.test.ts`, e2e (fake tools) |
| Command injection through a task's text, tool or folder (v6) | the computer builds the argv from a fixed table, runs it without a shell, passes the text on stdin (Copilot: as the value of `-p`), and names tools and folders by id only; the folder's real path is checked again before each run (a link swapped in is refused) | plugin `tasks.test.js` (shell metacharacters stay text, leading dashes, symlink escape, unknown ids) |
| A runaway or forgotten task keeps spending (v6) | time limit (default 30 min), output cap, one at a time, hourly and daily caps, "Parar", `miblo plus tasks stop`, `miblo plus remote off`; the process group is killed | plugin `tasks.test.js` |
| (1.26) An automatic task does damage: it runs Claude Code in `bypassPermissions`, so it can do everything Claude Code can do in that folder without asking (edit, delete, run commands, reach the network and whatever those reach with the person's rights) | off by default; on only from the person's terminal or the desktop app, confirmed on a phone, never under an AI agent; `mac3` over `tasksAuto`; each automatic task under its phone's MAC and passkey with `auto` itself signed; Claude Code only, allowed folders only, the time limit, one at a time, hourly and daily caps; "Parar", `tasks auto off` and `remote off` stop it; labelled automatic on the computer, the phone, the desktop app and the audit | plugin `tasks-auto.test.js`, web `phone-tasks-auto.test.ts` |
| Secrets in the conversation reach the phone (v6 history carries commands, outputs and diffs) | redaction (above) of whole texts after invisible characters are stripped: key blocks, known token shapes, auth and cookie headers, quoted and unquoted values of secret-named keys in env, JSON, YAML, code and flags, CLI password flags, URL credentials, long high-entropy strings; also the snapshot's tool detail and the task audit log; outputs are short tails of commands only; thinking and subagents never. Residual: a secret with no recognisable name, shape or entropy (a short dictionary word as a password in prose) | plugin `redact.test.js`, `redact-audit.test.js` (the audit corpus, a corpus of ordinary code that must pass unchanged), `history.test.js` |
| Markdown in an AI message injects markup, loads a tracking image or hides a phishing link (v6) | React-only renderer, no HTML; images never loaded; links only http(s), shown with their domain and opened after a tap that shows the whole address | web `chat-markdown.test.tsx`, e2e (`<img onerror>` and `![x](https://…)` stay text) |
| Secrets in logs | the plugin never logs tokens, keys or message text; the audit log keeps hashes, a short summary and phone ids | plugin `plus.test.js` |
| (v7) The server (or a MITM) plays the new phone towards the computer, knowing everything that travels | the computer shows the code and the phone types it into a CPace-style PAKE bound to both public keys and the attempt: nothing relayed reveals the code; one online guess per attempt (10^-6), 3 attempts, then denied; the computer's `conf` in the first grant pins it on the phone | plugin `phone-trust.test.js`, `account-phones.test.js` (shared `plus-v7-vector.json`), relay `test/pake.test.ts`, `test/api.test.ts`, `test/e2e/plugin.test.ts` |
| (v7) An AI agent turns approvals, replies, history or tasks on, adds a folder or a second phone | the change waits for a confirmation on a phone the computer already has: the code shown on the computer typed there, a proof under that phone's MAC key, the passkey with UV over `cap`; 3 wrong cancel, 6 requests an hour, one at a time; desktop browsers refused | plugin `plus.test.js`, `phone.test.js` |
| (v7) Account takeover (recovery code or a passkey of the attacker's) | on miblo.ai every use of a recovery code, failed attempts (at most hourly) and every new passkey send the security notice e-mail; a self-hosted server has no e-mail and logs these events (`account_security`) instead; either way a new phone still gets nothing without the code shown on the computer | relay `test/api.test.ts` (the code path) |
| (v8) A compromised phone app or a stolen unlocked phone uses the panic button to end the person's sessions, or someone turns the bridge back on from afar | a panic needs an enrolled phone's MAC key and its passkey with user verification over a fresh nonce and time, checked like a reply; it can only end sessions and lock, never start anything; turning the bridge back on is only at the computer (desktop app, or `miblo panic clear` refused under an AI agent), never a frame. Residual: a panic is a denial of service by design: whoever passes the phone's biometric can end the sessions | plugin `panic.test.js` (MAC, no UV, other challenge, stale, replay, other phone, the lock in hooks, CLI, status line and bridge start, clear refused under an agent), web `phone-panic.test.ts` (shared vector, hold, flow) |

## Self-hosted servers

A self-hosted Miblo relay implements every endpoint above with the same paths and shapes, so the
plugin and the phone app need nothing but a different origin:

- The plugin is pointed at it with `miblo server set https://relay.example.com` (behind the
  gadget's code). Relay (`wss://<host>/api/relay`), account API (`https://<host>/api/plus/*`), phone
  registry (`/api/phones*`) and the phone app (`https://<host>/app`) all follow; the passkeys of the
  phone app are made for, and checked against, the relying party `<host>`.
- **Server identity (trust on first use).** `GET /.well-known/miblo-relay.json` →
  `{v: 1, kind: "miblo-relay", origin, key, fingerprint, version, protocol}`: `key` is the server's
  Ed25519 public key (raw, base64url). `POST /api/server/identity {nonce}` → `{sig}`, the Ed25519
  signature of `"miblo-relay-identity-v1|" + origin + "|" + nonce`. `miblo server set` checks that
  `origin` is exactly the address typed, that the server signs a fresh nonce with `key`, shows the
  fingerprint (SHA-256 of the raw key, first 20 bytes, five groups of eight hex digits) and pins
  the key in `<data>/server.json` (MAC'd under the plugin's settings key). Before any account or relay
  call the plugin asks for a fresh signature again (at most every 30 minutes); a server that cannot
  produce it gets nothing.
- **One account.** The server has a single account, created with an operator-held setup token
  (`/api/setup`), signed in with a password (`POST /api/community/auth/password`) or a passkey alone
  (`/api/community/auth/passkey/*`), and a second factor is mandatory before anything else works
  (the same `/api/community/mfa*` API as miblo.ai). The account page is at `/conta` (and
  `/en/account`); the device-link page is `/plus/link` on the server's own origin.
- **No plans.** Every room a linked computer registers gets the `plus` plan with no end
  (`valid_until: null`), so history, replies, approvals and remote tasks work without a license.
  Rooms no computer registered keep the free-room limits above.
- **No e-mail.** The account has a username, not an e-mail: `/api/plus/me` and the device token
  answer `email: null` (the desktop app then shows no "Conectado como"), and the security notices
  miblo.ai e-mails (a recovery code used, failed recovery-code attempts, a new passkey or phone)
  are written to the server's log as `{"event":"account_security"}` lines instead.
- **Push.** Alerts are signed with the operator's own VAPID keys (`GET /api/relay/vapid`); the
  subject is `RELAY_VAPID_SUBJECT` or the server's origin.
