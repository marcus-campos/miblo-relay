-- The self-hosted Miblo relay's database (Cloudflare D1, or SQLite on Node). TEXT ids, ISO-8601
-- UTC TEXT times. No secret is stored in clear: the password as PBKDF2, session ids and device
-- tokens as SHA-256, passkeys as their public key, TOTP secrets AES-GCM encrypted under MFA_KEY,
-- recovery codes as HMACs. Grants are ciphertext the server cannot open.

-- The one account of this server.
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  lang TEXT NOT NULL DEFAULT 'pt',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- Sessions (revocable): the cookie carries the id and an HMAC; only the id's SHA-256 is here.
-- mfa_at/mfa_method/mfa_cred: when and how this session last passed the second factor.
CREATE TABLE sessions (
  id_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  user_agent TEXT NOT NULL DEFAULT '',
  mfa_at TEXT,
  mfa_method TEXT,
  mfa_cred TEXT
);
CREATE INDEX sessions_user ON sessions (user_id);

-- Passkeys (WebAuthn, user verification required). id = the credential id (base64url).
CREATE TABLE mfa_passkeys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  name TEXT NOT NULL,
  alg INTEGER NOT NULL,
  public_key TEXT NOT NULL,
  sign_count INTEGER NOT NULL DEFAULT 0,
  prf INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  last_used_at TEXT
);
CREATE INDEX mfa_passkeys_user ON mfa_passkeys (user_id);

-- TOTP (RFC 6238, SHA-1, 6 digits, 30 s). confirmed_at null: not a factor yet.
CREATE TABLE mfa_totp (
  user_id TEXT PRIMARY KEY REFERENCES users(id),
  secret_ct TEXT NOT NULL,
  confirmed_at TEXT,
  last_step INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE mfa_recovery_codes (
  user_id TEXT NOT NULL REFERENCES users(id),
  code_hash TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY (user_id, code_hash)
);

-- WebAuthn challenges: SHA-256 of the challenge, single use, 5 minutes, for one session.
CREATE TABLE mfa_challenges (
  challenge_hash TEXT PRIMARY KEY,
  session_hash TEXT NOT NULL,
  user_id TEXT NOT NULL,
  purpose TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX mfa_challenges_session ON mfa_challenges (session_hash);

-- Failed attempts per account ("<user id>" for the second factor, "pw:<user id>" for the password).
CREATE TABLE mfa_failures (
  user_id TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  window_start TEXT NOT NULL,
  locked_until TEXT
);

-- Device authorisation codes (`miblo account link`). Only the device code's SHA-256 is stored.
-- net_hash: a keyed hash of the requesting network (bounds live codes per network), never an IP.
CREATE TABLE plus_device_codes (
  device_code_hash TEXT PRIMARY KEY,
  user_code TEXT NOT NULL,
  status TEXT NOT NULL,
  name TEXT NOT NULL,
  platform TEXT NOT NULL,
  user_id TEXT REFERENCES users(id),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_poll_at TEXT,
  net_hash TEXT,
  country TEXT,
  viewer_user_id TEXT
);
CREATE INDEX plus_device_codes_user_code ON plus_device_codes (user_code, expires_at);
CREATE INDEX plus_device_codes_expires ON plus_device_codes (expires_at);
CREATE INDEX plus_device_codes_net ON plus_device_codes (net_hash, expires_at);
CREATE UNIQUE INDEX plus_device_codes_pending_user_code ON plus_device_codes (user_code) WHERE status = 'pending';

-- Linked computers. Only the token's SHA-256 is stored; revoked rows stay so a stolen token keeps failing.
CREATE TABLE plus_devices (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  kind TEXT NOT NULL DEFAULT 'computer',
  name TEXT NOT NULL,
  platform TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  last_seen_at TEXT,
  revoked_at TEXT
);
CREATE INDEX plus_devices_user ON plus_devices (user_id, revoked_at);

-- Relay rooms registered by a linked computer (proof of the room's write token checked by the room).
CREATE TABLE plus_rooms (
  room TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES plus_devices(id),
  user_id TEXT NOT NULL REFERENCES users(id),
  applied_plan TEXT NOT NULL DEFAULT 'free',
  applied_until TEXT,
  synced_at TEXT,
  sync_error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX plus_rooms_device ON plus_rooms (device_id);
CREATE INDEX plus_rooms_user ON plus_rooms (user_id);

-- Protocol v6: the phones of the account (pub: ECDH P-256 public key; att/cdj: its passkey
-- registration, checked by each computer, never by the server; model: browser and system from
-- its User-Agent, shown to the person; revoked rows listed 90 days so the computers revoke too).
CREATE TABLE account_phones (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  name TEXT NOT NULL,
  pub TEXT NOT NULL,
  att TEXT,
  cdj TEXT,
  model TEXT,
  place TEXT,
  created_at TEXT NOT NULL,
  asked_at TEXT,
  revoked_at TEXT
);
CREATE INDEX account_phones_user ON account_phones (user_id, revoked_at);

-- What one computer sealed to one phone (ciphertext only) and its signature.
CREATE TABLE phone_grants (
  device_id TEXT NOT NULL REFERENCES plus_devices(id),
  phone_id TEXT NOT NULL REFERENCES account_phones(id),
  room TEXT NOT NULL,
  epoch INTEGER NOT NULL,
  epk TEXT NOT NULL,
  iv TEXT NOT NULL,
  ct TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  cpub TEXT,
  sig TEXT,
  PRIMARY KEY (device_id, phone_id)
);
CREATE INDEX phone_grants_phone ON phone_grants (phone_id);

-- Where the person's confirmation of a new phone stands on one computer, and the round of the
-- 6-digit code exchange (commitment, computer key, both nonces).
CREATE TABLE phone_requests (
  device_id TEXT NOT NULL REFERENCES plus_devices(id),
  phone_id TEXT NOT NULL REFERENCES account_phones(id),
  state TEXT NOT NULL,
  expires_at TEXT,
  updated_at TEXT NOT NULL,
  commit_h TEXT,
  cpub TEXT,
  pnonce TEXT,
  cnonce TEXT,
  PRIMARY KEY (device_id, phone_id)
);
CREATE INDEX phone_requests_phone ON phone_requests (phone_id);
