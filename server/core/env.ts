// What every part of the server is given: the database, the relay rooms, the configuration and the
// secrets. Both runtimes provide it: Cloudflare Workers (D1 + Durable Objects, server/worker) and
// Node (SQLite + in-process rooms, server/node). Nothing here talks to anything but the operator's
// own server and the browsers' push services.

/** The subset of Cloudflare D1's API the server uses (the Node runtime implements it over SQLite). */
export type D1Result<T = Record<string, unknown>> = { results: T[]; success: boolean; meta: { changes: number; last_row_id?: number } };
export interface D1Statement {
  bind(...values: unknown[]): D1Statement;
  first<T = Record<string, unknown>>(column?: string): Promise<T | null>;
  all<T = Record<string, unknown>>(): Promise<D1Result<T>>;
  run(): Promise<D1Result>;
}
export interface Db {
  prepare(sql: string): D1Statement;
  batch(statements: D1Statement[]): Promise<D1Result[]>;
}

/** A relay room's address and the object behind it (a Durable Object stub, or the Node room). */
export interface RoomStub {
  fetch(input: string | Request, init?: RequestInit): Promise<Response>;
}
export interface RoomNamespace {
  idFromName(name: string): unknown;
  get(id: unknown): RoomStub;
}

export type Env = {
  DB: Db;
  RELAY: RoomNamespace;
  /**
   * The one origin this server answers as ("https://relay.example.com"): the phone app's origin, the
   * passkeys' relying party (its host), the device-link page's address. Never taken from a request.
   */
  PUBLIC_ORIGIN: string;
  /** Signs session cookies, CSRF tokens and challenges (32+ characters). */
  SESSION_SECRET: string;
  /** 32 random bytes (base64url): TOTP secrets at rest and recovery codes. */
  MFA_KEY: string;
  /** The server's identity key: an Ed25519 private key, PKCS#8, base64url (see identity.ts). */
  SERVER_IDENTITY_KEY: string;
  /** One-time token that creates the admin account; refused once the account exists. */
  SETUP_TOKEN?: string;
  /** The operator's own VAPID keys (push alerts); without them the phones get no alerts. */
  RELAY_VAPID_PUBLIC_KEY?: string;
  RELAY_VAPID_PRIVATE_KEY?: string;
  /** "mailto:you@example.com" or an https URL of the operator (sent to the push services). */
  RELAY_VAPID_SUBJECT?: string;
  /** Optional key of the relay's daily network hashes (else derived from the VAPID key). */
  RELAY_IP_KEY?: string;
  /** "1": the client address is the first X-Forwarded-For entry (behind your own reverse proxy). */
  TRUSTED_PROXY?: string;
  /** "1": development (http on localhost allowed). Never in production. */
  MIBLO_RELAY_DEV?: string;
};

export type RequestScope = { env: Env; dev: boolean; waitUntil: (p: Promise<unknown>) => void };

export function scopeOf(env: Env, waitUntil: (p: Promise<unknown>) => void = () => {}): RequestScope {
  return { env, dev: env.MIBLO_RELAY_DEV === "1", waitUntil };
}
