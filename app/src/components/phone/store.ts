// The phone's paired computers, in IndexedDB. Protocol v6: every pairing comes from an account
// grant (`acct`) and this phone's own identity for the account (its ECDH key, never extractable,
// its id and passkey) lives in the "identity" store; pairings from v5 QR codes are deleted.
// The pairing's frame key and this phone's own MAC key
// (Miblo+, v4) are stored as non-extractable CryptoKeys: page scripts can use them but can never
// read their bytes back. Pairings saved before v4 hold no phone identity: they keep working for the
// status, and Miblo+ actions ask to pair again (a new QR code from the computer).
import { fromB64url, importMacKey, importPairingKeys, type Pairing } from "@/lib/relay-crypto";

/** This phone's identity for one computer (docs/phone-relay-protocol.md v4, "Phones"). */
export type PhoneIdentity = { id: string; macKey: CryptoKey; credId: string; fp: string; at: number };

export type StoredPairing = {
  room: string;
  readToken: string;
  key: CryptoKey;
  name: string;
  addedAt: number;
  /** Set once this phone enrolled its passkey with the computer. */
  phone?: PhoneIdentity;
  /** The open pairing window's secret from the QR code, until this phone enrolled (single use, 10 min). */
  enroll?: { secret: string; at: number };
  /** The status key generation this pairing holds (a revoke on the computer moves it). */
  epoch?: number;
  /**
   * v6: it came from an account grant of this linked computer. `uid`: the account that made it
   * (only shown while that account is signed in; another account's are deleted); `cpub`: the
   * computer identity key that signed it (another key never replaces this room).
   */
  acct?: { device: string; uid?: string; cpub?: string };
};

/** A computer this phone confirmed (it showed its code, and the person confirmed it here). */
export type Pin = { cpub: string; device: string; name: string; at: number };
/** One round of the code exchange with one computer (protocol v6 "Verifying a new phone"). */
export type SasRound = { device: string; commit: string; cpub: string; pnonce: string; at: number; nonce?: string; code?: string; revealedAt?: number; denied?: boolean };

/** v6: this phone's identity in one account (one per account and browser). */
export type AccountIdentity = {
  uid: string;
  id: string;
  name: string;
  /** The ECDH P-256 private key grants are sealed to (non-extractable). */
  priv: CryptoKey;
  pub: string;
  /** This phone's passkey (null: the device has none; view only). */
  credId: string | null;
  at: number;
  /** The account accepted it (POST /api/phones). */
  registered: boolean;
  /** The computers this phone confirmed: grants are accepted only when one of them signed. */
  pins?: Pin[];
  /** The code exchanges in progress (this phone's nonce per commitment, and the code once shown). */
  rounds?: SasRound[];
};

/** The pairing window lasts 10 minutes on the computer (plugin lib/plus/phones.js WINDOW_MS). */
export const ENROLL_WINDOW_MS = 10 * 60 * 1000;

/** The pairing can send frames (saved by a Miblo+-aware app). */
export function canSend(p: StoredPairing): boolean {
  return p.key.usages.includes("encrypt");
}

/**
 * This phone may act on the computer (approve, deny, reply): it enrolled, and the computer still
 * lists it (`phones` from the status frame; a revoked phone is no longer there).
 */
export function plusReady(p: StoredPairing, phones: string[] | null | undefined): boolean {
  return canSend(p) && !!p.phone && !!phones?.includes(p.phone.id);
}

const DB_NAME = "miblo-phone";
const STORE = "pairings";
const IDENTITY = "identity";

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 2);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE, { keyPath: "room" });
      if (!req.result.objectStoreNames.contains(IDENTITY)) req.result.createObjectStore(IDENTITY, { keyPath: "uid" });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function run<T>(mode: IDBTransactionMode, fn: (store: IDBObjectStore) => IDBRequest<T>, name = STORE): Promise<T> {
  const db = await openDb();
  try {
    return await new Promise<T>((resolve, reject) => {
      const tx = db.transaction(name, mode);
      const req = fn(tx.objectStore(name));
      tx.oncomplete = () => resolve(req.result);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

export async function listPairings(): Promise<StoredPairing[]> {
  const all = await run<StoredPairing[]>("readonly", (s) => s.getAll() as IDBRequest<StoredPairing[]>);
  return all.sort((a, b) => a.addedAt - b.addedAt);
}

/**
 * Saves (or refreshes) a pairing read from a link or QR code. A new window secret replaces the old
 * one; this phone's identity is kept while the pairing (room and key) stays the same.
 */
export async function savePairing(p: Pairing, now = Date.now()): Promise<StoredPairing> {
  const existing = await run<StoredPairing | undefined>("readonly", (s) => s.get(p.room) as IDBRequest<StoredPairing | undefined>);
  const keys = await importPairingKeys(p.key);
  const record: StoredPairing = {
    room: p.room,
    readToken: p.readToken,
    key: keys.key,
    name: p.name,
    addedAt: existing?.addedAt ?? now,
    ...(existing?.phone && existing.readToken === p.readToken ? { phone: existing.phone } : {}),
    ...(p.enroll ? { enroll: { secret: p.enroll, at: now } } : {}),
  };
  await run("readwrite", (s) => s.put(record));
  return record;
}

/** Changes one pairing's Miblo+ fields (its identity once enrolled; the window secret spent). */
export async function updatePairing(room: string, patch: Partial<Pick<StoredPairing, "phone" | "enroll">>): Promise<StoredPairing | null> {
  const existing = await run<StoredPairing | undefined>("readonly", (s) => s.get(room) as IDBRequest<StoredPairing | undefined>);
  if (!existing) return null;
  const next: StoredPairing = { ...existing, ...patch };
  for (const k of Object.keys(patch) as (keyof typeof patch)[]) if (patch[k] === undefined) delete next[k];
  await run("readwrite", (s) => s.put(next));
  return next;
}

/**
 * The computer replaced the pairing's read token and status key (a phone was revoked) and sent the
 * new ones sealed to this phone: they replace the old ones; this phone's identity stays.
 */
export async function rekeyPairing(room: string, readToken: string, key: string, epoch: number): Promise<StoredPairing | null> {
  const existing = await run<StoredPairing | undefined>("readonly", (s) => s.get(room) as IDBRequest<StoredPairing | undefined>);
  // Only forward: an older (replayed) or the same generation changes nothing.
  if (!existing || epoch <= (existing.epoch ?? 0) || existing.readToken === readToken) return null;
  const next: StoredPairing = { ...existing, readToken, key: (await importPairingKeys(key)).key, epoch };
  await run("readwrite", (s) => s.put(next));
  return next;
}

export async function removePairing(room: string): Promise<void> {
  await run("readwrite", (s) => s.delete(room));
}

// --- v6: the account identity and pairings from grants ------------------------------------------

export async function loadIdentity(uid: string): Promise<AccountIdentity | null> {
  return (await run<AccountIdentity | undefined>("readonly", (s) => s.get(uid) as IDBRequest<AccountIdentity | undefined>, IDENTITY)) ?? null;
}

export async function saveIdentity(id: AccountIdentity): Promise<void> {
  await run("readwrite", (s) => s.put(id), IDENTITY);
}

export async function deleteIdentity(uid: string): Promise<void> {
  await run("readwrite", (s) => s.delete(uid), IDENTITY);
}

/** Deletes every pairing that did not come from the account (v5 QR codes and links). -> how many. */
export async function purgeLegacy(): Promise<number> {
  const all = await listPairings();
  const old = all.filter((p) => !p.acct);
  for (const p of old) await removePairing(p.room);
  return old.length;
}

/**
 * Saves (or refreshes) the pairing an account grant gave: the status key and this phone's MAC key
 * as non-extractable CryptoKeys. A grant of an older generation than the one held changes nothing.
 */
export async function savePairingFromGrant(
  g: { room: string; readToken: string; key: string; macKey: string; epoch: number; name: string },
  who: { id: string; credId: string | null; uid: string },
  device: string,
  cpub: string,
  now = Date.now(),
): Promise<StoredPairing | null> {
  const existing = await run<StoredPairing | undefined>("readonly", (s) => s.get(g.room) as IDBRequest<StoredPairing | undefined>);
  // A room another computer key (or another account) holds is never taken over by a grant.
  if (existing?.acct && ((existing.acct.cpub && existing.acct.cpub !== cpub) || (existing.acct.uid && existing.acct.uid !== who.uid))) return null;
  if (existing?.acct && (existing.epoch ?? 0) >= g.epoch && existing.readToken === g.readToken && existing.phone?.id === who.id) return null;
  if (existing?.acct && (existing.epoch ?? 0) > g.epoch) return null;
  const keys = await importPairingKeys(g.key);
  const record: StoredPairing = {
    room: g.room,
    readToken: g.readToken,
    key: keys.key,
    name: g.name,
    addedAt: existing?.addedAt ?? now,
    phone: { id: who.id, macKey: await importMacKey(fromB64url(g.macKey)), credId: who.credId ?? "", fp: "", at: existing?.phone?.at ?? now },
    epoch: g.epoch,
    acct: { device, uid: who.uid, cpub },
  };
  await run("readwrite", (s) => s.put(record));
  return record;
}

/** Every account identity kept in this browser (one per account that joined here). */
export async function listIdentities(): Promise<AccountIdentity[]> {
  return run<AccountIdentity[]>("readonly", (s) => s.getAll() as IDBRequest<AccountIdentity[]>, IDENTITY);
}
