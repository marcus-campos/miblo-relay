// My pet's file on the phone (protocol v6, "My pet on the phone"): the computer names the pet a
// Miblo runs by the SHA-256 of its file (the snapshot's `miblos[].pet`) and sends the file itself
// apart, once, sealed to this phone (a status-channel frame {v:6, kind:"pet", hash, file}). Kept here
// by that hash (in memory and, best effort, in localStorage, a few files at most), so the card draws
// the pet at once next time. A file is kept only when its bytes hash to the name it came with and it
// fits the firmware's cap; the firmware's own validation runs when it is drawn (look-renderer.ts
// loadPet), and a refused file falls back to the resting eyes.
import { useSyncExternalStore } from "react";
import { b64url, fromB64url } from "@/lib/relay-crypto";

export const PET_FILE_MAX = 8192;
const HASH_RE = /^[A-Za-z0-9_-]{43}$/;
const KEEP = 6;
const KEY = "miblo-pet:";
const INDEX = "miblo-pets";

const files = new Map<string, Uint8Array>();
const listeners = new Set<() => void>();

const isHash = (h: unknown): h is string => typeof h === "string" && HASH_RE.test(h);

function storedIndex(): string[] {
  try {
    const v = JSON.parse(localStorage.getItem(INDEX) ?? "[]") as unknown;
    return Array.isArray(v) ? v.filter(isHash) : [];
  } catch {
    return [];
  }
}

function store(hash: string, bytes: Uint8Array): void {
  try {
    const index = [...storedIndex().filter((h) => h !== hash), hash];
    while (index.length > KEEP) localStorage.removeItem(KEY + index.shift());
    localStorage.setItem(KEY + hash, b64url(bytes));
    localStorage.setItem(INDEX, JSON.stringify(index));
  } catch {
    // Private mode or full: memory only.
  }
}

/** The pet file named `hash`, when this phone has it. */
export function petFile(hash: string | null): Uint8Array | null {
  if (!isHash(hash)) return null;
  const had = files.get(hash);
  if (had) return had;
  try {
    const s = localStorage.getItem(KEY + hash);
    const bytes = s ? fromB64url(s) : null;
    if (bytes && bytes.length <= PET_FILE_MAX) {
      files.set(hash, bytes);
      return bytes;
    }
  } catch {
    // Not available.
  }
  return null;
}

/** A "pet" frame from the computer (sealed to this phone): kept when its file is the one it names. -> whether it was one. */
export async function acceptPetFrame(payload: unknown): Promise<boolean> {
  if (!payload || typeof payload !== "object") return false;
  const p = payload as { kind?: unknown; hash?: unknown; file?: unknown };
  if (p.kind !== "pet") return false;
  if (!isHash(p.hash) || typeof p.file !== "string" || p.file.length > Math.ceil((PET_FILE_MAX * 4) / 3) + 4) return true;
  let bytes: Uint8Array;
  try {
    bytes = fromB64url(p.file);
  } catch {
    return true;
  }
  if (!bytes.length || bytes.length > PET_FILE_MAX) return true;
  const digest = b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as Uint8Array<ArrayBuffer>)));
  if (digest !== p.hash) return true;
  if (!files.has(digest)) {
    files.set(digest, bytes);
    store(digest, bytes);
    listeners.forEach((l) => l());
  }
  return true;
}

function subscribe(l: () => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

/** The pet file named `hash` (re-renders when it arrives). */
export function usePetFile(hash: string | null): Uint8Array | null {
  return useSyncExternalStore(subscribe, () => petFile(hash), () => null);
}
