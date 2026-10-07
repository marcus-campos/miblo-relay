// The look's share code, as the Miblo settings page's "Copy my Miblo" button makes it (firmware:
// miblo_lookcode.h, the format's reference). "MIBLO1:" + base64url (no padding) of:
//   [0] pet  [1] mascot (preset)  [2] petEyes  [3] accHead  [4] accFace  [5] accNeck
//   [6] custom-colour mask (bit i = slot i has its own colour; bit 7 always 0)
//   then R, G, B for each slot in the mask, slot 0 first.
// Decoding is strict, exactly like the firmware's: anything else is refused with a reason. Only
// surrounding whitespace (a paste's trailing newline) is forgiven, nothing inside the code.
import { LOOK_CODE, isLook, isEyes, isPet, isPreset, fitsSlot, SLOTS, type Look } from "./miblo-look";

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const MASK_BITS = SLOTS.length; // 7 colour slots

export type LookCodeError =
  | "empty" // nothing pasted
  | "prefix" // not a Miblo code (or another version of the format)
  | "length" // too short, too long or cut off
  | "characters" // something that is not base64url
  | "pet" // unknown pet (13 never is one)
  | "preset"
  | "eyes"
  | "wear" // an unknown accessory or one in the wrong slot
  | "colors"; // the colour mask does not match the colours that follow

export type LookCodeResult = { ok: true; look: Look } | { ok: false; error: LookCodeError };

/** The share code for `look`; null if the settings page could not hold it. */
export function encodeLookCode(look: Look): string | null {
  if (!isLook(look)) return null;
  const bytes = [look.pet, look.mascot, look.eyes, look.head, look.face, look.neck, 0];
  look.colors.forEach((c, i) => {
    if (!c) return;
    bytes[6] |= 1 << i;
    for (let j = 0; j < 6; j += 2) bytes.push(parseInt(c.slice(j, j + 2), 16));
  });
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const n = bytes.length - i;
    const v = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += B64[(v >> 18) & 63] + B64[(v >> 12) & 63];
    if (n > 1) out += B64[(v >> 6) & 63];
    if (n > 2) out += B64[v & 63];
  }
  return LOOK_CODE.prefix + out;
}

/** The look in a pasted code, or why it is not one. */
export function decodeLookCode(input: string): LookCodeResult {
  const fail = (error: LookCodeError): LookCodeResult => ({ ok: false, error });
  const code = input.trim();
  if (!code) return fail("empty");
  if (!code.startsWith(LOOK_CODE.prefix)) return fail("prefix");
  const s = code.slice(LOOK_CODE.prefix.length);
  const maxChars = Math.ceil((LOOK_CODE.maxBytes * 4) / 3);
  if (s.length < 10 || s.length > maxChars || s.length % 4 === 1) return fail("length");
  const bytes: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const ch of s) {
    const v = B64.indexOf(ch);
    if (v < 0) return fail("characters");
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((acc >> bits) & 255);
      acc &= (1 << bits) - 1;
    }
  }
  if (acc !== 0) return fail("characters"); // non-canonical: unused low bits set
  const [pet, mascot, eyes, head, face, neck, mask] = bytes;
  if (!isPet(pet)) return fail("pet");
  if (!isPreset(mascot)) return fail("preset");
  if (!isEyes(eyes)) return fail("eyes");
  if (!fitsSlot("head", head) || !fitsSlot("face", face) || !fitsSlot("neck", neck)) return fail("wear");
  if (mask >> MASK_BITS) return fail("colors");
  let custom = 0;
  for (let i = 0; i < MASK_BITS; i++) custom += (mask >> i) & 1;
  if (bytes.length !== 7 + 3 * custom) return fail("colors");
  let at = 7;
  const hex = (b: number) => b.toString(16).padStart(2, "0");
  const colors = Array.from({ length: MASK_BITS }, (_, i) => {
    if (!((mask >> i) & 1)) return "";
    const c = hex(bytes[at]) + hex(bytes[at + 1]) + hex(bytes[at + 2]);
    at += 3;
    return c;
  });
  return { ok: true, look: { pet, mascot, eyes, head, face, neck, colors } };
}
