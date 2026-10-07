// A Miblo pet's look, in exactly the firmware's settings format. Every list and label comes from
// the firmware itself: generated/miblo-look-tables.json is written by the firmware's
// tools/lookweb/build.sh (claude_gadget repository: make look-publish WEB=<this web/ dir>) from the
// same tables and strings the gadget's settings page uses. Never edit it by hand.
// Config keys: pet, mascot, petColors ("rrggbb" or "" per slot, comma separated), petEyes,
// accHead, accFace, accNeck. 13 is never a pet nor an accessory. Shared by the browser and the server.
import tables from "./generated/miblo-look-tables.json";
import type { Locale } from "./i18n";

type Named = { id: number; pt: string; en: string };
export type WearSlot = "head" | "face" | "neck";

/**
 * The settings page's pet list, in its order (13 is never one). `body`: the pet's own Auto body
 * colour. "My pet" (21, the owner's own from Miblo Studio) is not a look: it travels as its own
 * file (lib/studio/mpet.ts), never in a look or a look code.
 */
export const PETS: (Named & { body: string | null })[] = tables.pets.filter((p) => !("custom" in p && p.custom));
/** The four colour presets (config "mascot") and their swatch colours. */
export const PRESETS: (Named & { rgb: string })[] = tables.presets;
/** Colour slots (miblo::PetSlot), in config order. */
export const SLOTS: Named[] = tables.slots;
export const EYES: Named[] = tables.eyes;
export const WEAR_SLOTS: WearSlot[] = ["head", "face", "neck"];
/** Accessories per slot, in the settings page's order. */
export const WEAR_BY_SLOT: Record<WearSlot, Named[]> = tables.wear;
export const WEAR: (Named & { slot: WearSlot })[] = WEAR_SLOTS.flatMap((slot) => WEAR_BY_SLOT[slot].map((w) => ({ ...w, slot })));

/** The settings page's own words for the pet card (section title, field labels, None, Auto...). */
export const LOOK_LABELS: Record<keyof typeof tables.labels, { pt: string; en: string }> = tables.labels;
export const WEAR_SLOT_NAMES: Record<WearSlot, { pt: string; en: string }> = {
  head: LOOK_LABELS.head,
  face: LOOK_LABELS.face,
  neck: LOOK_LABELS.neck,
};
export const AUTO = LOOK_LABELS.auto;
export const NONE = LOOK_LABELS.none;

/** The firmware version the tables and the renderer were built from, and the renderer's URL. */
export const LOOK_FIRMWARE: string = tables.firmware;
export const LOOK_WASM: string = tables.wasm;
/** The share code's prefix ("MIBLO1:") and largest payload, as the firmware defines them. */
export const LOOK_CODE: { prefix: string; maxBytes: number } = tables.code;

export type Look = {
  pet: number;
  mascot: number;
  /** Seven entries, "rrggbb" (lowercase) or "" for Auto. */
  colors: string[];
  eyes: number;
  head: number;
  face: number;
  neck: number;
};

export const DEFAULT_LOOK: Look = { pet: 0, mascot: 0, colors: ["", "", "", "", "", "", ""], eyes: 0, head: 0, face: 0, neck: 0 };

export const isPet = (v: number) => PETS.some((p) => p.id === v);
/** "My pet" (Miblo Studio): a gadget may run it, never a look. */
export const MY_PET = tables.studio.pet;
export const MY_PET_NAME: { pt: string; en: string } = tables.studio.name;
/** Any pet a gadget may be showing, My pet included. */
export const isGadgetPet = (v: number) => isPet(v) || v === MY_PET;
/** A pet's name, My pet included. */
export const petName = (id: number, lang: Locale) => (id === MY_PET ? MY_PET_NAME[lang] : nameOf(PETS, id, lang));
export const isPreset = (v: number) => PRESETS.some((p) => p.id === v);
export const isEyes = (v: number) => EYES.some((e) => e.id === v);
export const fitsSlot = (slot: WearSlot, id: number) => id === 0 || WEAR_BY_SLOT[slot].some((w) => w.id === id);
export const isHex = (v: string) => /^[0-9a-f]{6}$/.test(v);

/** A look the settings page could save: every id known and in its slot, seven colours. */
export function isLook(l: Look): boolean {
  return (
    isPet(l.pet) &&
    isPreset(l.mascot) &&
    isEyes(l.eyes) &&
    fitsSlot("head", l.head) &&
    fitsSlot("face", l.face) &&
    fitsSlot("neck", l.neck) &&
    l.colors.length === SLOTS.length &&
    l.colors.every((c) => c === "" || isHex(c))
  );
}

export function nameOf(list: Named[], id: number, lang: Locale): string {
  return list.find((x) => x.id === id)?.[lang] ?? "";
}

/** The config's petColors string from the slots ("f55110,,,,,,"). */
export function encodeColors(colors: string[]): string {
  return Array.from({ length: 7 }, (_, i) => (isHex(colors[i] ?? "") ? colors[i] : "")).join(",");
}

export function decodeColors(value: string): string[] {
  const parts = value.split(",");
  return Array.from({ length: 7 }, (_, i) => {
    const c = (parts[i] ?? "").trim().toLowerCase();
    return isHex(c) ? c : "";
  });
}

/**
 * The swatch colour of a preset for a pet, as the settings page paints it: on the first preset a
 * pet with a classic colour of its own shows that one (the capybara is brown there).
 */
export function presetColor(mascot: number, pet: number): string {
  const own = mascot === 0 ? PETS.find((p) => p.id === pet)?.body : null;
  return own || PRESETS.find((p) => p.id === mascot)?.rgb || PRESETS[0].rgb;
}

/** The body colour the look shows: the custom body slot, or its preset's swatch. */
export function bodyColor(look: Pick<Look, "mascot" | "colors" | "pet">): string {
  return look.colors[0] || presetColor(look.mascot, look.pet);
}

/** What to set on the Miblo settings page, field by field, in the page's own words and order. */
export function lookInstructions(look: Look, lang: Locale): { label: string; value: string }[] {
  const auto = AUTO[lang];
  const none = NONE[lang];
  const wear = (id: number) => (id ? nameOf(WEAR, id, lang) : none);
  return [
    { label: LOOK_LABELS.pet[lang], value: nameOf(PETS, look.pet, lang) },
    { label: LOOK_LABELS.eyes[lang], value: nameOf(EYES, look.eyes, lang) },
    ...WEAR_SLOTS.map((s) => ({ label: WEAR_SLOT_NAMES[s][lang], value: wear(look[s]) })),
    { label: LOOK_LABELS.mascot[lang], value: nameOf(PRESETS, look.mascot, lang) },
    ...SLOTS.map((s) => ({ label: s[lang], value: look.colors[s.id] ? `#${look.colors[s.id]}` : auto })),
  ];
}

/** The same values as the settings page's config keys (for people who use the API or a script). */
export function lookConfig(look: Look): Record<string, number | string> {
  return {
    pet: look.pet,
    mascot: look.mascot,
    petColors: encodeColors(look.colors),
    petEyes: look.eyes,
    accHead: look.head,
    accFace: look.face,
    accNeck: look.neck,
  };
}
