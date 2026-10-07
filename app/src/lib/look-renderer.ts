// The Miblo's own pet drawing in the browser: the firmware's renderer compiled to WebAssembly
// (claude_gadget: firmware/tools/lookweb), pixel for pixel what the gadget's settings preview shows
// on its 240 x 240 screen. Browser only. The module is fetched once (a versioned file, cached for
// good) and shared by every <MibloScreen> on the page.
//
// It needs 'wasm-unsafe-eval' in the page's script-src (server/security-headers.ts): that allows
// compiling WebAssembly and nothing else (no eval, no inline scripts).
import { LOOK_WASM, isLook, type Look } from "./miblo-look";

export const SCREEN = 240;
/** The preview's expressions: 0 ahead, 1 to the side, 2 happy, 3 typing; 4 is a blink. */
export const FRAMES = 5;

export type LookModule = {
  memory: WebAssembly.Memory;
  _initialize?: () => void;
  miblo_look_buffer: () => number;
  miblo_look_render: (...args: number[]) => number;
  // My pet (firmware 1.19.0's renderer and later; claude_gadget tools/lookweb/wasm_api.cpp).
  miblo_pet_buffer?: () => number;
  miblo_pet_load?: (n: number) => number;
  miblo_pet_render?: (...args: number[]) => number;
  miblo_pet_colors?: (...args: number[]) => number;
  // A built-in pet in a mood (firmware 1.19.0's renderer with the phone companion's export).
  miblo_look_mood?: (...args: number[]) => number;
};

/** The gadget's moods (miblo::PetMood order); the antic (7) is My pet's alone. */
export const MOOD = { idle: 0, blink: 1, work: 2, alert: 3, happy: 4, sleepy: 5, dizzy: 6 } as const;

/** The firmware's verdicts for miblo_pet_load (miblo::PetError order). */
export const PET_ERRORS = [
  "ok", "size", "magic", "version", "grid", "palette", "frames", "moods", "fps", "flags", "name", "colors", "anchors",
  "reserved", "offsets", "data", "checksum", "read", "layers", "ops", "deltas", "cost",
] as const;

/**
 * What the module imports. The C library's start-up asks for the environment (there is none);
 * the drawing itself imports nothing, so any other call is a bug and fails loudly.
 */
export function lookImports(memory: () => WebAssembly.Memory): WebAssembly.Imports {
  const wasi: Record<string, (...a: number[]) => number> = {
    environ_sizes_get: (count, size) => {
      const v = new DataView(memory().buffer);
      v.setUint32(count, 0, true);
      v.setUint32(size, 0, true);
      return 0;
    },
    environ_get: () => 0,
  };
  return {
    wasi_snapshot_preview1: new Proxy(wasi, {
      get: (target, name: string) =>
        target[name] ??
        (() => {
          throw new Error(`miblo-look: unexpected import ${name}`);
        }),
    }),
  };
}

/** The module ready to draw (its C start-up run). */
export function startLookModule(instance: WebAssembly.Instance): LookModule {
  const m = instance.exports as unknown as LookModule;
  m._initialize?.();
  return m;
}

/** Draws `look` at `frame`: a copy of the 240 x 240 RGBA screen, or null for a look the gadget could not hold. */
export function drawLook(m: LookModule, look: Look, frame = 0): Uint8ClampedArray<ArrayBuffer> | null {
  if (!isLook(look) || !Number.isInteger(frame) || frame < 0 || frame >= FRAMES) return null;
  const slots = look.colors.map((c) => (c ? parseInt(c, 16) + 1 : 0));
  if (!m.miblo_look_render(look.pet, look.mascot, look.eyes, look.head, look.face, look.neck, ...slots, frame)) return null;
  return new Uint8ClampedArray(new Uint8ClampedArray(m.memory.buffer, m.miblo_look_buffer(), SCREEN * SCREEN * 4));
}

/**
 * A built-in pet in `look` in `mood` (MOOD) at `tick` (its breath's clock, a second a tick), as the
 * gadget draws that mood: a copy of the screen, or null (My pet, an unknown mood, an older module).
 */
export function drawMood(m: LookModule, look: Look, mood: number, tick = 0): Uint8ClampedArray<ArrayBuffer> | null {
  if (!m.miblo_look_mood || !isLook(look) || !Number.isInteger(mood) || !Number.isInteger(tick) || tick < 0) return null;
  const slots = look.colors.map((c) => (c ? parseInt(c, 16) + 1 : 0));
  if (!m.miblo_look_mood(look.pet, mood, tick % 65536, look.mascot, look.eyes, look.head, look.face, look.neck, ...slots)) return null;
  return new Uint8ClampedArray(new Uint8ClampedArray(m.memory.buffer, m.miblo_look_buffer(), SCREEN * SCREEN * 4));
}

/**
 * Installs an MPET1 or MPET2 file as My pet in the module, after the firmware's own validation: "ok" or the
 * reason it was refused (nothing installed then). An empty file uninstalls it.
 */
export function loadPet(m: LookModule, bytes: Uint8Array): (typeof PET_ERRORS)[number] {
  if (!m.miblo_pet_buffer || !m.miblo_pet_load) return "read";
  if (bytes.length > 8192) {
    m.miblo_pet_load(0);
    return "size";
  }
  new Uint8Array(m.memory.buffer, m.miblo_pet_buffer(), bytes.length).set(bytes);
  return PET_ERRORS[m.miblo_pet_load(bytes.length)] ?? "read";
}

/** My pet (loaded with loadPet) in mood `mood` (0..7) at frame `tick` of its loop, in `look`'s preset, eyes, items and colours. */
export function drawPet(m: LookModule, mood: number, tick: number, look: Look): Uint8ClampedArray<ArrayBuffer> | null {
  if (!m.miblo_pet_render) return null;
  const slots = look.colors.map((c) => (c ? parseInt(c, 16) + 1 : 0));
  if (!m.miblo_pet_render(mood, tick, look.mascot, look.eyes, look.head, look.face, look.neck, ...slots)) return null;
  return new Uint8ClampedArray(new Uint8ClampedArray(m.memory.buffer, m.miblo_look_buffer(), SCREEN * SCREEN * 4));
}

/**
 * The colours the gadget gives a pet's palette kinds (body, line, detail, nose, lid, eye, accent,
 * pupil, white) for a preset and colour slots, given its own Auto body (or null), eye and accent:
 * "rrggbb" each, or null when refused.
 */
export function petKindColors(m: LookModule, mascot: number, body: string | null, eye: string, accent: string, colors: string[]): string[] | null {
  if (!m.miblo_pet_colors) return null;
  const slots = colors.map((c) => (c ? parseInt(c, 16) + 1 : 0));
  const at = m.miblo_pet_colors(mascot, body ? 1 : 0, body ? parseInt(body, 16) : 0, parseInt(eye, 16), parseInt(accent, 16), ...slots);
  const out = Array.from(new Uint32Array(m.memory.buffer, at, 9), (v) => v.toString(16).padStart(6, "0"));
  return out.every((v) => v === "000000") ? null : out;
}

let loading: Promise<LookModule> | null = null;

async function instantiate(): Promise<LookModule> {
  let memory: WebAssembly.Memory | null = null;
  const imports = lookImports(() => memory!);
  const response = fetch(LOOK_WASM);
  let instance: WebAssembly.Instance;
  try {
    instance = (await WebAssembly.instantiateStreaming(response, imports)).instance;
  } catch (e) {
    // A server that does not label it application/wasm: the same bytes, compiled from a buffer.
    if (!(e instanceof TypeError)) throw e;
    const res = await fetch(LOOK_WASM);
    if (!res.ok) throw new Error(`miblo-look: ${res.status}`);
    instance = await WebAssembly.instantiate(await WebAssembly.compile(await res.arrayBuffer()), imports);
  }
  memory = (instance.exports as unknown as LookModule).memory;
  return startLookModule(instance);
}

function renderer(): Promise<LookModule> {
  loading ??= instantiate().catch((e) => {
    loading = null; // a later call tries again
    throw e;
  });
  return loading;
}

/** The shared module (Miblo Studio draws My pet with it). */
export function lookModule(): Promise<LookModule> {
  return renderer();
}

/** Starts fetching the renderer (e.g. as a form opens). */
export function preloadRenderer(): void {
  renderer().catch(() => {});
}

/** The look on the Miblo's screen at `frame`; null for a look the gadget could not hold. */
export async function renderLook(look: Look, frame = 0): Promise<ImageData | null> {
  if (!isLook(look)) return null;
  const pixels = drawLook(await renderer(), look, frame);
  return pixels && new ImageData(pixels, SCREEN, SCREEN);
}

/** A built-in pet's look on the Miblo's screen in `mood` at `tick`; null when it cannot be drawn. */
export async function renderMood(look: Look, mood: number, tick = 0): Promise<ImageData | null> {
  if (!isLook(look)) return null;
  const pixels = drawMood(await renderer(), look, mood, tick);
  return pixels && new ImageData(pixels, SCREEN, SCREEN);
}

/**
 * My pet (an MPET1 or MPET2 file) on the Miblo's screen in `mood` at `tick` of its loop, in `look`'s preset,
 * eyes, items and colours (its pet is ignored). The module holds one pet at a time: every call
 * loads its own, so many screens on a page can share it. null: the file is refused.
 */
export async function renderPet(mpet: Uint8Array, mood: number, tick: number, look: Look): Promise<ImageData | null> {
  const m = await renderer();
  if (loadPet(m, mpet) !== "ok") return null;
  const pixels = drawPet(m, mood, tick, look);
  return pixels && new ImageData(pixels, SCREEN, SCREEN);
}
