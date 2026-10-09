// Miblo 1.26 animations in the apps (the product repository's docs/screen-sdk-architecture.md
// "1.26: animations from the flash"): what plays (the snapshot's `screen.anim`, else the card's own
// `anim`), when to draw the next frame (never above the animation's fps), and the Canvas fallback
// for a screen module older than the 1.26 player.
//
// The module path (firmware 1.26's miblo_screen_tiles / _anim / _anim_tick / _fx_tick / _mode7 /
// _mesh) draws every kind. The fallback here draws, from the same data:
//   - tile maps and sprites (flips, sub-palettes, the transparent colour; not the two priorities:
//     every tile is behind the card, and no blending against the tile under a sprite);
//   - whole frames, rectangle frames (deltas) and sprite-sheet cells;
//   - the card effects sweep, count, slide, pulse, blink and orbit.
// It does not draw rain, ticker, Mode 7 effects or meshes (the card is drawn still, the layer as
// its first map): those need the module.
//
// The tile set and the animation data come from the bridge (`GET /sdk/v1/screen/tiles/<slot>`,
// `/anim/<slot>`). Their layouts below (MTIL1, MANM1) are the app's proposed contract for the
// firmware (anim-fw-tiles) and plugin (anim-sdk) streams; the module path passes the bytes through
// untouched, so only this fallback depends on them.
//
// The same file is in the desktop app (installer/src/lib) and the phone app (web/src/lib, and the
// self-hosted relay's copy): keep them identical.

import { ANIM_SLOTS, crc32, decodeAnyFrame, layoutParts, parseSteps, SIZE, type AnimStep, type Card, type CardLeaf, type Prim, type RectFrame } from './screen-card';

/** The Miblo's own screens (screen-live FRAME_MS). */
export const BASE_FPS = 10;
/** The card effects, as the firmware computes them (20 to 30 fps). */
export const FX_FPS = 20;
/** Never faster than this, whatever the snapshot says. */
export const MAX_FPS = 30;
/** How long a sweep, a count or a slide takes after a card update. */
export const TWEEN_MS = 600;
const PIXELS = SIZE * SIZE;
/** The screens' background (#0b0b0d) in RGB565. */
export const BG565 = 0x0841;

export const MODE7_FX = ['rotate', 'zoom', 'perspective', 'wave', 'scroll'] as const;
export type Mode7Fx = (typeof MODE7_FX)[number];
export type AnimKind = 'frames' | 'tiles' | 'mode7' | 'mesh';

export interface Region {
  x: number;
  y: number;
  w: number;
  h: number;
}

/** A Mode 7 effect's bounded parameters (the firmware clamps them again). */
export interface Mode7 {
  effect: Mode7Fx;
  speed: number;
  amplitude: number;
  centre: [number, number];
  region: Region | null;
}

/** What plays on the App screen, as the bridge reports it. */
export interface AnimInfo {
  kind: AnimKind;
  /** The data slot (tiles, sprites, Mode 7 art, a mesh); null for frames. */
  slot: number | null;
  /** Frames: the slots in order with their time. Tiles: the maps' own steps are in the data. */
  steps: AnimStep[] | null;
  /** Frames a second asked for (1..30). */
  fps: number;
  loop: boolean;
  /** The step the gadget was on when the snapshot left (playback starts there). */
  step: number;
  /** A sprite sheet's cell size, when steps name cells. */
  cell: { w: number; h: number } | null;
  /** Where a sheet's cell (or the whole animation) is drawn; null: the whole screen. */
  region: Region | null;
  mode7: Mode7 | null;
  /** A mesh's parameters, handed to the module as they came (the fallback cannot draw one). */
  mesh: Record<string, unknown> | null;
  /** When the data was written (ms): a change fetches it again. */
  at: number | null;
  /** What the gadget measures: its real frames a second and the last draw's time. */
  real: { fps: number | null; drawMs: number | null };
  /** Equal for the same animation (playback restarts when it changes). */
  sig: string;
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const intIn = (v: unknown, lo: number, hi: number): v is number => Number.isInteger(v) && (v as number) >= lo && (v as number) <= hi;
const num = (v: unknown, lo: number, hi: number): number | null => (typeof v === 'number' && Number.isFinite(v) && v >= lo && v <= hi ? v : null);
const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v));

function regionOf(v: unknown): Region | null {
  if (!isObj(v)) return null;
  const { x, y, w, h } = v;
  if (!intIn(x, 0, SIZE - 1) || !intIn(y, 0, SIZE - 1) || !intIn(w, 1, SIZE) || !intIn(h, 1, SIZE)) return null;
  return x + w <= SIZE && y + h <= SIZE ? { x, y, w, h } : null;
}

function mode7Of(v: unknown): Mode7 | null {
  if (!isObj(v)) return null;
  const effect = (typeof v.effect === 'string' ? v.effect : v.fx) as string;
  if (!(MODE7_FX as readonly string[]).includes(effect)) return null;
  const c = Array.isArray(v.centre) ? v.centre : Array.isArray(v.center) ? v.center : null;
  const centre: [number, number] = c && intIn(c[0], 0, SIZE - 1) && intIn(c[1], 0, SIZE - 1) ? [c[0], c[1]] : [SIZE / 2, SIZE / 2];
  return {
    effect: effect as Mode7Fx,
    // Out of range is brought into it (the firmware clamps the same way); not a number is the default.
    speed: clamp(num(v.speed, -Infinity, Infinity) ?? 1, -1000, 1000),
    amplitude: clamp(num(v.amplitude, -Infinity, Infinity) ?? 0, 0, SIZE),
    centre,
    region: regionOf(v.region),
  };
}

/** Frames a second from a step list (its average step). */
const stepsFps = (steps: AnimStep[]) => 1000 / (steps.reduce((s, x) => s + x.ms, 0) / steps.length);

/**
 * What the gadget measures while it animates, from the snapshot's `screen`: `anim.real: {fps,
 * drawMs}` (or `anim.realFps` / `anim.drawMs`), else the screen's own `realFps` / `drawMs`.
 */
export function realOf(screen: unknown): { fps: number | null; drawMs: number | null } {
  const s = isObj(screen) ? screen : {};
  const a = isObj(s.anim) ? s.anim : {};
  const r = isObj(a.real) ? a.real : null;
  return {
    fps: num(r ? r.fps : a.realFps, 0, 1000) ?? num(s.realFps, 0, 1000),
    drawMs: num(r ? r.drawMs : a.drawMs, 0, 60_000) ?? num(s.drawMs, 0, 60_000),
  };
}

/**
 * What plays, from the snapshot's `screen` (its `anim`, the plugin's report of the animation on
 * the App screen) and the card (its own `anim`, when the bridge sends no report). null: nothing.
 * Every number is bounded; anything malformed is dropped (the card then draws still).
 */
export function parseAnim(screen: unknown, card: Card | null): AnimInfo | null {
  const s = isObj(screen) ? screen : {};
  const raw = isObj(s.anim) ? s.anim : null;
  const real = realOf(s);
  if (!raw) {
    const a = card?.anim ?? null;
    if (!a) return null;
    const fps = clamp(stepsFps(a.steps), 1, MAX_FPS);
    return finish({ kind: 'frames', slot: null, steps: a.steps, fps, loop: a.loop, step: 0, cell: null, region: null, mode7: null, mesh: null, at: null, real });
  }
  // The report's steps, else the card's (already checked by parseCard).
  const steps = raw.steps !== undefined ? parseSteps(raw.steps) : (card?.anim?.steps ?? null);
  const mode7 = mode7Of(isObj(raw.fx) ? raw.fx : isObj(raw.mode7) ? raw.mode7 : null);
  const mesh = isObj(raw.mesh) ? raw.mesh : null;
  const slot = intIn(raw.slot, 0, ANIM_SLOTS - 1) ? raw.slot : null;
  const explicit = (['frames', 'tiles', 'mode7', 'mesh'] as const).find((k) => k === raw.kind) ?? null;
  const kind: AnimKind | null = explicit ?? (mode7 ? 'mode7' : mesh ? 'mesh' : steps ? 'frames' : slot !== null ? 'tiles' : null);
  if (!kind) return null;
  if (kind === 'frames' && !steps) return null;
  if (kind !== 'frames' && slot === null) return null;
  if (kind === 'mode7' && !mode7) return null;
  const c = isObj(raw.cell) ? raw.cell : null;
  const cell = c && intIn(c.w, 1, SIZE) && intIn(c.h, 1, SIZE) ? { w: c.w, h: c.h } : null;
  const fps = clamp(num(raw.fps, 0.1, 1000) ?? (steps ? stepsFps(steps) : 4), 1, MAX_FPS);
  const step = intIn(raw.step, 0, 255) ? raw.step : 0;
  const at = num(raw.at, 0, Number.MAX_SAFE_INTEGER);
  return finish({ kind, slot, steps, fps, loop: raw.loop !== false, step, cell, region: regionOf(raw.region), mode7, mesh, at, real });
}

function finish(a: Omit<AnimInfo, 'sig'>): AnimInfo {
  const { real: _r, step: _s, ...same } = a;
  return { ...a, sig: JSON.stringify(same) };
}

/**
 * Frames a second to draw at: the animation's own (never above what the gadget reaches, when it
 * says) while the App screen shows it; the effects' rate while a card effect runs; else the
 * Miblo's own 10.
 */
export function playFps(anim: AnimInfo | null, fxRunning: boolean): number {
  if (anim) {
    const real = anim.real.fps;
    return clamp(real && real > 0 ? Math.min(anim.fps, real) : anim.fps, 1, MAX_FPS);
  }
  return fxRunning ? FX_FPS : BASE_FPS;
}

/**
 * Whether a requestAnimationFrame callback draws a frame at `fps`: one per period, in step with
 * the display (a 60 Hz display at 4 fps draws every 15th callback; at its own rate, every one).
 */
export class FrameGate {
  private next = -Infinity;

  due(now: number, fps: number): boolean {
    const period = 1000 / clamp(fps, 0.1, 1000);
    // Half a millisecond of slack: the display's own timestamps jitter around the period.
    if (now + 0.5 < this.next) return false;
    this.next = now - this.next > period ? now + period : this.next + period;
    return true;
  }

  reset() {
    this.next = -Infinity;
  }
}

/** The step shown `elapsed` ms after the start (a non-looping animation stays on its last step). */
export function stepAt(steps: readonly { ms: number }[], elapsed: number, loop: boolean): number {
  const total = steps.reduce((s, x) => s + x.ms, 0);
  if (!steps.length || total <= 0) return 0;
  if (!loop && elapsed >= total) return steps.length - 1;
  let e = ((elapsed % total) + total) % total;
  for (let i = 0; i < steps.length; i++) {
    if (e < steps[i].ms) return i;
    e -= steps[i].ms;
  }
  return steps.length - 1;
}

/** Elapsed time at the start of step `i` (playback joins the gadget there). */
export const stepStart = (steps: readonly { ms: number }[], i: number) => steps.slice(0, Math.max(0, Math.min(i, steps.length))).reduce((s, x) => s + x.ms, 0);

// ---- MTIL1: a tile set ----
//
// offset  size     field
// 0       5        "MTIL1"
// 5       1        palette size N (2..64)
// 6       2*N      palette, RGB565 little-endian
// 6+2N    1        sub-palettes K (1..4)
// 7+2N    16*K     each sub-palette: 16 indexes into the palette
// ...     2        tile count T (1..256), little-endian
// ...     32*T     tiles: 8 x 8, 4 bits a pixel (an index into the cell's sub-palette), rows top to
//                  bottom, the left pixel in the high nibble
// ...     4        CRC-32 (IEEE) of everything before, little-endian

export interface TileSet {
  palette: Uint16Array;
  /** K x 16 palette indexes. */
  subs: Uint8Array;
  count: number;
  tiles: Uint8Array;
}

export const TILE_LIMITS = { tiles: 256, subs: 4, colours: 64, maps: 16, sprites: 16, steps: 16, grid: 30 } as const;
const GRID = TILE_LIMITS.grid;

const crcOk = (b: Uint8Array) => crc32(b.subarray(0, b.length - 4)) === ((b[b.length - 4] | (b[b.length - 3] << 8) | (b[b.length - 2] << 16) | (b[b.length - 1] << 24)) >>> 0);
const magic = (b: Uint8Array, m: string) => b.length > m.length && String.fromCharCode(...b.subarray(0, m.length)) === m;
const withCrc = (bytes: number[]) => {
  const out = new Uint8Array(bytes.length + 4);
  out.set(bytes);
  const c = crc32(out.subarray(0, bytes.length));
  out.set([c & 0xff, (c >>> 8) & 0xff, (c >>> 16) & 0xff, c >>> 24], bytes.length);
  return out;
};

/** A tile set, or null when it is not a valid MTIL1 file. */
export function decodeTiles(b: Uint8Array): TileSet | null {
  if (!magic(b, 'MTIL1') || b.length < 12) return null;
  const n = b[5];
  if (n < 2 || n > TILE_LIMITS.colours) return null;
  let at = 6 + 2 * n;
  const k = b[at];
  if (k < 1 || k > TILE_LIMITS.subs) return null;
  at += 1;
  if (b.length < at + 16 * k + 2) return null;
  const subs = b.slice(at, at + 16 * k);
  if (subs.some((i) => i >= n)) return null;
  at += 16 * k;
  const count = b[at] | (b[at + 1] << 8);
  at += 2;
  if (count < 1 || count > TILE_LIMITS.tiles || b.length !== at + 32 * count + 4 || !crcOk(b)) return null;
  const palette = new Uint16Array(n);
  for (let i = 0; i < n; i++) palette[i] = b[6 + 2 * i] | (b[7 + 2 * i] << 8);
  return { palette, subs, count, tiles: b.slice(at, at + 32 * count) };
}

export function encodeTiles(t: TileSet): Uint8Array {
  const out: number[] = [...'MTIL1'].map((c) => c.charCodeAt(0));
  out.push(t.palette.length);
  for (const c of t.palette) out.push(c & 0xff, c >> 8);
  out.push(t.subs.length / 16, ...t.subs, t.count & 0xff, t.count >> 8, ...t.tiles);
  return withCrc(out);
}

// ---- MANM1: maps, sprites and steps ----
//
// offset  size     field
// 0       5        "MANM1"
// 5       1        maps M (1..16)
// 6       1        sprites S (0..16)
// 7       1        steps N (1..16)
// 8       1        flags: bit 0 loop
// 9       1800*M   maps: 30 x 30 cells, each a tile index and an attribute byte (bit 0 H flip,
//                  bit 1 V flip, bits 2-3 sub-palette, bit 4 in front of the card's items)
// ...     3*S      sprites: first tile, size (8, 16 or 32 px square: its tiles row by row from the
//                  first), sub-palette (bits 0-1)
// ...     N*(3+3S) steps: the map, its time in ms (50..2000, little-endian), then per sprite x, y
//                  and flags (bit 0 shown, bit 1 H flip, bit 2 V flip); x and y are its top left
// ...     4        CRC-32 (IEEE) of everything before, little-endian
// Colour index 0 of a sprite's sub-palette is transparent.

export interface Sprite {
  tile: number;
  size: 8 | 16 | 32;
  sub: number;
}
export interface SpriteAt {
  x: number;
  y: number;
  shown: boolean;
  hflip: boolean;
  vflip: boolean;
}
export interface TileStep {
  map: number;
  ms: number;
  sprites: SpriteAt[];
}
export interface AnimData {
  /** M x 1800 bytes. */
  maps: Uint8Array[];
  sprites: Sprite[];
  steps: TileStep[];
  loop: boolean;
}

/** Animation data, or null when it is not a valid MANM1 file. */
export function decodeAnimData(b: Uint8Array): AnimData | null {
  if (!magic(b, 'MANM1') || b.length < 13) return null;
  const [m, s, n, flags] = [b[5], b[6], b[7], b[8]];
  if (m < 1 || m > TILE_LIMITS.maps || s > TILE_LIMITS.sprites || n < 1 || n > TILE_LIMITS.steps) return null;
  const mapBytes = GRID * GRID * 2;
  const size = 9 + mapBytes * m + 3 * s + n * (3 + 3 * s) + 4;
  if (b.length !== size || !crcOk(b)) return null;
  let at = 9;
  const maps: Uint8Array[] = [];
  for (let i = 0; i < m; i++, at += mapBytes) maps.push(b.slice(at, at + mapBytes));
  const sprites: Sprite[] = [];
  for (let i = 0; i < s; i++, at += 3) {
    const size = b[at + 1];
    if (size !== 8 && size !== 16 && size !== 32) return null;
    sprites.push({ tile: b[at], size, sub: b[at + 2] & 3 });
  }
  const steps: TileStep[] = [];
  for (let i = 0; i < n; i++) {
    const map = b[at];
    const ms = b[at + 1] | (b[at + 2] << 8);
    if (map >= m || ms < 50 || ms > 2000) return null;
    at += 3;
    const at0 = at;
    const sp: SpriteAt[] = [];
    for (let j = 0; j < s; j++) {
      const f = b[at0 + 3 * j + 2];
      sp.push({ x: b[at0 + 3 * j], y: b[at0 + 3 * j + 1], shown: !!(f & 1), hflip: !!(f & 2), vflip: !!(f & 4) });
    }
    at += 3 * s;
    steps.push({ map, ms, sprites: sp });
  }
  return { maps, sprites, steps, loop: !!(flags & 1) };
}

export function encodeAnimData(a: AnimData): Uint8Array {
  const out: number[] = [...'MANM1'].map((c) => c.charCodeAt(0));
  out.push(a.maps.length, a.sprites.length, a.steps.length, a.loop ? 1 : 0);
  for (const m of a.maps) out.push(...m);
  for (const s of a.sprites) out.push(s.tile, s.size, s.sub);
  for (const st of a.steps) {
    out.push(st.map, st.ms & 0xff, st.ms >> 8);
    for (const p of st.sprites) out.push(p.x, p.y, (p.shown ? 1 : 0) | (p.hflip ? 2 : 0) | (p.vflip ? 4 : 0));
  }
  return withCrc(out);
}

/** One pixel of a tile: its 4-bit index (0..15). */
const nibble = (t: TileSet, tile: number, x: number, y: number) => {
  const byte = t.tiles[tile * 32 + y * 4 + (x >> 1)];
  return x & 1 ? byte & 15 : byte >> 4;
};

/**
 * Draws step `i` of a tile animation into `out` (240 x 240 RGB565): the map, then the sprites
 * shown, in order (a later one over an earlier one). A tile index past the set draws nothing
 * there, as the firmware refuses it.
 */
export function renderTiles(t: TileSet, a: AnimData, i: number, out: Uint16Array) {
  const st = a.steps[Math.max(0, Math.min(i, a.steps.length - 1))];
  const map = a.maps[st.map];
  const subs = t.subs.length / 16;
  for (let cy = 0; cy < GRID; cy++) {
    for (let cx = 0; cx < GRID; cx++) {
      const c = (cy * GRID + cx) * 2;
      const tile = map[c];
      const attr = map[c + 1];
      if (tile >= t.count) continue;
      const sub = ((attr >> 2) & 3) % subs;
      for (let y = 0; y < 8; y++) {
        const sy = attr & 2 ? 7 - y : y;
        const row = (cy * 8 + y) * SIZE + cx * 8;
        for (let x = 0; x < 8; x++) out[row + x] = t.palette[t.subs[sub * 16 + nibble(t, tile, attr & 1 ? 7 - x : x, sy)]];
      }
    }
  }
  a.sprites.forEach((sp, j) => {
    const at = st.sprites[j];
    if (!at?.shown) return;
    const n = sp.size / 8;
    const sub = sp.sub % subs;
    for (let py = 0; py < sp.size; py++) {
      const y = at.y + py;
      if (y >= SIZE) break;
      const sy = at.vflip ? sp.size - 1 - py : py;
      for (let px = 0; px < sp.size; px++) {
        const x = at.x + px;
        if (x >= SIZE) break;
        const sx = at.hflip ? sp.size - 1 - px : px;
        const tile = sp.tile + (sy >> 3) * n + (sx >> 3);
        if (tile >= t.count) continue;
        const v = nibble(t, tile, sx & 7, sy & 7);
        if (v !== 0) out[y * SIZE + x] = t.palette[t.subs[sub * 16 + v]];
      }
    }
  });
}

/**
 * Draws a frame step into `layer`: a whole frame, a rectangle frame over what is there (a delta),
 * or a sprite sheet's cell (cells of `cell` size, left to right, top to bottom) at `region`'s
 * corner (else the cell's own place on the sheet).
 */
export function drawFrameStep(layer: Uint16Array, f: RectFrame, cellIndex: number | null, cell: { w: number; h: number } | null, region: Region | null) {
  if (cellIndex !== null && cell && f.w === SIZE && f.h === SIZE) {
    const cols = Math.max(1, Math.floor(SIZE / cell.w));
    const sx = (cellIndex % cols) * cell.w;
    const sy = Math.floor(cellIndex / cols) * cell.h;
    const dx = region ? region.x : sx;
    const dy = region ? region.y : sy;
    for (let y = 0; y < cell.h && sy + y < SIZE && dy + y < SIZE; y++) {
      for (let x = 0; x < cell.w && sx + x < SIZE && dx + x < SIZE; x++) layer[(dy + y) * SIZE + dx + x] = f.rgb565[(sy + y) * SIZE + sx + x];
    }
    return;
  }
  for (let y = 0; y < f.h; y++) layer.set(f.rgb565.subarray(y * f.w, (y + 1) * f.w), (f.y + y) * SIZE + f.x);
}

/** A layer filled with the screens' background. */
export const blankLayer = () => new Uint16Array(PIXELS).fill(BG565);

/** Decodes a frame slot's bytes for playback (whole or rectangle), or null. */
export const frameForPlay = (b: Uint8Array | null) => (b ? decodeAnyFrame(b) : null);

// ---- the card effects (the Canvas fallback) ----

/** The effects the Canvas fallback draws; the rest need the module. */
export const FALLBACK_FX = ['sweep', 'count', 'slide', 'pulse', 'blink', 'orbit'] as const;
/** Effects that move all the time (the others run for a moment after an update). */
const CONTINUOUS = new Set(['blink', 'orbit', 'rain', 'ticker']);

const ease = (p: number) => 1 - (1 - p) ** 3;
const NUM = /^(\D*?)(-?)(\d[\d.,]*\d|\d)(\D*)$/;

/**
 * A number counting from `from` to `to` (p 0..1), written as `to` is ("8.432", "R$ 5,42", "61%"):
 * its digits interpolated as one whole number, its separators kept where they are. A value that is
 * not such a number, or a different prefix or suffix, shows `to` at once.
 */
export function countText(from: string, to: string, p: number): string {
  const a = NUM.exec(from);
  const b = NUM.exec(to);
  if (!a || !b || p >= 1 || a[1] !== b[1] || a[4] !== b[4]) return to;
  const digits = (m: RegExpExecArray) => Number((m[2] ? '-' : '') + m[3].replace(/[.,]/g, ''));
  const x = digits(a);
  const y = digits(b);
  if (!Number.isSafeInteger(x) || !Number.isSafeInteger(y)) return to;
  const v = Math.round(x + (y - x) * ease(Math.max(0, p)));
  // Separators of `to`, counted from the right; the value padded to as many digits.
  const seps: [number, string][] = [];
  let d = 0;
  for (let i = b[3].length - 1; i >= 0; i--) {
    const ch = b[3][i];
    if (ch === '.' || ch === ',') seps.push([d, ch]);
    else d++;
  }
  // The rightmost separator is a decimal one unless 3 digits follow it ("5,42" vs "8.432"): a
  // counting value keeps its decimals ("0,05"), never invents thousands ("0.008").
  const dec = seps[0] && seps[0][0] !== 3 ? seps[0][0] : 0;
  const raw = String(Math.abs(v)).padStart(dec + 1, '0');
  let out = '';
  let k = 0;
  for (let i = raw.length - 1; i >= 0; i--, k++) {
    const sep = seps.find((s) => s[0] === k);
    if (sep && k > 0) out = sep[1] + out;
    out = raw[i] + out;
  }
  return `${b[1]}${v < 0 ? '-' : ''}${out}${b[4]}`;
}

interface CellWas {
  leaf: CardLeaf;
}

/**
 * The card effects over time, for the Canvas fallback: on each card update rings and bars sweep,
 * numbers count and sparklines slide to their new values (1.26, every card, no API change); an
 * item's own `fx` adds pulse, blink or orbit.
 */
export class FxPlayer {
  private json = '';
  private card: Card | null = null;
  private was: CellWas[] = [];
  private changedAt = -Infinity;

  /** The card shown now; `now` is when it came. The first card shows as it is (an update moves). */
  update(card: Card | null, now: number) {
    const json = card ? JSON.stringify(card) : '';
    if (json === this.json) return;
    // What was on screen: the cells as drawn a moment ago (mid-tween counts as its target).
    this.was = this.card ? flatLeaves(this.card).map((leaf) => ({ leaf })) : [];
    this.json = json;
    this.card = card;
    this.changedAt = now;
  }

  /**
   * Plays the card's arrival from nothing at `now` (rings and bars from 0, numbers from 0): the
   * Apps tab's preview on hover.
   */
  replay(now: number) {
    if (!this.card) return;
    this.was = flatLeaves(this.card).map((l) => ({ leaf: l.t === 'ring' || l.t === 'bar' ? { ...l, value: 0 } : l.t === 'big' ? { ...l, value: '0' } : l.t === 'spark' ? { ...l, values: [...l.values.slice(1), l.values[0]] } : l }));
    this.changedAt = now;
  }

  /** Whether anything moves at `now` (so the screen keeps drawing at the effects' rate). */
  running(now: number): boolean {
    if (!this.card) return false;
    if (now - this.changedAt < TWEEN_MS + 200) return true;
    return flatLeaves(this.card).some((l) => l.fx && CONTINUOUS.has(l.fx));
  }

  /** The card's drawing at `now`. */
  prims(tool: string, layer: boolean, now: number): Prim[] {
    if (!this.card) return [];
    const p = Math.min(1, Math.max(0, (now - this.changedAt) / TWEEN_MS));
    const leaves = flatLeaves(this.card);
    let i = 0;
    const tween = (l: CardLeaf): CardLeaf => {
      const was = this.was[i++]?.leaf;
      if (!was || was.t !== l.t) return l;
      if (l.t === 'ring' || l.t === 'bar') {
        const from = (was as typeof l).value;
        return { ...l, value: from + (l.value - from) * ease(p) };
      }
      if (l.t === 'big') return { ...l, value: countText((was as typeof l).value, l.value, p) };
      return l;
    };
    const card: Card = { ...this.card, items: this.card.items.map((it) => (it.t === 'row' ? { t: 'row', items: it.items.map(tween) } : tween(it))) };
    const { head, cells } = layoutParts(card, tool, layer);
    const out: Prim[] = [...head];
    cells.forEach((c, j) => {
      const leaf = leaves[j];
      const was = this.was[j]?.leaf;
      let prims = c.prims;
      // Slide: a changed sparkline comes in from the right, one point's width.
      if (leaf.t === 'spark' && was?.t === 'spark' && JSON.stringify(was.values) !== JSON.stringify(leaf.values) && p < 1) {
        const step = (c.box.w - 4) / Math.max(1, leaf.values.length - 1);
        const dx = Math.round((1 - ease(p)) * step);
        prims = prims.map((q) => (q.k === 'line' ? { ...q, pts: q.pts.filter(([x]) => x + dx <= c.box.x + c.box.w).map(([x, y]) => [x + dx, y] as [number, number]) } : q.k === 'rect' ? { ...q, x: Math.min(q.x + dx, c.box.x + c.box.w - q.w) } : q));
      }
      if (leaf.fx === 'blink' && Math.floor(now / 500) % 2 === 1) return;
      if (leaf.fx === 'pulse' && was && now - this.changedAt < 800 && JSON.stringify(was) !== JSON.stringify(leaf)) {
        const q = 1 - (now - this.changedAt) / 800;
        out.push({ k: 'rect', x: c.box.x - 4, y: c.box.y + 2, w: c.box.w + 8, h: c.box.h - 4, color: leafColor(leaf), r: 10, alpha: 0.28 * q });
      }
      out.push(...prims);
      if (leaf.fx === 'orbit') {
        const ring = prims.find((q): q is Extract<Prim, { k: 'ring' }> => q.k === 'ring');
        if (ring) {
          const a = -Math.PI / 2 + ((now % 4000) / 4000) * Math.PI * 2;
          const r = ring.r - ring.width / 2;
          const d = Math.max(4, Math.round(ring.width * 0.9));
          out.push({ k: 'rect', x: Math.round(ring.cx + Math.cos(a) * r - d / 2), y: Math.round(ring.cy + Math.sin(a) * r - d / 2), w: d, h: d, color: '#eeeeee', r: d / 2 });
        }
      }
    });
    return out;
  }
}

const flatLeaves = (c: Card): CardLeaf[] => c.items.flatMap((it) => (it.t === 'row' ? it.items : [it]));
const PAL: Record<string, string> = { amber: '#f5a524', blue: '#60a5fa', green: '#4ade80', red: '#ef4444', white: '#eeeeee', grey: '#aaaaaa' };
const leafColor = (l: CardLeaf) => ('color' in l ? PAL[l.color] : PAL.amber);

/** Whether a card carries an effect the Canvas fallback cannot draw (the page may say so). */
export const needsModule = (c: Card | null) => !!c && flatLeaves(c).some((l) => l.fx === 'rain' || l.fx === 'ticker');

/** The card's own effects, in order (the Apps tab's preview plays them on hover). */
export const cardFx = (c: Card | null) => (c ? flatLeaves(c).map((l) => l.fx).filter((x): x is NonNullable<CardLeaf['fx']> => !!x) : []);
