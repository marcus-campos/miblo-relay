// The App screen of the Miblo 1.25 screen SDK (the product repository's
// docs/screen-sdk-architecture.md): a program's card, read with the core's rules; its layout, the
// same fixed slots the firmware uses (so a card looks alike on the gadget, in the desktop app and
// on the phone); a Canvas 2D drawing of that layout, for a screen module older than the card
// renderer (`miblo_screen_card`); and the MFRM1 frame format (a 240 x 240 indexed image).
//
// The same file is in the desktop app (installer/src/lib) and the phone app (web/src/lib, and the
// self-hosted relay's copy): keep them identical. No DOM here but the drawer's CanvasRenderingContext2D.

export const SIZE = 240;
const PIXELS = SIZE * SIZE;

// ---- the card ----

export const CARD_COLORS = ['amber', 'blue', 'green', 'red', 'white', 'grey'] as const;
export type CardColor = (typeof CARD_COLORS)[number];
/** The palette's names, as the firmware's ui::color (miblo_ui/src/ui_canvas.h). */
export const PALETTE: Record<CardColor, string> = { amber: '#f5a524', blue: '#60a5fa', green: '#4ade80', red: '#ef4444', white: '#eeeeee', grey: '#aaaaaa' };
const INK = { bg: '#0b0b0d', text: '#eeeeee', muted: '#aaaaaa', track: '#262629' };

/** Limits of the contract (title 24, text 40, big value 10); a caption is cut at 20. */
export const LIMITS = { title: 24, text: 40, big: 10, label: 20, tool: 24, items: 4, sparkMin: 2, sparkMax: 24, json: 1024 } as const;

export type CardLeaf =
  | { t: 'big'; value: string; label: string }
  | { t: 'ring'; value: number; label: string; color: CardColor }
  | { t: 'bar'; value: number; label: string; color: CardColor }
  | { t: 'text'; value: string }
  | { t: 'spark'; values: number[]; label: string; color: CardColor };
export type CardItem = CardLeaf | { t: 'row'; items: CardLeaf[] };

export interface Card {
  v: 1;
  title: string;
  items: CardItem[];
  /** One of the core's icons (drawn by the core; the Canvas fallback has none). */
  icon: string | null;
  /** The layer: the frame slot (0..3) drawn under the card. */
  bg: number | null;
}

// Controls, bidi marks and overrides, and every other format character (the plugin's cleanText).
const CONTROLS = /[\u0000-\u001F\u007F-\u009F؜‎‏‪-‮⁦-⁩]/g;

/** One line of shown text: whitespace runs made one space, no invisible characters, NFC, cut to `max` characters. */
export function cleanLine(v: unknown, max: number): string {
  if (typeof v !== 'string') return '';
  const s = v.normalize('NFC').replace(/\s+/g, ' ').replace(CONTROLS, '').replace(/\p{Cf}/gu, '').trim();
  return Array.from(s).slice(0, max).join('');
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const colorOf = (v: unknown, fallback: CardColor): CardColor => (CARD_COLORS as readonly string[]).includes(v as string) ? (v as CardColor) : fallback;
const unit = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 1 ? v : null);

/** "frame:3" (or 3) to the slot, else null. */
export function frameSlot(v: unknown): number | null {
  if (typeof v === 'number') return Number.isInteger(v) && v >= 0 && v <= 3 ? v : null;
  const m = typeof v === 'string' ? /^frame:([0-3])$/.exec(v) : null;
  return m ? Number(m[1]) : null;
}

function leaf(v: unknown): CardLeaf | null {
  if (!isObj(v)) return null;
  const label = cleanLine(v.label, LIMITS.label);
  switch (v.t) {
    case 'big': {
      const raw = typeof v.value === 'number' && Number.isFinite(v.value) ? String(v.value) : v.value;
      const value = cleanLine(raw, LIMITS.big);
      return value ? { t: 'big', value, label } : null;
    }
    case 'ring':
    case 'bar': {
      const value = unit(v.value);
      return value === null ? null : { t: v.t, value, label, color: colorOf(v.color, v.t === 'ring' ? 'amber' : 'blue') };
    }
    case 'text': {
      const value = cleanLine(v.value, LIMITS.text);
      return value ? { t: 'text', value } : null;
    }
    case 'spark': {
      const vs = v.values;
      if (!Array.isArray(vs) || vs.length < LIMITS.sparkMin || vs.length > LIMITS.sparkMax) return null;
      if (!vs.every((n) => typeof n === 'number' && Number.isFinite(n))) return null;
      return { t: 'spark', values: vs as number[], label, color: colorOf(v.color, 'green') };
    }
    default:
      return null;
  }
}

/**
 * A card as the core reads it, or null when it is invalid (the core refuses it: `v` not 1, no
 * items or more than 4, an unknown `t`, a value out of its range). Unknown fields are ignored;
 * strings are cleaned and cut; an unknown colour is the item's own default.
 */
export function parseCard(raw: unknown): Card | null {
  if (!isObj(raw) || raw.v !== 1 || !Array.isArray(raw.items)) return null;
  if (raw.items.length < 1 || raw.items.length > LIMITS.items) return null;
  const items: CardItem[] = [];
  for (const it of raw.items) {
    if (isObj(it) && it.t === 'row') {
      if (!Array.isArray(it.items) || it.items.length < 1 || it.items.length > 2) return null;
      const kids = it.items.map(leaf);
      if (kids.some((k) => k === null)) return null;
      items.push({ t: 'row', items: kids as CardLeaf[] });
    } else {
      const l = leaf(it);
      if (!l) return null;
      items.push(l);
    }
  }
  const icon = typeof raw.icon === 'string' && /^[a-z0-9-]{1,16}$/.test(raw.icon) ? raw.icon : null;
  return { v: 1, title: cleanLine(raw.title, LIMITS.title), items, icon, bg: frameSlot(raw.bg) };
}

// ---- the layout (fixed per item count) ----

export type Prim =
  | { k: 'rect'; x: number; y: number; w: number; h: number; color: string; r?: number; alpha?: number }
  | { k: 'text'; x: number; y: number; text: string; size: number; color: string; align: 'left' | 'center' | 'right'; bold?: boolean; maxW: number }
  | { k: 'ring'; cx: number; cy: number; r: number; width: number; value: number; color: string }
  | { k: 'line'; pts: [number, number][]; color: string; width: number };

/** The header band: the title on the left, the program's name on the right (always drawn). */
export const HEADER = 30;
const PAD = 12;
const TOP = 38;
const BOTTOM = SIZE - 10;

const pct = (v: number) => `${Math.round(v * 100)}%`;

function leafPrims(it: CardLeaf, x: number, y: number, w: number, h: number, alone: boolean): Prim[] {
  const mid = y + h / 2;
  switch (it.t) {
    case 'big': {
      const size = Math.round(Math.max(18, Math.min(alone ? 64 : 44, h * (it.label ? 0.5 : 0.62))));
      const base = it.label ? mid + size * 0.22 : mid + size * 0.36;
      const out: Prim[] = [{ k: 'text', x: x + w / 2, y: Math.round(base), text: it.value, size, color: INK.text, align: 'center', bold: true, maxW: w - 4 }];
      if (it.label) out.push({ k: 'text', x: x + w / 2, y: Math.round(base + 18), text: it.label, size: 12, color: INK.muted, align: 'center', maxW: w - 4 });
      return out;
    }
    case 'ring': {
      if (alone) {
        const r = Math.round(Math.min(h / 2 - (it.label ? 16 : 6), w / 2 - 6, 70));
        const cy = Math.round(it.label ? mid - 10 : mid);
        const out: Prim[] = [
          { k: 'ring', cx: x + w / 2, cy, r, width: Math.max(5, Math.round(r * 0.2)), value: it.value, color: PALETTE[it.color] },
          { k: 'text', x: x + w / 2, y: Math.round(cy + r * 0.18), text: pct(it.value), size: Math.max(12, Math.round(r * 0.5)), color: INK.text, align: 'center', bold: true, maxW: r * 1.5 },
        ];
        if (it.label) out.push({ k: 'text', x: x + w / 2, y: cy + r + 18, text: it.label, size: 12, color: INK.muted, align: 'center', maxW: w - 4 });
        return out;
      }
      const r = Math.round(Math.max(10, Math.min(h / 2 - 4, w / 4, 40)));
      const cx = x + r + 2;
      const out: Prim[] = [
        { k: 'ring', cx, cy: Math.round(mid), r, width: Math.max(4, Math.round(r * 0.22)), value: it.value, color: PALETTE[it.color] },
        { k: 'text', x: cx, y: Math.round(mid + r * 0.2), text: pct(it.value), size: Math.max(10, Math.round(r * 0.5)), color: INK.text, align: 'center', bold: true, maxW: r * 1.6 },
      ];
      if (it.label) out.push({ k: 'text', x: cx + r + 10, y: Math.round(mid + 5), text: it.label, size: 13, color: INK.muted, align: 'left', maxW: w - 2 * r - 14 });
      return out;
    }
    case 'bar': {
      const barH = alone ? 14 : 10;
      const top = Math.round(mid + 2);
      return [
        { k: 'text', x, y: top - 8, text: it.label, size: 12, color: INK.muted, align: 'left', maxW: w - 44 },
        { k: 'text', x: x + w, y: top - 8, text: pct(it.value), size: 12, color: INK.text, align: 'right', bold: true, maxW: 44 },
        { k: 'rect', x, y: top, w, h: barH, color: INK.track, r: barH / 2 },
        { k: 'rect', x, y: top, w: Math.round(w * it.value), h: barH, color: PALETTE[it.color], r: barH / 2 },
      ];
    }
    case 'text': {
      const lines = wrap(it.value, Math.max(8, Math.floor(w / 7.4)));
      const lh = 18;
      const y0 = mid - ((lines.length - 1) * lh) / 2 + 5;
      return lines.map((text, i) => ({ k: 'text', x: x + w / 2, y: Math.round(y0 + i * lh), text, size: 14, color: INK.text, align: 'center', maxW: w - 4 }) as Prim);
    }
    case 'spark': {
      const top = it.label ? y + 18 : y + 4;
      const bot = y + h - 4;
      const lo = Math.min(...it.values);
      const hi = Math.max(...it.values);
      const span = hi - lo || 1;
      const step = (w - 4) / (it.values.length - 1);
      const pts = it.values.map((v, i) => [Math.round(x + 2 + i * step), Math.round(bot - ((v - lo) / span) * (bot - top))] as [number, number]);
      const last = pts[pts.length - 1];
      const out: Prim[] = [];
      if (it.label) out.push({ k: 'text', x, y: y + 13, text: it.label, size: 12, color: INK.muted, align: 'left', maxW: w });
      out.push({ k: 'line', pts, color: PALETTE[it.color], width: 2 }, { k: 'rect', x: last[0] - 3, y: last[1] - 3, w: 6, h: 6, color: PALETTE[it.color], r: 3 });
      return out;
    }
  }
}

/** Words into at most two lines of about `n` characters (the second cut with "…"). */
function wrap(s: string, n: number): string[] {
  if (s.length <= n) return [s];
  const words = s.split(' ');
  let first = '';
  while (words.length && (first ? first.length + 1 : 0) + words[0].length <= n) first += (first ? ' ' : '') + words.shift();
  if (!first) return [s.slice(0, n), cut(s.slice(n), n)];
  return [first, cut(words.join(' '), n)].filter(Boolean);
}
const cut = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

/**
 * The card's drawing: the header (title, and the program's name, which a card can never hide),
 * then the items in fixed slots, top to bottom (one item fills the screen; a row splits its slot
 * in two). `layer`: a frame is under it (no background of its own, the header on a dark band).
 */
export function layoutCard(card: Card, tool: string, layer: boolean): Prim[] {
  const out: Prim[] = [];
  if (!layer) out.push({ k: 'rect', x: 0, y: 0, w: SIZE, h: SIZE, color: INK.bg });
  else out.push({ k: 'rect', x: 0, y: 0, w: SIZE, h: HEADER, color: INK.bg, alpha: 0.78 });
  const name = cleanLine(tool, LIMITS.tool);
  if (card.title) out.push({ k: 'text', x: PAD, y: 20, text: card.title, size: 13, color: INK.text, align: 'left', bold: true, maxW: name ? 128 : SIZE - 2 * PAD });
  if (name) out.push({ k: 'text', x: SIZE - PAD, y: 20, text: name, size: 11, color: INK.muted, align: 'right', maxW: card.title ? 84 : SIZE - 2 * PAD });
  const n = card.items.length;
  const slot = (BOTTOM - TOP) / n;
  const w = SIZE - 2 * PAD;
  card.items.forEach((it, i) => {
    const y = Math.round(TOP + i * slot);
    const h = Math.round(slot);
    if (it.t === 'row') {
      const gap = 12;
      const cw = it.items.length === 2 ? (w - gap) / 2 : w;
      it.items.forEach((k, j) => out.push(...leafPrims(k, Math.round(PAD + j * (cw + gap)), y, Math.round(cw), h, false)));
    } else out.push(...leafPrims(it, PAD, y, w, h, n === 1));
  });
  return out;
}

/** Draws a layout on a 240 x 240 canvas (the fallback: a screen module without `miblo_screen_card`). */
export function drawPrims(ctx: CanvasRenderingContext2D, prims: Prim[], font = 'system-ui, sans-serif') {
  for (const p of prims) {
    ctx.save();
    switch (p.k) {
      case 'rect':
        if (p.w <= 0 || p.h <= 0) break;
        ctx.globalAlpha = p.alpha ?? 1;
        ctx.fillStyle = p.color;
        if (p.r && typeof ctx.roundRect === 'function') {
          ctx.beginPath();
          ctx.roundRect(p.x, p.y, p.w, p.h, Math.min(p.r, p.w / 2, p.h / 2));
          ctx.fill();
        } else ctx.fillRect(p.x, p.y, p.w, p.h);
        break;
      case 'text': {
        let size = p.size;
        const set = () => (ctx.font = `${p.bold ? '700 ' : ''}${size}px ${font}`);
        set();
        // A value too wide for its slot shrinks (to 10 px), then is cut with "…".
        while (size > 10 && ctx.measureText(p.text).width > p.maxW) {
          size -= 1;
          set();
        }
        let text = p.text;
        while (text.length > 1 && ctx.measureText(text).width > p.maxW) text = `${Array.from(text).slice(0, -2).join('')}…`;
        ctx.fillStyle = p.color;
        ctx.textAlign = p.align;
        ctx.textBaseline = 'alphabetic';
        ctx.fillText(text, p.x, p.y);
        break;
      }
      case 'ring': {
        ctx.lineWidth = p.width;
        ctx.lineCap = 'round';
        ctx.strokeStyle = INK.track;
        ctx.beginPath();
        ctx.arc(p.cx, p.cy, p.r - p.width / 2, 0, Math.PI * 2);
        ctx.stroke();
        if (p.value > 0) {
          ctx.strokeStyle = p.color;
          ctx.beginPath();
          ctx.arc(p.cx, p.cy, p.r - p.width / 2, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * p.value);
          ctx.stroke();
        }
        break;
      }
      case 'line':
        ctx.lineWidth = p.width;
        ctx.lineJoin = 'round';
        ctx.lineCap = 'round';
        ctx.strokeStyle = p.color;
        ctx.beginPath();
        p.pts.forEach(([x, y], i) => (i ? ctx.lineTo(x, y) : ctx.moveTo(x, y)));
        ctx.stroke();
        break;
    }
    ctx.restore();
  }
}

// ---- the frame (MFRM1) ----

export const MAX_RLE = 60_000;

let crcTable: Uint32Array | null = null;
/** CRC-32 (IEEE), as the pet and frame files use it. */
export function crc32(b: Uint8Array): number {
  if (!crcTable) {
    crcTable = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crcTable[n] = c >>> 0;
    }
  }
  let c = 0xffffffff;
  for (let i = 0; i < b.length; i++) c = crcTable[(c ^ b[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

export interface Frame {
  /** 240 x 240 RGB565, as the screen module's framebuffer. */
  rgb565: Uint16Array;
  /** The same as RGBA, for a canvas. */
  rgba: Uint8ClampedArray<ArrayBuffer>;
}

/** RGB565 to RGBA, as the screen module's toRgba does. */
export function rgb565ToRgba(c: number, out: Uint8ClampedArray, at: number) {
  const r = (c >> 11) & 31;
  const g = (c >> 5) & 63;
  const b = c & 31;
  out[at] = (r << 3) | (r >> 2);
  out[at + 1] = (g << 2) | (g >> 4);
  out[at + 2] = (b << 3) | (b >> 2);
  out[at + 3] = 255;
}

/**
 * An MFRM1 file decoded, or null when it is not a valid one (the gadget's own checks: the header,
 * 2..64 colours, the RLE length, the exact file length, the CRC, runs of 1..255 of a palette
 * index, exactly 57600 pixels).
 */
export function decodeFrame(b: Uint8Array): Frame | null {
  if (b.length < 12 || String.fromCharCode(...b.subarray(0, 5)) !== 'MFRM1') return null;
  const n = b[5];
  if (n < 2 || n > 64 || b.length < 8 + 2 * n) return null;
  const l = b[6 + 2 * n] | (b[7 + 2 * n] << 8);
  if (l > MAX_RLE || l % 2 !== 0 || b.length !== 8 + 2 * n + l + 4) return null;
  const crc = (b[b.length - 4] | (b[b.length - 3] << 8) | (b[b.length - 2] << 16) | (b[b.length - 1] << 24)) >>> 0;
  if (crc32(b.subarray(0, b.length - 4)) !== crc) return null;
  const palette = new Uint16Array(n);
  for (let i = 0; i < n; i++) palette[i] = b[6 + 2 * i] | (b[7 + 2 * i] << 8);
  const rgb565 = new Uint16Array(PIXELS);
  let px = 0;
  for (let i = 8 + 2 * n, end = i + l; i < end; i += 2) {
    const count = b[i];
    const idx = b[i + 1];
    if (count === 0 || idx >= n || px + count > PIXELS) return null;
    rgb565.fill(palette[idx], px, px + count);
    px += count;
  }
  if (px !== PIXELS) return null;
  const rgba = new Uint8ClampedArray(new ArrayBuffer(PIXELS * 4));
  for (let i = 0; i < PIXELS; i++) rgb565ToRgba(rgb565[i], rgba, i * 4);
  return { rgb565, rgba };
}

/** An MFRM1 file of 240 x 240 RGB565 pixels with at most 64 colours (the previews and the tests; the SDK has the real converter). */
export function encodeFrame(pixels: Uint16Array): Uint8Array {
  const colours = [...new Set(pixels)];
  if (colours.length > 64) throw new Error('too many colours');
  while (colours.length < 2) colours.push(0);
  const index = new Map(colours.map((c, i) => [c, i]));
  const rle: number[] = [];
  for (let y = 0; y < SIZE; y++) {
    let x = 0;
    while (x < SIZE) {
      const c = pixels[y * SIZE + x];
      let run = 1;
      while (x + run < SIZE && run < 255 && pixels[y * SIZE + x + run] === c) run++;
      rle.push(run, index.get(c)!);
      x += run;
    }
  }
  if (rle.length > MAX_RLE) throw new Error('frame too large');
  const out = new Uint8Array(8 + 2 * colours.length + rle.length + 4);
  out.set([0x4d, 0x46, 0x52, 0x4d, 0x31, colours.length]);
  colours.forEach((c, i) => out.set([c & 0xff, c >> 8], 6 + 2 * i));
  const at = 6 + 2 * colours.length;
  out.set([rle.length & 0xff, rle.length >> 8], at);
  out.set(rle, at + 2);
  const crc = crc32(out.subarray(0, out.length - 4));
  out.set([crc & 0xff, (crc >>> 8) & 0xff, (crc >>> 16) & 0xff, crc >>> 24], out.length - 4);
  return out;
}

// ---- the App screen in a snapshot ----

export interface ScreenApp {
  card: Card;
  /** The card as received (what the core's `miblo_screen_card` is given, with `tool`). */
  json: string;
  /** The program that set it (its Status API tool name); '' when the bridge sends none. */
  tool: string;
  /** The frame under it, or null. */
  bg: number | null;
  /** When that frame was written (ms), when the bridge says; a change fetches it again. */
  frameAt: number | null;
}

/**
 * The App screen a snapshot carries (`screen: {card, bg, tool?, frames?}`), or null: none, or a
 * card the core would refuse. `bg` beside the card wins over the card's own.
 */
export function screenAppOf(snapshot: unknown): ScreenApp | null {
  if (!isObj(snapshot) || !isObj(snapshot.screen)) return null;
  const s = snapshot.screen;
  if (isObj(s.card) && JSON.stringify(s.card).length > LIMITS.json * 4) return null;
  const card = parseCard(s.card);
  if (!card) return null;
  const tool = cleanLine(s.tool, LIMITS.tool);
  const bg = s.bg === undefined || s.bg === null ? card.bg : frameSlot(s.bg);
  const fr = Array.isArray(s.frames) ? s.frames.find((f) => isObj(f) && f.slot === bg) : null;
  const at = isObj(fr) && typeof fr.at === 'number' && Number.isFinite(fr.at) ? fr.at : null;
  const json = JSON.stringify({ ...(s.card as Record<string, unknown>), bg: bg === null ? undefined : `frame:${bg}`, tool });
  return { card: { ...card, bg }, json, tool, bg, frameAt: at };
}
