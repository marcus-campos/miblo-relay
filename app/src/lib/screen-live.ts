// The Miblo's screen, live: the gadget's own firmware (its choice of screen and its drawing)
// compiled to WebAssembly (generated/miblo-screen.js, from the product repository's
// `make screenweb-publish`), fed the snapshot the bridge sends the gadgets. 10 frames a second
// while the canvas is on screen and the page visible; nothing otherwise. 1.25: a program's App
// screen (screen-card.ts) over the ordinary screens, its frame under it.
//
// The same file is in the desktop app (installer/src/lib) and the phone app (web/src/lib, and the
// self-hosted relay's copy): keep them identical.

import type { MibloScreen, Tick } from './generated/miblo-screen.js';
import { decodeFrame, drawPrims, layoutCard, screenAppOf, type Frame, type ScreenApp } from './screen-card';

/** The app's language: the firmware's is pt-BR or en. */
export type Lang = 'pt' | 'en';

/** The first paired Miblo, as the bridge reads it (plugin lib/miblo-mirror.js screenLook). */
export interface ScreenMiblo {
  name?: string;
  look?: string;
  myPet?: boolean;
  /** My pet's file: its hash, and the file itself (base64). */
  pet?: string;
  petFile?: string;
  petMin?: number;
  sleepMin?: number;
}

/** `status --screen`'s `screen`: the snapshot the gadgets got last (null: no bridge) and the first Miblo. */
export interface ScreenFeed {
  snapshot: Record<string, unknown> | null;
  miblo: ScreenMiblo | null;
}

/** The look a new Miblo has (every field 0: the cat, the first colours, no items). */
export const FACTORY_LOOK = 'MIBLO1:AAAAAAAAAA';
export const FRAME_MS = 100;
export const SIZE = 240;

/** The firmware's language for the app's. */
export const screenLang = (l: Lang) => (l === 'pt' ? 'pt-BR' : 'en');

export interface LiveDeps {
  /** Instantiates the module (the app: fetch of the bundled wasm). */
  load: () => Promise<MibloScreen>;
  /** A monotonic clock, ms. */
  nowMs: () => number;
  /** The wall clock, seconds. */
  epochSec: () => number;
  /** This computer's time zone (IANA). */
  zone: () => string;
  /** The canvas to draw on, when it is in the page. */
  canvas: () => HTMLCanvasElement | null;
  /** The window is hidden (minimised, in the tray). */
  hidden: () => boolean;
  every: (fn: () => void, ms: number) => unknown;
  stop: (handle: unknown) => void;
  /** 1.25: a frame of the App screen (MFRM1) from the running bridge; null when there is none. */
  frame?: (slot: number) => Promise<Uint8Array | null>;
  /** The font the Canvas fallback draws a card with. */
  font?: string;
}

/**
 * The screens the App screen may take the place of: the ordinary ones. "Needs you", the fanfare,
 * a focus, a timer, a note and every other Miblo screen keep priority, as on the gadget.
 */
export const APP_OVER: ReadonlySet<string> = new Set(['Main', 'Desk', 'Roam', 'Summary', 'Disconnected']);
/** A frame is fetched again after this long when the bridge does not say when it changed. */
export const FRAME_TTL_MS = 60_000;

/**
 * The card renderer of a newer screen module (firmware 1.25, `miblo_screen_card`): the card JSON
 * in the input buffer, `layer` 1 to draw over the framebuffer as it is (the frame written there),
 * 0 over the screen's own background; 0 when drawn. A wrapper method `card(json, layer)` is used
 * when the loader has one. false: this module has no card renderer (the Canvas fallback draws it).
 */
export function moduleCard(s: MibloScreen, json: string, layer: Frame | null): boolean | null {
  const w = s as MibloScreen & { card?: (json: string, layer: boolean) => number };
  const x = s.exports as Record<string, unknown>;
  const raw = typeof x.miblo_screen_card === 'function' && typeof x.miblo_screen_input === 'function' && x.memory instanceof WebAssembly.Memory;
  if (typeof w.card !== 'function' && !raw) return null;
  if (layer) s.pixels().set(layer.rgb565);
  if (typeof w.card === 'function') return w.card(json, !!layer) === 0;
  const b = new TextEncoder().encode(json);
  if (b.length >= 6144) return false;
  new Uint8Array((x.memory as WebAssembly.Memory).buffer, (x.miblo_screen_input as () => number)(), b.length).set(b);
  return (x.miblo_screen_card as (n: number, layer: number) => number)(b.length, layer ? 1 : 0) === 0;
}

const fromBase64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export class LiveScreen {
  private screen: MibloScreen | null = null;
  private loading: Promise<void> | null = null;
  private failed = false;
  private timer: unknown = null;
  private feedNow: ScreenFeed | null = null;
  private lang: Lang = 'en';
  // What the module has now (applied only when it changes).
  private applied = { lang: '', look: '', pet: '', timing: '', seq: -1 as unknown, zone: '' };
  private rgba: Uint8ClampedArray<ArrayBuffer> | null = null;
  /** The last frame's result (for tests and the page's description). */
  last: Tick | null = null;
  /** 1.25: what was drawn last: the Miblo's own screen, or the App screen (and how). */
  drawn: 'miblo' | 'app-module' | 'app-canvas' | null = null;
  private app: ScreenApp | null = null;
  private frames = new Map<number, { at: number | null; fetched: number; frame: Frame | null }>();
  private fetching = new Set<number>();

  constructor(private readonly d: LiveDeps) {}

  /** The latest feed and the app's language: applied now if the module is ready, else once it is. */
  update(feed: ScreenFeed | null, lang: Lang) {
    this.feedNow = feed;
    this.lang = lang;
    this.app = screenAppOf(feed?.snapshot ?? null);
    if (this.app?.bg != null) this.wantFrame(this.app.bg, this.app.frameAt);
    if (this.screen) this.apply(this.screen);
  }

  /** The App screen the latest snapshot carries (null: none). */
  appNow(): ScreenApp | null {
    return this.app;
  }

  /** Starts loading the module and the frames, if the canvas is on screen. */
  ensureRunning() {
    if (this.failed) {
      // No module: the App screen is still drawn (by the Canvas fallback).
      if (this.app && this.timer === null && this.visible()) this.timer = this.d.every(() => this.frame(), FRAME_MS);
      return;
    }
    if (!this.screen && !this.loading) {
      this.loading = this.d
        .load()
        .then((s) => {
          s.init({ lang: screenLang(this.lang) });
          this.screen = s;
          this.applied.lang = screenLang(this.lang);
          this.apply(s);
        })
        .catch(() => {
          this.failed = true;  // no screen: the rest of the tab works as before
        })
        .finally(() => {
          this.loading = null;
          this.ensureRunning();
        });
    }
    if (this.screen && this.timer === null && this.visible()) this.timer = this.d.every(() => this.frame(), FRAME_MS);
  }

  /** The window was shown or hidden: frames resume or pause. */
  visibilityChanged() {
    if (this.visible()) this.ensureRunning();
    else this.pause();
  }

  pause() {
    if (this.timer !== null) this.d.stop(this.timer);
    this.timer = null;
  }

  private visible() {
    return !this.d.hidden() && this.d.canvas() !== null;
  }

  private apply(s: MibloScreen) {
    const feed = this.feedNow;
    const lang = screenLang(this.lang);
    if (lang !== this.applied.lang) {
      s.config({ lang });
      this.applied.lang = lang;
    }
    const zone = this.d.zone();
    if (zone && zone !== this.applied.zone) {
      s.zone(zone);
      this.applied.zone = zone;
    }
    const m = feed?.miblo ?? null;
    const myPet = !!(m?.myPet && m.pet && m.petFile);
    const look = `${m?.look ?? FACTORY_LOOK}|${myPet ? 'pet' : ''}`;
    if (look !== this.applied.look) {
      if (!s.look(m?.look ?? FACTORY_LOOK, myPet)) s.look(FACTORY_LOOK, false);
      this.applied.look = look;
    }
    const pet = myPet ? m!.pet! : '';
    if (pet !== this.applied.pet) {
      if (pet) {
        try {
          if (s.petLoad(fromBase64(m!.petFile!)) !== 0) s.look(m?.look ?? FACTORY_LOOK, false);
        } catch {
          s.look(m?.look ?? FACTORY_LOOK, false);
        }
      } else s.petLoad(null);
      this.applied.pet = pet;
    }
    const timing = `${m?.petMin ?? 15}/${m?.sleepMin ?? 60}`;
    if (timing !== this.applied.timing) {
      s.config({ petMin: m?.petMin ?? 15, sleepMin: m?.sleepMin ?? 60 });
      this.applied.timing = timing;
    }
    // Each snapshot once, as the gadget gets it (the bridge sends one at least every 10 s).
    const snap = feed?.snapshot ?? null;
    if (snap && snap.seq !== this.applied.seq) {
      s.feed(snap, this.d.nowMs());
      this.applied.seq = snap.seq;
    }
  }

  /** Fetches a frame slot when it is not here, changed (`at`), or old (no `at`: FRAME_TTL_MS). */
  private wantFrame(slot: number, at: number | null) {
    const have = this.frames.get(slot);
    const fresh = have && (at !== null ? have.at === at : this.d.nowMs() - have.fetched < FRAME_TTL_MS);
    if (fresh || this.fetching.has(slot) || !this.d.frame) return;
    this.fetching.add(slot);
    this.d
      .frame(slot)
      .then((bytes) => (bytes ? decodeFrame(bytes) : null))
      .catch(() => null)
      .then((frame) => {
        // A failed fetch keeps the frame it had (a bridge restarting), and tries again later.
        const old = this.frames.get(slot)?.frame ?? null;
        this.frames.set(slot, { at, fetched: this.d.nowMs(), frame: frame ?? old });
        this.fetching.delete(slot);
      });
  }

  /** The App screen: its frame (if it has one and it came), then the card over it. */
  private drawApp(ctx: CanvasRenderingContext2D, s: MibloScreen | null, app: ScreenApp) {
    if (app.bg !== null) this.wantFrame(app.bg, app.frameAt);
    const layer = app.bg !== null ? (this.frames.get(app.bg)?.frame ?? null) : null;
    if (s && moduleCard(s, app.json, layer)) {
      this.rgba ??= new Uint8ClampedArray(new ArrayBuffer(SIZE * SIZE * 4));
      s.toRgba(this.rgba);
      ctx.putImageData(new ImageData(this.rgba, SIZE, SIZE), 0, 0);
      this.drawn = 'app-module';
      return;
    }
    if (layer) ctx.putImageData(new ImageData(layer.rgba, SIZE, SIZE), 0, 0);
    drawPrims(ctx, layoutCard(app.card, app.tool, !!layer), this.d.font);
    this.drawn = 'app-canvas';
  }

  /** One frame: the module's choice and drawing, onto the canvas (the App screen over an ordinary screen). */
  frame() {
    const s = this.screen;
    const canvas = this.d.canvas();
    const app = this.app;
    if ((!s && !(this.failed && app)) || !canvas || this.d.hidden()) {
      this.pause();
      return;
    }
    const ctx = canvas.getContext('2d');
    if (!s) {
      if (ctx && app) this.drawApp(ctx, null, app);
      return;
    }
    this.last = s.tick(this.d.nowMs(), this.d.epochSec());
    if (!ctx) return;
    if (app && APP_OVER.has(this.last.screen)) {
      this.drawApp(ctx, s, app);
      return;
    }
    this.drawn = 'miblo';
    if (this.last.screen === 'asleep') {
      // The panel off, as on the gadget.
      ctx.fillStyle = '#000';
      ctx.fillRect(0, 0, SIZE, SIZE);
      return;
    }
    this.rgba ??= new Uint8ClampedArray(new ArrayBuffer(SIZE * SIZE * 4));
    s.toRgba(this.rgba);
    ctx.putImageData(new ImageData(this.rgba, SIZE, SIZE), 0, 0);
  }
}
