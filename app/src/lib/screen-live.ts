// The Miblo's screen, live: the gadget's own firmware (its choice of screen and its drawing)
// compiled to WebAssembly (generated/miblo-screen.js, from the product repository's
// `make screenweb-publish`), fed the snapshot the bridge sends the gadgets. 10 frames a second
// while the canvas is on screen and the page visible; nothing otherwise. 1.25: a program's App
// screen (screen-card.ts) over the ordinary screens, its frame under it. 1.26: the App screen's
// animation (screen-anim.ts: frames, tiles and sprites, Mode 7, meshes, the card effects) at its
// own fps, never above, with requestAnimationFrame when the host gives it.
//
// The same file is in the desktop app (installer/src/lib) and the phone app (web/src/lib, and the
// self-hosted relay's copy): keep them identical.

import type { MibloScreen, Tick } from './generated/miblo-screen.js';
import { decodeAnyFrame, decodeFrame, drawPrims, rgb565ToRgba, screenAppOf, type Frame, type RectFrame, type ScreenApp } from './screen-card';
import { BASE_FPS, blankLayer, decodeAnimData, decodeTiles, drawFrameStep, FrameGate, FxPlayer, parseAnim, playFps, realOf, renderTiles, stepAt, stepStart, type AnimData, type AnimInfo, type TileSet } from './screen-anim';

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
  /**
   * 1.26: the display's frame callback (requestAnimationFrame) and its cancel. With them the screen
   * draws in step with the display at the rate it needs (an animation's fps, never above; the
   * Miblo's own 10 otherwise); without them, every FRAME_MS.
   */
  raf?: (fn: () => void) => unknown;
  cancelRaf?: (handle: unknown) => void;
  /** 1.25: a frame of the App screen (MFRM1) from the running bridge; null when there is none. */
  frame?: (slot: number) => Promise<Uint8Array | null>;
  /** 1.26: an animation's tile set and its maps/sprites (`/sdk/v1/screen/tiles|anim/<slot>`). */
  tiles?: (slot: number) => Promise<Uint8Array | null>;
  animData?: (slot: number) => Promise<Uint8Array | null>;
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

/** Pixels written to the module's framebuffer as the layer under the card. */
type Layer = { rgb565: Uint16Array };

/**
 * The card renderer of a newer screen module (firmware 1.25, `miblo_screen_card`): the card JSON
 * in the input buffer, `layer` 1 to draw over the framebuffer as it is (the frame written there),
 * 0 over the screen's own background; 0 when drawn. A wrapper method `card(json, layer)` is used
 * when the loader has one. false: this module has no card renderer (the Canvas fallback draws it).
 */
export function moduleCard(s: MibloScreen, json: string, layer: Layer | null): boolean | null {
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

/**
 * 1.26's player in a module (firmware anim-fw-tiles / anim-fw-fx): `miblo_screen_tiles(n)` and
 * `miblo_screen_anim(n)` take a tile set and its animation data written to the frame buffer (or
 * the input buffer when the module has none); `miblo_screen_anim_tick(ms)` draws the animation
 * into the framebuffer at `ms` of playback (time since it started, so the app joins the gadget at
 * its step and "Parar" holds it); `miblo_screen_fx_tick(ms)` draws the card's effects over it at
 * `ms` of the monotonic clock (the one `tick(nowMs)` gets: effects follow card updates). Mode 7 and
 * meshes take their parameters through the loader's `mode7(params)` / `mesh(params)`. Each part is
 * null when the module predates it.
 */
export interface ModuleAnim {
  load: ((tiles: Uint8Array, anim: Uint8Array) => boolean) | null;
  animTick: ((ms: number) => void) | null;
  fxTick: ((ms: number) => void) | null;
  mode7: ((params: unknown) => boolean) | null;
  mesh: ((params: unknown) => boolean) | null;
}

export function moduleAnim(s: MibloScreen): ModuleAnim {
  const x = s.exports as Record<string, unknown>;
  const w = s as MibloScreen & Record<string, unknown>;
  const fn = (k: string) => (typeof x[k] === 'function' ? (x[k] as (...a: number[]) => number) : null);
  const mem = x.memory instanceof WebAssembly.Memory ? x.memory : null;
  const buf = fn('miblo_screen_frame_buffer');
  const input = fn('miblo_screen_input');
  const put = (b: Uint8Array) => {
    // The frame buffer holds 60140 bytes, the input 6144.
    const at = buf && b.length <= 60_140 ? buf() : input && b.length < 6144 ? input() : null;
    if (at === null || !mem) return false;
    new Uint8Array(mem.buffer, at, b.length).set(b);
    return true;
  };
  const tiles = fn('miblo_screen_tiles');
  const anim = fn('miblo_screen_anim');
  const animTick = fn('miblo_screen_anim_tick');
  const fxTick = fn('miblo_screen_fx_tick');
  const method = (k: string) => (typeof w[k] === 'function' ? (p: unknown) => (w[k] as (p: unknown) => number)(p) === 0 : null);
  return {
    load: tiles && anim && mem ? (t, a) => put(t) && tiles(t.length) === 0 && put(a) && anim(a.length) === 0 : null,
    animTick: animTick ? (ms) => void animTick(ms >>> 0) : null,
    fxTick: fxTick ? (ms) => void fxTick(ms >>> 0) : null,
    mode7: method('mode7'),
    mesh: method('mesh'),
  };
}

const fromBase64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

/** A slot's file from the bridge, kept with when it was written and when it came. */
interface Cached {
  at: number | null;
  fetched: number;
  bytes: Uint8Array | null;
}
type Kind = 'frame' | 'tiles' | 'anim';

/** What the page may say about the App screen's animation. */
export interface AnimView {
  info: AnimInfo;
  /** Drawn here: by the module, by the Canvas fallback, or not (its data stays on the Miblo). */
  where: 'module' | 'canvas' | 'gadget';
  stopped: boolean;
}

export class LiveScreen {
  private screen: MibloScreen | null = null;
  private loading: Promise<void> | null = null;
  private failed = false;
  private timer: unknown = null;
  private loopToken: object | null = null;
  private gate = new FrameGate();
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
  private cache = new Map<string, Cached>();
  private fetching = new Set<string>();
  private decoded = new Map<string, { bytes: Uint8Array; value: unknown }>();
  // 1.26: the animation and the card effects.
  private anim: AnimInfo | null = null;
  private animStart = 0;
  private stoppedSig: string | null = null;
  private stoppedAt = 0;
  private fx = new FxPlayer();
  private layer: Uint16Array | null = null;
  private layerKey = '';
  private layerRgba: Uint8ClampedArray<ArrayBuffer> | null = null;
  private layerRgbaKey = '';
  private moduleLoaded = '';
  private real: { fps: number | null; drawMs: number | null } = { fps: null, drawMs: null };
  /** How the animation was drawn last (null: none played). */
  animWhere: AnimView['where'] | null = null;

  constructor(private readonly d: LiveDeps) {}

  /** The latest feed and the app's language: applied now if the module is ready, else once it is. */
  update(feed: ScreenFeed | null, lang: Lang) {
    this.feedNow = feed;
    this.lang = lang;
    this.app = screenAppOf(feed?.snapshot ?? null);
    const scr = isObj(feed?.snapshot?.screen) ? feed!.snapshot!.screen : null;
    this.real = realOf(scr);
    const anim = this.app ? parseAnim(scr, this.app.card) : null;
    if (anim?.sig !== this.anim?.sig) {
      // A new animation starts where the gadget is (its step), a stop is forgotten.
      this.animStart = this.d.nowMs() - (anim?.steps ? stepStart(anim.steps, anim.step) : 0);
      this.layerKey = '';
      this.stoppedSig = null;
    }
    this.anim = anim;
    if (this.app?.bg != null) this.want('frame', this.app.bg, this.app.frameAt);
    this.wantAnim();
    if (this.screen) this.apply(this.screen);
  }

  /** The App screen the latest snapshot carries (null: none). */
  appNow(): ScreenApp | null {
    return this.app;
  }

  /** The App screen's animation, and how it is drawn here (null: none). */
  animNow(): AnimView | null {
    if (!this.anim) return null;
    return { info: this.anim, where: this.animWhere ?? (this.canPlayHere() ? 'canvas' : 'gadget'), stopped: this.stoppedSig === this.anim.sig };
  }

  /** What the gadget measures: its real fps and its last draw (null when it does not say). */
  stats(): { fps: number | null; drawMs: number | null; rate: number } {
    return { ...this.real, rate: this.rate() };
  }

  /** "Parar" / "Continuar": holds the animation on its current frame here (the Miblo keeps playing). */
  setAnimStopped(stop: boolean) {
    if (!this.anim) return;
    const now = this.d.nowMs();
    if (stop && this.stoppedSig !== this.anim.sig) {
      this.stoppedSig = this.anim.sig;
      this.stoppedAt = now;
    } else if (!stop && this.stoppedSig) {
      this.animStart += now - this.stoppedAt;
      this.stoppedSig = null;
    }
  }

  /** Starts loading the module and the frames, if the canvas is on screen. */
  ensureRunning() {
    if (this.failed) {
      // No module: the App screen is still drawn (by the Canvas fallback).
      if (this.app && this.visible()) this.startLoop();
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
    if (this.screen && this.visible()) this.startLoop();
  }

  /** The window was shown or hidden: frames resume or pause. */
  visibilityChanged() {
    if (this.visible()) this.ensureRunning();
    else this.pause();
  }

  pause() {
    if (this.timer !== null) {
      if (this.loopToken && this.d.cancelRaf) this.d.cancelRaf(this.timer);
      else if (!this.loopToken) this.d.stop(this.timer);
    }
    this.timer = null;
    this.loopToken = null;
  }

  private startLoop() {
    if (this.timer !== null) return;
    const raf = this.d.raf;
    if (!raf) {
      this.timer = this.d.every(() => this.frame(), FRAME_MS);
      return;
    }
    const token = {};
    this.loopToken = token;
    this.gate.reset();
    const loop = () => {
      if (this.loopToken !== token) return;
      if (this.gate.due(this.d.nowMs(), this.rate())) this.frame();
      if (this.loopToken === token) this.timer = raf(loop);
    };
    this.timer = raf(loop);
  }

  /** Frames a second the screen needs now: the App screen's animation or effects, else the Miblo's 10. */
  private rate(): number {
    if (this.drawn !== 'app-module' && this.drawn !== 'app-canvas') return BASE_FPS;
    const fx = this.fx.running(this.d.nowMs());
    const a = this.anim;
    if (!a || this.stoppedSig === a.sig) return playFps(null, fx);
    // An animation whose pictures stay on the Miblo (the phone): only the card moves here, at its
    // own rate, still never above the animation's.
    if (this.animWhere === 'gadget') return Math.min(playFps(null, fx), playFps(a, false));
    return playFps(a, fx);
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

  private fetcher(kind: Kind) {
    return kind === 'frame' ? this.d.frame : kind === 'tiles' ? this.d.tiles : this.d.animData;
  }

  /** Fetches a slot's file when it is not here, changed (`at`), or old (no `at`: FRAME_TTL_MS). */
  private want(kind: Kind, slot: number, at: number | null) {
    const key = `${kind}:${slot}`;
    const have = this.cache.get(key);
    const fresh = have && (at !== null ? have.at === at : this.d.nowMs() - have.fetched < FRAME_TTL_MS);
    const get = this.fetcher(kind);
    if (fresh || this.fetching.has(key) || !get) return;
    this.fetching.add(key);
    get(slot)
      .catch(() => null)
      .then((bytes) => {
        // A failed fetch keeps the file it had (a bridge restarting), and tries again later.
        const old = this.cache.get(key)?.bytes ?? null;
        this.cache.set(key, { at, fetched: this.d.nowMs(), bytes: bytes ?? old });
        this.fetching.delete(key);
      });
  }

  /**
   * A slot's file decoded (once per file and decoder: a slot may be the card's background and a
   * step of its animation), or null when it is not here or not valid.
   */
  private get<T>(kind: Kind, slot: number, as: string, decode: (b: Uint8Array) => T | null): T | null {
    const bytes = this.cache.get(`${kind}:${slot}`)?.bytes ?? null;
    if (!bytes) return null;
    const key = `${kind}:${slot}:${as}`;
    const d = this.decoded.get(key);
    if (d && d.bytes === bytes) return d.value as T | null;
    const value = decode(bytes);
    this.decoded.set(key, { bytes, value });
    return value;
  }

  private frameAt(slot: number): number | null {
    const scr = this.feedNow?.snapshot?.screen;
    const fr = isObj(scr) && Array.isArray(scr.frames) ? scr.frames.find((f) => isObj(f) && f.slot === slot) : null;
    return isObj(fr) && typeof fr.at === 'number' && Number.isFinite(fr.at) ? fr.at : (this.anim?.at ?? null);
  }

  /** Asks for what the animation needs: its frames, or its tile set and data. */
  private wantAnim() {
    const a = this.anim;
    if (!a) return;
    if (a.kind === 'frames') for (const st of a.steps ?? []) this.want('frame', st.slot, this.frameAt(st.slot));
    else if (a.slot !== null) {
      this.want('tiles', a.slot, a.at);
      this.want('anim', a.slot, a.at);
    }
  }

  /** Whether this host can draw the animation at all (the phone has no bridge to fetch it from). */
  private canPlayHere(): boolean {
    const a = this.anim;
    if (!a) return false;
    return a.kind === 'frames' ? !!this.d.frame : !!(this.d.tiles && this.d.animData);
  }

  /** Elapsed playback time (held while stopped). */
  private elapsed(now: number) {
    return (this.anim && this.stoppedSig === this.anim.sig ? this.stoppedAt : now) - this.animStart;
  }

  /**
   * The animation's layer at `now`, composed here (frames, or tiles for a module without the 1.26
   * player); null when nothing plays or its data has not come (the card then draws over its frame).
   */
  private animLayer(now: number, bg: Frame | null): Uint16Array | null {
    const a = this.anim;
    if (!a) return null;
    const t = this.elapsed(now);
    if (a.kind === 'frames') {
      const steps = a.steps!;
      const i = stepAt(steps, t, a.loop);
      const key = `${a.sig}|${i}|${bg ? 'bg' : ''}`;
      if (key === this.layerKey && this.layer) return this.layer;
      const prev = this.layerKey.startsWith(`${a.sig}|`) ? Number(this.layerKey.split('|')[1]) : -1;
      // The next step is drawn over the last (a rectangle frame is a delta); anything else from the start.
      const from = prev >= 0 && i === prev + 1 && this.layer ? i : 0;
      if (from === 0) this.layer = bg ? bg.rgb565.slice() : blankLayer();
      let missing = false;
      for (let k = from; k <= i; k++) {
        const f = this.get<RectFrame>('frame', steps[k].slot, 'play', decodeAnyFrame);
        if (f) drawFrameStep(this.layer!, f, steps[k].cell, a.cell, a.region);
        else missing = true;
      }
      // A frame still on its way: composed again on the next frame, until every one came.
      this.layerKey = missing ? '' : key;
      return this.layer;
    }
    const tiles = a.slot !== null ? this.get<TileSet>('tiles', a.slot, 'tiles', decodeTiles) : null;
    const data = a.slot !== null ? this.get<AnimData>('anim', a.slot, 'anim', decodeAnimData) : null;
    if (!tiles || !data) return null;
    // Mode 7 and meshes need the module: the fallback shows the art still, as its first step.
    // Tiles keep their steps in the data: playback joins the gadget's step there.
    const i = a.kind === 'tiles' ? stepAt(data.steps, t + (a.steps ? 0 : stepStart(data.steps, a.step)), a.loop && data.loop) : 0;
    const key = `${a.sig}|${i}`;
    if (key !== this.layerKey || !this.layer) {
      this.layer ??= blankLayer();
      renderTiles(tiles, data, i, this.layer);
      this.layerKey = key;
    }
    return this.layer;
  }

  /** The module's own player, when it has the 1.26 one and the data came: true when it drew the layer. */
  private moduleLayer(s: MibloScreen, now: number, bg: Frame | null): boolean {
    const a = this.anim;
    if (!a || a.kind === 'frames' || a.slot === null) return false;
    const m = moduleAnim(s);
    if (!m.load || !m.animTick) return false;
    const tiles = this.cache.get(`tiles:${a.slot}`)?.bytes;
    const data = this.cache.get(`anim:${a.slot}`)?.bytes;
    if (!tiles || !data) return false;
    const key = `${a.sig}|${tiles.length}|${data.length}`;
    if (key !== this.moduleLoaded) {
      if (!m.load(tiles, data)) return false;
      if (a.kind === 'mode7' && !(m.mode7 && m.mode7(a.mode7))) return false;
      if (a.kind === 'mesh' && !(m.mesh && m.mesh(a.mesh))) return false;
      this.moduleLoaded = key;
    }
    s.pixels().set(bg ? bg.rgb565 : blankLayer());
    m.animTick(Math.max(0, this.elapsed(now)));
    return true;
  }

  /** The App screen: its frame or animation (if it has one and it came), then the card over it. */
  private drawApp(ctx: CanvasRenderingContext2D, s: MibloScreen | null, app: ScreenApp) {
    const now = this.d.nowMs();
    if (app.bg !== null) this.want('frame', app.bg, app.frameAt);
    this.wantAnim();
    this.fx.update(app.card, now);
    const bg = app.bg !== null ? this.get<Frame>('frame', app.bg, 'bg', decodeFrame) : null;
    const hasFx = app.card.items.some((it) => (it.t === 'row' ? it.items.some((l) => l.fx) : !!it.fx));
    const m = s ? moduleAnim(s) : null;
    // The module draws the card when it can draw its effects too (or the card has none).
    const moduleCards = !!s && (!hasFx || !!m?.fxTick);
    if (s && moduleCards) {
      const native = this.moduleLayer(s, now, bg);
      // Natively drawn: the layer is the framebuffer itself (written onto itself: nothing to copy).
      const layer = native ? { rgb565: s.pixels() } : this.animLayer(now, bg) ? { rgb565: this.layer! } : bg;
      if (moduleCard(s, app.json, layer)) {
        m?.fxTick?.(now);
        this.rgba ??= new Uint8ClampedArray(new ArrayBuffer(SIZE * SIZE * 4));
        s.toRgba(this.rgba);
        ctx.putImageData(new ImageData(this.rgba, SIZE, SIZE), 0, 0);
        this.drawn = 'app-module';
        this.animWhere = this.anim ? (native ? 'module' : layer && layer !== bg ? 'canvas' : 'gadget') : null;
        return;
      }
    }
    const layer = this.animLayer(now, bg);
    if (layer) {
      if (this.layerRgbaKey !== this.layerKey || !this.layerRgba) {
        this.layerRgba ??= new Uint8ClampedArray(new ArrayBuffer(SIZE * SIZE * 4));
        for (let i = 0; i < layer.length; i++) rgb565ToRgba(layer[i], this.layerRgba, i * 4);
        this.layerRgbaKey = this.layerKey;
      }
      ctx.putImageData(new ImageData(this.layerRgba, SIZE, SIZE), 0, 0);
    } else if (bg) ctx.putImageData(new ImageData(bg.rgba, SIZE, SIZE), 0, 0);
    drawPrims(ctx, this.fx.prims(app.tool, !!(layer || bg), now), this.d.font);
    this.drawn = 'app-canvas';
    this.animWhere = this.anim ? (layer ? 'canvas' : 'gadget') : null;
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
