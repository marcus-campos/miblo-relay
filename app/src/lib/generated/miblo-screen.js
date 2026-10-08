// The ESM loader of miblo-screen.wasm (the Miblo's screen for the apps: docs/screen-in-app.md).
// No Emscripten runtime: the module imports three WASI stubs and nothing else. Works in browsers,
// webviews and Node 18+. Copied next to the wasm by tools/screenweb/build.sh.

/** The firmware's languages, in miblo::Lang order. */
export const LANGS = ['en', 'pt-BR', 'pt-PT', 'es', 'fr', 'it', 'de'];

/** miblo::ScreenId names, in order (miblo_policy.h). */
export const SCREENS = ['Boot', 'Setup', 'WrongPassword', 'JoinFailed', 'Welcome', 'Paired', 'PairCode', 'PresenceCode',
  'Updating', 'Disconnected', 'AlertFlash', 'AlertHero', 'Main', 'HardResetCountdown', 'Desk', 'Roam',
  'UpdateAvailable', 'LimitReset', 'Summary', 'Visit', 'Hello', 'Focus', 'Timer', 'Note', 'Cue', 'Find', 'Nudge',
  'DayEnd', 'WeekRecap', 'Fanfare', 'Passerby', 'Preview', 'Identify'];

export const SIZE = 240;
const INPUT_MAX = 6144;  // miblo::kSnapshotMaxBytes
const PET_MAX = 8192;    // miblo::kPetFileMax
const MODES = { overview: 0, limits: 1, sessions: 2 };

/**
 * Instantiates the module. `source`: the wasm's bytes, a Response (or a promise of one, e.g.
 * fetch(url)) or a compiled WebAssembly.Module. Each instance is a screen of its own.
 */
export async function loadMibloScreen(source) {
  let mem = null;
  const wasi = {
    environ_sizes_get: (count, size) => {
      const v = new DataView(mem.buffer);
      v.setUint32(count, 0, true);
      v.setUint32(size, 0, true);
      return 0;
    },
    environ_get: () => 0,
    fd_close: () => 0,
    // The firmware's serial log (printf): dropped, every byte reported written.
    fd_write: (fd, iovs, count, written) => {
      const v = new DataView(mem.buffer);
      let n = 0;
      for (let i = 0; i < count; i++) n += v.getUint32(iovs + i * 8 + 4, true);
      v.setUint32(written, n, true);
      return 0;
    },
    fd_seek: () => 70,  // ESPIPE: the log is not seekable
  };
  const imports = { wasi_snapshot_preview1: wasi };
  const src = await source;
  let instance;
  if (src instanceof WebAssembly.Module) instance = await WebAssembly.instantiate(src, imports);
  else if (typeof Response !== 'undefined' && src instanceof Response) {
    const bytes = await src.arrayBuffer();
    instance = (await WebAssembly.instantiate(bytes, imports)).instance;
  } else instance = (await WebAssembly.instantiate(src, imports)).instance;
  const x = instance.exports;
  mem = x.memory;
  x._initialize();
  const enc = new TextEncoder();
  const put = (text) => {
    const b = enc.encode(text);
    if (b.length >= INPUT_MAX) return -1;
    new Uint8Array(mem.buffer, x.miblo_screen_input(), b.length).set(b);
    return b.length;
  };
  const langIndex = (lang) => {
    const i = LANGS.indexOf(lang);
    if (i >= 0) return i;
    const base = LANGS.findIndex((l) => l.split('-')[0] === String(lang).split('-')[0]);
    return base >= 0 ? base : 0;
  };

  return {
    exports: x,
    /** The factory settings with these, every clock and the snapshot reset. */
    init({ lang = 'en', pet = 0, mascot = 0, petMin = 15, sleepMin = 60, mode = 'overview' } = {}) {
      x.miblo_screen_init(langIndex(lang), pet, mascot, petMin, sleepMin, MODES[mode] ?? 0);
    },
    /** Owner settings as the gadget's settings patch (mode, rotate, insist, fanfareMin, workFrom...): 0 ok, 1 bad JSON, 2 refused. */
    config(patch) {
      const n = put(JSON.stringify(patch));
      return n < 0 ? 1 : x.miblo_screen_config(n);
    },
    /** A look code (MIBLO1:...); `myPet`: My pet with that look. false when the code is not valid. */
    look(code, myPet = false) {
      const n = put(String(code));
      return n >= 0 && x.miblo_screen_look(n, myPet ? 1 : 0) === 0;
    },
    /** The time zone: an IANA name (the firmware's table) or a POSIX rule. */
    zone(name) {
      const n = put(String(name));
      if (n >= 0) x.miblo_screen_tz(n);
    },
    /** The bridge's snapshot (object or JSON text), as the gadget gets it: 0 ok, else miblo::ParseResult. */
    feed(snapshot, nowMs) {
      const n = put(typeof snapshot === 'string' ? snapshot : JSON.stringify(snapshot));
      return n < 0 ? 1 : x.miblo_screen_feed(n, nowMs >>> 0);
    },
    /** My pet's file (MPET1/MPET2), or null to remove it: 0 ok, else miblo::PetError. */
    petLoad(bytes) {
      if (!bytes || !bytes.length) return x.miblo_screen_pet_load(0);
      if (bytes.length > PET_MAX) return 1;
      new Uint8Array(mem.buffer, x.miblo_screen_pet_buffer(), bytes.length).set(bytes);
      return x.miblo_screen_pet_load(bytes.length);
    },
    /** One frame at `nowMs` (any monotonic ms clock) and `epochSec` (wall clock): the screen drawn, or 'asleep'. */
    tick(nowMs, epochSec) {
      const id = x.miblo_screen_tick(nowMs >>> 0, epochSec >>> 0);
      return { id, screen: id === 255 ? 'asleep' : SCREENS[id] ?? String(id) };
    },
    /** screens::DeskMood last used by pet mode. */
    mood() {
      return x.miblo_screen_mood();
    },
    /** The 240 x 240 RGB565 framebuffer (a view into the module's memory: copy it to keep it). */
    pixels() {
      return new Uint16Array(mem.buffer, x.miblo_screen_fb(), SIZE * SIZE);
    },
    /** The framebuffer as RGBA into `out` (SIZE * SIZE * 4 bytes, e.g. an ImageData's data). */
    toRgba(out) {
      const px = new Uint16Array(mem.buffer, x.miblo_screen_fb(), SIZE * SIZE);
      for (let i = 0, o = 0; i < px.length; i++, o += 4) {
        const c = px[i];
        const r = c >> 11, g = (c >> 5) & 63, b = c & 31;
        out[o] = (r << 3) | (r >> 2);
        out[o + 1] = (g << 2) | (g >> 4);
        out[o + 2] = (b << 3) | (b >> 2);
        out[o + 3] = 255;
      }
      return out;
    },
  };
}
