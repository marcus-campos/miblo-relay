// Types of miblo-screen.js (the Miblo's screen for the apps: docs/screen-in-app.md).

export declare const LANGS: readonly ['en', 'pt-BR', 'pt-PT', 'es', 'fr', 'it', 'de'];
export declare const SCREENS: readonly string[];
export declare const SIZE: 240;

export type ScreenName =
  | 'Boot' | 'Setup' | 'WrongPassword' | 'JoinFailed' | 'Welcome' | 'Paired' | 'PairCode' | 'PresenceCode'
  | 'Updating' | 'Disconnected' | 'AlertFlash' | 'AlertHero' | 'Main' | 'HardResetCountdown' | 'Desk' | 'Roam'
  | 'UpdateAvailable' | 'LimitReset' | 'Summary' | 'Visit' | 'Hello' | 'Focus' | 'Timer' | 'Note' | 'Cue' | 'Find'
  | 'Nudge' | 'DayEnd' | 'WeekRecap' | 'Fanfare' | 'Passerby' | 'Preview' | 'Identify';

export interface ScreenInit {
  /** One of LANGS (a base language picks its first variant); default 'en'. */
  lang?: string;
  /** miblo::Pet (0 the cat .. 21 My pet). */
  pet?: number;
  /** The colour preset (0..). */
  mascot?: number;
  /** Pet mode after this many quiet minutes (1..60). */
  petMin?: number;
  /** The panel off after this many (0 = never). */
  sleepMin?: number;
  mode?: 'overview' | 'limits' | 'sessions';
}

/** The owner's settings that change behaviour, as the gadget's settings patch (miblo_config.cpp applyConfigPatch). */
export interface ScreenConfig {
  mode?: 'overview' | 'limits' | 'sessions';
  lang?: string;
  tz?: string;
  rotate?: boolean;
  rotateEverySec?: number;
  rotateShowSec?: number;
  insist?: boolean;
  fanfareMin?: number;
  petMin?: number;
  sleepMin?: number;
  name?: string;
  owner?: string;
  /** "MM-DD". */
  birthday?: string;
  endOfDay?: boolean;
  workFrom?: number;
  workTo?: number;
  workDays?: number;
  frame?: boolean;
  discreet?: boolean;
  [field: string]: unknown;
}

export interface Tick {
  /** miblo::ScreenId, 255 when asleep. */
  id: number;
  screen: ScreenName | 'asleep';
}

export interface MibloScreen {
  /** The raw exports: miblo_screen_*, and the look renderer's miblo_look_* / miblo_pet_*. */
  readonly exports: WebAssembly.Exports;
  init(init?: ScreenInit): void;
  /** 0 ok, 1 bad JSON, 2 a field refused (nothing applied). */
  config(patch: ScreenConfig): number;
  /** A look code (MIBLO1:...); false when it is not valid. */
  look(code: string, myPet?: boolean): boolean;
  /** An IANA zone ("America/Sao_Paulo") or a POSIX rule ("<-03>3"). */
  zone(name: string): void;
  /** The bridge's snapshot: 0 ok, 1 too large, 2 bad JSON, 3 bad version. */
  feed(snapshot: unknown, nowMs: number): number;
  /** My pet's MPET1/MPET2 file, or null to remove it: 0 ok, else miblo::PetError. */
  petLoad(bytes: Uint8Array | null): number;
  tick(nowMs: number, epochSec: number): Tick;
  mood(): number;
  /** The framebuffer, 240 x 240 RGB565 (a view into the module's memory). */
  pixels(): Uint16Array;
  /** The framebuffer as RGBA into `out` (240 * 240 * 4 bytes). */
  toRgba<T extends Uint8Array | Uint8ClampedArray>(out: T): T;
}

export declare function loadMibloScreen(
  source: BufferSource | Response | PromiseLike<Response> | WebAssembly.Module,
): Promise<MibloScreen>;
