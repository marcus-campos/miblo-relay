// How the phone animates a Miblo: what its screen shows (the plugin's `screen`, worked out as the
// firmware does) as a loop of the gadget's moods, drawn by the firmware's own renderer
// (lib/look-renderer.ts renderMood). Pure, so it is tested without a browser.
import { MOOD } from "@/lib/look-renderer";
import type { MibloScreen } from "./snapshot";

type Step = readonly [mood: number, ms: number];

/** Each screen's loop: [mood, how long it shows] in turn. */
export const LOOPS: Record<MibloScreen, readonly Step[]> = {
  // Needs you: wide eyes and the alarm, as the gadget's alert.
  alert: [[MOOD.alert, 4000]],
  // Working: paws tapping, now and then a look up and a blink.
  work: [
    [MOOD.work, 900],
    [MOOD.idle, 300],
    [MOOD.work, 900],
    [MOOD.idle, 300],
    [MOOD.work, 1440],
    [MOOD.blink, 160],
  ],
  // The dashboard: at rest, a blink every few seconds.
  idle: [
    [MOOD.idle, 3840],
    [MOOD.blink, 160],
  ],
  // Pet mode: happy now and then, as the pet plays on its own.
  pet: [
    [MOOD.idle, 1200],
    [MOOD.happy, 1200],
    [MOOD.idle, 1440],
    [MOOD.blink, 160],
  ],
  // Asleep (the gadget's screen is off): eyes closed, the Zs.
  sleep: [[MOOD.sleepy, 4000]],
};

const total = (loop: readonly Step[]) => loop.reduce((n, [, ms]) => n + ms, 0);

/**
 * The frame to draw `ms` into the animation: the mood and the breath's tick (a second a tick, the
 * renderer's clock). Offline, or with reduced motion (`still`), the loop's first frame stays.
 */
export function frameAt(screen: MibloScreen | null, online: boolean, ms: number, still = false): { mood: number; tick: number } {
  const loop = LOOPS[online && screen ? screen : "idle"];
  if (!online) return { mood: MOOD.idle, tick: 0 };
  if (still || !Number.isFinite(ms) || ms < 0) return { mood: loop[0][0], tick: 0 };
  let t = ms % total(loop);
  for (const [mood, len] of loop) {
    if (t < len) return { mood, tick: Math.floor(ms / 1000) % 65536 };
    t -= len;
  }
  return { mood: loop[0][0], tick: 0 };
}
