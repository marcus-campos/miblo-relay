// When the phone app locks by itself (docs/phone-relay-protocol.md, "App lock (PIN)"): after the
// chosen minutes with no touch, tap or key while the app is on screen, also counting the time it
// spent in the background; or, with "leave", as soon as the app is hidden. The clock is passed in,
// so the rules are tested with a fake one.
import type { IdleChoice } from "./pin-lock";

export class IdleLock {
  private last: number;
  private hiddenAt: number | null = null;

  constructor(
    private choice: IdleChoice,
    private readonly now: () => number,
    private readonly onLock: () => void,
  ) {
    this.last = now();
  }

  setChoice(choice: IdleChoice): void {
    this.choice = choice;
  }

  /** A touch, tap or key on the visible app. */
  activity(): void {
    if (this.hiddenAt === null) this.last = this.now();
  }

  /** The app was hidden (another app, the home screen, the screen turned off) or left. */
  hidden(): void {
    if (this.hiddenAt === null) this.hiddenAt = this.now();
    if (this.choice === "leave") this.onLock();
  }

  /** The app is on screen again: locks if it was away (or idle) for too long. */
  visible(): void {
    this.hiddenAt = null;
    this.check();
  }

  /** Called on a timer while the app is open (timers are slowed in the background: visible() checks too). */
  check(): boolean {
    if (this.choice === "leave") return false;
    if (this.now() - this.last >= this.choice * 60_000) {
      this.onLock();
      return true;
    }
    return false;
  }

  /** Unlocked again: the idle time starts over. */
  reset(): void {
    this.last = this.now();
  }
}
