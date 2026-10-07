// Keeping a conversation at its newest message (the chat view's scrolling, kept apart from React so
// it is tested in Node). The session screen scrolls the window; this decides when to follow the
// end and when to leave the person where they are:
//   - it starts pinned to the end: opening a conversation lands on the newest message, also when
//     the history arrives later, or grows (code blocks, long messages) after it was laid out;
//   - only the person's own scrolling (wheel, touch, keys) unpins it, and only once they are away
//     from the end; scrolling back down to the end pins it again;
//   - while unpinned, new messages are counted (the "↓ novas mensagens" pill) and nothing moves;
//   - jump() goes to the end (smoothly) and pins again; a smooth scroll in progress never unpins.

export type Metrics = { scrollTop: number; scrollHeight: number; viewport: number };
export type AnchorEnv = {
  metrics(): Metrics;
  scrollTo(top: number, smooth: boolean): void;
  now?(): number;
};

/** Closer than this to the end counts as "at the end". */
export const NEAR_END_PX = 96;
/** The person's input keeps counting as theirs this long after the last wheel, touch or key. */
export const USER_INPUT_MS = 700;

export class ScrollAnchor {
  pinned = true;
  unseen = 0;
  private lastCount = 0;
  private userAt = -Infinity;
  private readonly now: () => number;

  constructor(private readonly env: AnchorEnv) {
    this.now = env.now ?? (() => Date.now());
  }

  distance(): number {
    const m = this.env.metrics();
    return Math.max(0, m.scrollHeight - (m.scrollTop + m.viewport));
  }

  /** The person touched, wheeled or pressed a scrolling key. */
  userInput(): void {
    this.userAt = this.now();
  }

  /** A scroll event (the person's, or one of ours). -> whether the pill's state changed. */
  onScroll(): boolean {
    const before = `${this.pinned}|${this.unseen}`;
    const near = this.distance() <= NEAR_END_PX;
    if (near) {
      this.pinned = true;
      this.unseen = 0;
    } else if (this.now() - this.userAt <= USER_INPUT_MS) {
      this.pinned = false;
    }
    return before !== `${this.pinned}|${this.unseen}`;
  }

  /**
   * The content changed: new messages (`count`, the number of messages now), or the layout grew.
   * Pinned: back to the end at once. Not pinned: new messages are counted.
   */
  onContent(count: number): void {
    const added = Math.max(0, count - this.lastCount);
    const first = this.lastCount === 0 && count > 0;
    this.lastCount = count;
    if (this.pinned || first) {
      this.pinned = true;
      this.unseen = 0;
      this.env.scrollTo(this.env.metrics().scrollHeight, false);
    } else if (added) {
      this.unseen += added;
    }
  }

  /** "↓ novas mensagens": to the end, smoothly, pinned again. */
  jump(): void {
    this.pinned = true;
    this.unseen = 0;
    this.userAt = -Infinity;
    this.env.scrollTo(this.env.metrics().scrollHeight, true);
  }
}
