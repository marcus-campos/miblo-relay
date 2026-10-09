// The red "Pânico" button (panic-model.ts): held for 2 s (finger, mouse, or Space/Enter held), then
// the caller asks for the passkey and sends the frame. Letting go early cancels it.
import { useEffect, useRef, useState } from "react";
import { HOLD_MS, holdController, type PanicState, type PanicStrings } from "./panic-model";
import { Notice } from "./AppParts";
import styles from "./phone.module.css";

/** What the phone shows for a computer turned off by panic (replies, approvals and tasks are off). */
export function PanicOffNotice({ s, state }: { s: PanicStrings; state: PanicState }) {
  return (
    <Notice tone="bad" role="alert">
      <p className="font-bold" data-testid="panic-off">
        {state.by === "computer" ? s.offByComputer : s.off}
      </p>
      <p className="mt-1">{s.offBody}</p>
    </Notice>
  );
}

export function PanicButton({ s, busy = false, disabled = false, onConfirm, now = () => Date.now() }: { s: PanicStrings; busy?: boolean; disabled?: boolean; onConfirm: () => void; now?: () => number }) {
  const hold = useRef(holdController(HOLD_MS));
  const [holding, setHolding] = useState(false);
  const [progress, setProgress] = useState(0);
  // The latest callback, without restarting the hold's timer on every render.
  const confirm = useRef(onConfirm);
  useEffect(() => {
    confirm.current = onConfirm;
  }, [onConfirm]);

  useEffect(() => {
    if (!holding) return;
    const timer = window.setInterval(() => {
      const { progress: p, fire } = hold.current.tick(now());
      setProgress(p);
      if (fire) {
        setHolding(false);
        confirm.current();
      }
    }, 50);
    return () => window.clearInterval(timer);
  }, [holding, now]);

  const start = () => {
    if (disabled || busy || hold.current.holding) return;
    hold.current.start(now());
    setHolding(true);
  };
  const cancel = () => {
    hold.current.cancel();
    setHolding(false);
    setProgress(0);
  };
  const off = disabled || busy;

  return (
    <section className={styles.panicCard} aria-labelledby="panic-title">
      <h2 id="panic-title" className="sr-only">
        {s.button}
      </h2>
      <button
        type="button"
        className={styles.panicButton}
        data-testid="panic-button"
        disabled={off}
        aria-busy={busy}
        aria-describedby="panic-explain"
        onPointerDown={start}
        onPointerUp={cancel}
        onPointerLeave={cancel}
        onPointerCancel={cancel}
        onKeyDown={(e) => {
          if ((e.key === " " || e.key === "Enter") && !e.repeat) {
            e.preventDefault();
            start();
          }
        }}
        onKeyUp={(e) => {
          if (e.key === " " || e.key === "Enter") cancel();
        }}
        onContextMenu={(e) => e.preventDefault()}
        style={{ ["--panic-progress" as string]: String(progress) }}
      >
        <span className={styles.panicFill} aria-hidden="true" />
        <span className={styles.panicLabel}>{busy ? s.verifying : holding ? s.holding : s.button}</span>
      </button>
      <p className={styles.panicHint}>{s.hold}</p>
      <p id="panic-explain" className={styles.panicHint}>
        {s.explain}
      </p>
    </section>
  );
}
