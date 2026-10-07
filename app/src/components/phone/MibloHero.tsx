"use client";

// The top of the phone's dashboard: the person's own Miblo as it is on their desk. Its pet in its
// colours and accessories, drawn by the firmware's own renderer (lib/look-renderer.ts, the same
// WebAssembly the gallery uses), in the mood its screen shows now (working, needs you, pet mode,
// asleep), with its name and whether the computer reaches it. Several Miblos: tabs, or a swipe.
// Reduced motion: one still frame per state.
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { renderMood, renderPet, SCREEN } from "@/lib/look-renderer";
import { usePetFile } from "./pet-cache";
import type { Look } from "@/lib/miblo-look";
import { frameAt } from "./miblo-mood";
import type { MibloScreen, MibloView } from "./snapshot";
import type { PhoneStrings } from "./strings";
import styles from "./phone.module.css";

const STEP_MS = 160; // the shortest step of a loop (a blink)
const SWIPE_PX = 40;

function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    const q = matchMedia("(prefers-reduced-motion: reduce)");
    const on = () => setReduced(q.matches);
    on();
    q.addEventListener("change", on);
    return () => q.removeEventListener("change", on);
  }, []);
  return reduced;
}

/** The Miblo's screen: its look (or My pet, from its file) in the mood `screen` shows, animated unless `still`. */
function LiveScreen({
  look,
  pet = null,
  screen,
  online,
  still,
  label,
  unavailable,
  onRefused,
  small = false,
}: {
  look: Look;
  /** My pet's file (MPET1 or MPET2): drawn in `look`'s preset, eyes, items and colours. */
  pet?: Uint8Array | null;
  /** The file was refused by the firmware's validation (the caller shows the resting eyes). */
  onRefused?: () => void;
  screen: MibloScreen | null;
  online: boolean;
  still: boolean;
  /** Its accessible name; null: decorative (a thumbnail inside a labelled button). */
  label: string | null;
  unavailable: string;
  small?: boolean;
}) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const [ms, setMs] = useState(0);
  const [failed, setFailed] = useState(false);
  const animate = online && !still;
  const { mood, tick: breath } = frameAt(screen, online, animate ? ms : 0, still);
  // My pet loops its own frames at its own speed (the file's fps, byte 9), as the gadget does.
  const tick = pet ? (animate ? Math.floor((ms * Math.max(1, pet[9] ?? 4)) / 1000) % 65536 : 0) : breath;
  const lookKey = JSON.stringify(look);

  // A new state starts its loop from the top.
  useEffect(() => {
    if (!animate) return;
    const start = performance.now();
    const timer = setInterval(() => setMs(performance.now() - start), STEP_MS);
    return () => clearInterval(timer);
  }, [animate, screen]);

  useEffect(() => {
    let current = true;
    const parsed = JSON.parse(lookKey) as Look;
    (pet ? renderPet(pet, mood, tick, parsed) : renderMood(parsed, mood, tick))
      .then((img) => {
        if (!current) return;
        if (!img) {
          if (pet) onRefused?.();
          return setFailed(true);
        }
        canvas.current?.getContext("2d")?.putImageData(img, 0, 0);
        setFailed(false);
      })
      .catch(() => current && setFailed(true));
    return () => {
      current = false;
    };
  }, [lookKey, mood, tick, pet, onRefused]);

  return (
    <div className={small ? styles.thumbScreen : styles.mibloScreen}>
      <canvas
        ref={canvas}
        width={SCREEN}
        height={SCREEN}
        role={label ? "img" : undefined}
        aria-label={label ?? undefined}
        aria-hidden={label ? undefined : true}
        className={styles.mibloCanvas}
      />
      {failed && !small && <p className={styles.mibloUnavailable}>{unavailable}</p>}
    </div>
  );
}

/**
 * Whether a Miblo can be drawn: a built-in pet's look, or My pet once its file is here (and the
 * firmware's validation did not refuse it). Otherwise the resting eyes.
 */
function useDrawable(m: MibloView | undefined): { pet: Uint8Array | null; drawable: boolean; refused: () => void } {
  const pet = usePetFile(m?.myPet ? m.pet : null);
  const [refusedPet, setRefusedPet] = useState<Uint8Array | null>(null);
  const refused = useCallback(() => setRefusedPet(pet), [pet]);
  if (!m?.look) return { pet: null, drawable: false, refused };
  if (!m.myPet) return { pet: null, drawable: true, refused };
  return { pet, drawable: !!pet && pet !== refusedPet, refused };
}

/**
 * The compact Miblo for the "Agora" tab: a small live screen beside its name and state, one tap
 * from the big one. Decorative inside its button (the button carries the words).
 */
export function MibloThumb({ m, restingFace }: { m: MibloView; restingFace: ReactNode }) {
  const still = useReducedMotion();
  const { pet, drawable, refused } = useDrawable(m);
  return (
    <span className={styles.thumb} data-offline={m.online ? undefined : "true"} data-screen={m.screen ?? undefined}>
      {drawable && m.look ? (
        <LiveScreen look={m.look} pet={pet} onRefused={refused} screen={m.screen} online={m.online} still={still} label={null} unavailable="" small />
      ) : (
        <span className={styles.thumbScreen}>
          <span className={styles.thumbResting}>{restingFace}</span>
        </span>
      )}
    </span>
  );
}

export function MibloHero({
  t,
  miblos,
  host,
  needs,
  stale,
  restingFace,
}: {
  t: PhoneStrings;
  miblos: MibloView[];
  /** The computer these Miblos are paired with. */
  host: string;
  /** Sessions waiting for the person on that computer. */
  needs: number;
  stale: boolean;
  /** Shown for a Miblo whose look the phone cannot draw (My pet, an unknown look). */
  restingFace: ReactNode;
}) {
  const still = useReducedMotion();
  const [picked, setPicked] = useState(0);
  const touch = useRef<number | null>(null);
  const tabs = useRef<(HTMLButtonElement | null)[]>([]);
  const index = Math.min(picked, miblos.length - 1);
  const m = miblos[index];
  const { pet, drawable, refused } = useDrawable(m);
  if (!m) return null;
  const state = m.online ? (m.screen ? t.miblo.screen[m.screen] : t.miblo.online) : t.miblo.offline;
  const go = (i: number, focus = false) => {
    const n = (i + miblos.length) % miblos.length;
    setPicked(n);
    if (focus) tabs.current[n]?.focus();
  };
  const several = miblos.length > 1;

  return (
    <>
      <section
        aria-label={host}
        className={styles.bezel}
        data-alert={needs > 0 ? "true" : undefined}
        data-stale={stale ? "true" : undefined}
        onTouchStart={(e) => {
          touch.current = e.touches[0]?.clientX ?? null;
        }}
        onTouchEnd={(e) => {
          const x0 = touch.current;
          touch.current = null;
          const x1 = e.changedTouches[0]?.clientX;
          if (!several || x0 === null || x1 === undefined || Math.abs(x1 - x0) < SWIPE_PX) return;
          go(index + (x1 < x0 ? 1 : -1));
        }}
      >
        <div
          id="miblo-panel"
          className={styles.mibloGlass}
          role={several ? "tabpanel" : undefined}
          data-offline={m.online ? undefined : "true"}
          data-screen={m.screen ?? undefined}
        >
          <p className={styles.host}>{host}</p>
          {drawable && m.look ? (
            <LiveScreen
              key={`${m.label}-${index}-${m.pet ?? ""}`}
              look={m.look}
              pet={pet}
              onRefused={refused}
              screen={m.screen}
              online={m.online}
              still={still}
              label={t.miblo.picture(m.name, state)}
              unavailable={t.miblo.unavailable}
            />
          ) : (
            <div className={styles.mibloScreen} role="img" aria-label={t.miblo.picture(m.name, state)}>
              <span className={styles.mibloResting}>{restingFace}</span>
            </div>
          )}
          {needs > 0 && (
            <p className={styles.mibloNeeds}>
              <span className={styles.mibloNeedsCount}>{needs}</span>
              {t.needsYouCount(needs)}
            </p>
          )}
        </div>
      </section>
      <div className={styles.mibloMeta}>
        <p className={styles.mibloName}>
          <span className={styles.mibloTitle}>{m.name}</span>
          {m.label && m.label !== m.name && <span className={styles.mibloLabel}>{m.label}</span>}
          <span className={styles.mibloOnline} data-online={m.online ? "true" : "false"}>
            <span className={styles.dot} aria-hidden="true" />
            {m.online ? t.miblo.online : t.miblo.offline}
          </span>
        </p>
        <p className={styles.mibloState}>
          {m.online ? (m.screen ? t.miblo.screen[m.screen] : "") : t.miblo.offlineHint}
          {!m.online && <span className={styles.mibloHelp}>{t.miblo.offlineHelp}</span>}
          {m.myPet && <span className="block">{t.miblo.myPet}</span>}
        </p>
      </div>
      {several && (
        <div role="tablist" aria-label={t.miblo.yours} className={styles.mibloTabs}>
          {miblos.map((x, i) => (
            <button
              key={`${x.label}-${i}`}
              ref={(el) => {
                tabs.current[i] = el;
              }}
              type="button"
              role="tab"
              aria-selected={i === index}
              aria-controls="miblo-panel"
              tabIndex={i === index ? 0 : -1}
              className={styles.tab}
              data-offline={x.online ? undefined : "true"}
              onClick={() => go(i)}
              onKeyDown={(e) => {
                if (e.key === "ArrowRight") go(index + 1, true);
                else if (e.key === "ArrowLeft") go(index - 1, true);
                else return;
                e.preventDefault();
              }}
            >
              {x.online && x.screen === "alert" && (
                <span className={styles.tabBadge} aria-hidden="true">
                  !
                </span>
              )}
              {x.name}
            </button>
          ))}
        </div>
      )}
    </>
  );
}
