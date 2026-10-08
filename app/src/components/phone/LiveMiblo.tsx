"use client";

// "Meu Miblo": the Miblo's screen, live. Not a drawing of it: the gadget's own firmware compiled
// to WebAssembly (lib/screen-live.ts, the same module and code as the desktop app's Now tab, the
// product repository's docs/screen-in-app.md), fed the snapshot the computer sends this phone (put
// back in the gadget's shape), wearing the first Miblo's look. 1.25: a program's App screen
// (lib/screen-card.ts) over the ordinary screens, drawn over a neutral background: its frame stays
// on the Miblo ("fundo no Miblo"). 10 frames a second while the tab and the page are visible.
import { useEffect, useRef } from "react";
import { loadMibloScreen } from "@/lib/generated/miblo-screen.js";
import { SCREEN_WASM } from "@/lib/screen-module";
import { LiveScreen, SIZE, type ScreenMiblo } from "@/lib/screen-live";
import { b64url } from "@/lib/relay-crypto";
import { usePetFile } from "./pet-cache";
import type { MibloView, SnapshotView } from "./snapshot";
import type { PhoneStrings } from "./strings";
import styles from "./phone.module.css";

/** The first Miblo as the live screen's module takes it (My pet when its file came). */
export function screenMiblo(m: MibloView | null, petFile: Uint8Array | null): ScreenMiblo | null {
  if (!m) return null;
  const myPet = m.myPet && !!m.pet && !!petFile;
  return {
    name: m.name,
    look: m.code ?? undefined,
    myPet,
    pet: myPet ? m.pet! : undefined,
    // The module's loader reads standard base64.
    petFile: myPet ? b64url(petFile!).replace(/-/g, "+").replace(/_/g, "/") : undefined,
  };
}

export function LiveMiblo({ t, snap, lang }: { t: PhoneStrings; snap: SnapshotView; lang: "pt" | "en" }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const live = useRef<LiveScreen | null>(null);
  const first = snap.miblos[0] ?? null;
  const petFile = usePetFile(first?.myPet ? first.pet : null);

  useEffect(() => {
    const l = new LiveScreen({
      load: () => loadMibloScreen(fetch(SCREEN_WASM)),
      nowMs: () => performance.now(),
      epochSec: () => Math.floor(Date.now() / 1000),
      zone: () => Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
      canvas: () => canvas.current,
      hidden: () => document.hidden,
      every: (fn, ms) => window.setInterval(fn, ms),
      stop: (h) => window.clearInterval(h as number),
      font: getComputedStyle(document.body).fontFamily || "system-ui, sans-serif",
    });
    live.current = l;
    const vis = () => l.visibilityChanged();
    document.addEventListener("visibilitychange", vis);
    return () => {
      document.removeEventListener("visibilitychange", vis);
      l.pause();
      live.current = null;
    };
  }, []);

  useEffect(() => {
    const l = live.current;
    if (!l) return;
    l.update({ snapshot: snap.gadget, miblo: screenMiblo(first, petFile) }, lang);
    l.ensureRunning();
  }, [snap, first, petFile, lang]);

  const app = snap.app;
  const layer = app?.bg !== null && app?.bg !== undefined;
  return (
    <figure className={styles.live} data-app={app ? "true" : undefined}>
      <div className={styles.liveBezel}>
        <canvas ref={canvas} className={styles.liveScreen} width={SIZE} height={SIZE} role="img" aria-label={t.miblo.liveAlt} />
      </div>
      <figcaption className={styles.liveCaption}>
        <span>{first ? t.miblo.liveOf(first.name) : t.miblo.liveFactory}</span>
        {app && (
          <span className={styles.liveApp} title={t.miblo.appHelp}>
            {t.miblo.app(app.tool || app.card.title || "App")}
          </span>
        )}
        {app && layer && (
          <span className={styles.liveBg} title={t.miblo.appBgHelp}>
            {t.miblo.appBg}
          </span>
        )}
      </figcaption>
    </figure>
  );
}
