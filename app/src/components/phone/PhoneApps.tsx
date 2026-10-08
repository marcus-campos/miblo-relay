"use client";

// "Meu Miblo": the computer's Miblo Apps (1.25), read-only: each app's screen (its card drawn with
// the screen's own layout, lib/screen-card.ts), whether it is on, "Configure o app X no
// computador" when it asks for a setting, and its settings. Turning apps on and setting them up
// happens in the desktop app.
import { useEffect, useRef } from "react";
import { drawPrims, layoutCard, SIZE } from "@/lib/screen-card";
import type { AppView } from "./snapshot";
import type { PhoneStrings } from "./strings";
import styles from "./phone.module.css";

function Preview({ app, t }: { app: AppView; t: PhoneStrings }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const sig = JSON.stringify(app.preview);
  useEffect(() => {
    const ctx = canvas.current?.getContext("2d");
    if (!ctx || !app.preview) return;
    drawPrims(ctx, layoutCard(app.preview, app.preview.title ? "" : app.name, false), getComputedStyle(document.body).fontFamily || "system-ui, sans-serif");
    // Redrawn only when the card changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sig]);
  if (!app.preview) return <div className={styles.appPreview} aria-hidden="true" />;
  return <canvas ref={canvas} className={styles.appPreview} width={SIZE} height={SIZE} role="img" aria-label={t.apps.previewAlt(app.name)} />;
}

export function PhoneApps({ t, apps }: { t: PhoneStrings; apps: AppView[] }) {
  if (!apps.length) return null;
  return (
    <div>
      <ul className={styles.appList}>
        {apps.map((a) => (
          <li key={a.id} className={styles.appRow}>
            <Preview app={a} t={t} />
            <div className={styles.appInfo}>
              <p className={styles.appName}>
                {a.name}
                {!a.enabled && <span className={styles.appOff}>{t.apps.off}</span>}
              </p>
              {a.needsSetup && <p className={styles.appSetup}>{t.apps.setup(a.name)}</p>}
              {a.settings.length > 0 && (
                <dl className={styles.appSettings}>
                  {a.settings.map((s) => (
                    <div key={s.label}>
                      <dt>{s.label}</dt>
                      <dd>{s.value || "—"}</dd>
                    </div>
                  ))}
                </dl>
              )}
            </div>
          </li>
        ))}
      </ul>
      <p className={styles.appHelp}>{t.apps.help}</p>
    </div>
  );
}
