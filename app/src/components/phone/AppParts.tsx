"use client";

// Small presentational pieces of the phone app: icons, the bottom tab bar, the top bar with the
// account menu, notices with a "for the terminal" disclosure, numbered steps, the approval
// countdown ring and the pairing illustration. They keep the app's own look (phone.module.css),
// so only the behaviour is shared with the site (usePopover); no state beyond what each one shows.
import { useId, type ReactNode } from "react";
import { usePopover } from "@/components/ui/usePopover";
import { ringText, type AppTab } from "./app-model";
import type { PhoneStrings } from "./strings";
import styles from "./phone.module.css";

// --- icons (24 px, stroke) -------------------------------------------------------------------

type IconName = "now" | "miblo" | "settings" | "back" | "chevron" | "send" | "share" | "plus" | "user" | "alert" | "check" | "close" | "terminal" | "bell" | "download" | "copy" | "stop" | "down" | "spark" | "folder";

const PATHS: Record<IconName, ReactNode> = {
  now: <path d="M3 12h4l2.5-6 5 12L17 12h4" />,
  miblo: (
    <>
      <rect x="4" y="3.5" width="16" height="14" rx="3" />
      <path d="M9 9.5v2M15 9.5v2M8 21h8" />
    </>
  ),
  settings: (
    <>
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" />
    </>
  ),
  back: <path d="M15 18l-6-6 6-6" />,
  chevron: <path d="M9 18l6-6-6-6" />,
  send: <path d="M12 19V5M5 12l7-7 7 7" />,
  share: <path d="M12 3v12M8 7l4-4 4 4M5 12v7a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-7" />,
  plus: <path d="M12 5v14M5 12h14" />,
  user: (
    <>
      <circle cx="12" cy="8" r="4" />
      <path d="M4 21a8 8 0 0 1 16 0" />
    </>
  ),
  alert: <path d="M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" />,
  check: <path d="M20 6 9 17l-5-5" />,
  close: <path d="M18 6 6 18M6 6l12 12" />,
  terminal: <path d="M4 17l6-5-6-5M12 19h8" />,
  bell: <path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 0 1-3.4 0" />,
  download: <path d="M12 3v12M7 10l5 5 5-5M5 21h14" />,
  copy: <path d="M9 9h10v10H9zM5 15V5h10" />,
  stop: <rect x="6" y="6" width="12" height="12" rx="2" />,
  down: <path d="M12 5v14M5 12l7 7 7-7" />,
  spark: <path d="M12 3v4M12 17v4M3 12h4M17 12h4M6 6l2.5 2.5M15.5 15.5 18 18M6 18l2.5-2.5M15.5 8.5 18 6" />,
  folder: <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />,
};

export function Icon({ name, size = 24, className }: { name: IconName; size?: number; className?: string }) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {PATHS[name]}
    </svg>
  );
}

// --- top bar ---------------------------------------------------------------------------------

export function PixelCube({ size }: { size: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 13 13" aria-hidden="true" shapeRendering="crispEdges">
      <rect width="13" height="12" rx="2" fill="#F2A30F" />
      <rect x="2" y="2" width="9" height="8" fill="#141922" />
      <rect x="4" y="5" width="1" height="2" fill="#f6c6b8" />
      <rect x="8" y="5" width="1" height="2" fill="#f6c6b8" />
      <rect x="3" y="12" width="7" height="1" fill="currentColor" />
    </svg>
  );
}

export type AccountLinks = { signedIn: boolean | null; initial: string | null; account: string; help: string; site: string };

/** The app's top bar: the wordmark (or a screen title) and the account menu. */
export function TopBar({ t, title, links }: { t: PhoneStrings; title?: string; links: AccountLinks }) {
  return (
    <header className={styles.topbar}>
      <div className={styles.topbarInner}>
        {title ? (
          <h1 className={styles.topbarTitle}>{title}</h1>
        ) : (
          <span className="inline-flex items-center gap-2" aria-label="Miblo">
            <PixelCube size={26} />
            <span className="font-display text-[1.375rem] font-semibold leading-none">miblo</span>
          </span>
        )}
        <AccountMenu t={t} links={links} />
      </div>
    </header>
  );
}

function AccountMenu({ t, links }: { t: PhoneStrings; links: AccountLinks }) {
  // The site's popover behaviour (closes on a tap outside and on Escape).
  const { open, toggle, root, button } = usePopover();
  const id = useId();
  return (
    <div className={styles.menuBox} ref={root}>
      <button
        ref={button}
        type="button"
        className={styles.avatar}
        aria-label={t.account.menu}
        aria-expanded={open}
        aria-controls={id}
        onClick={toggle}
        data-signed-in={links.signedIn ? "true" : undefined}
      >
        {links.signedIn && links.initial ? <span aria-hidden="true">{links.initial}</span> : <Icon name="user" size={20} />}
      </button>
      {open && (
        <ul id={id} className={styles.menu}>
          <li>
            <a href={links.account}>{links.signedIn ? t.account.account : t.account.signIn}</a>
          </li>
          <li>
            <a href={links.help}>{t.account.help}</a>
          </li>
          <li>
            <a href={links.site}>{t.account.site}</a>
          </li>
        </ul>
      )}
    </div>
  );
}

// --- bottom tabs -----------------------------------------------------------------------------

export function TabBar({ t, tab, badge, onTab }: { t: PhoneStrings; tab: AppTab; badge: number; onTab: (tab: AppTab) => void }) {
  const items: { id: AppTab; icon: IconName }[] = [
    { id: "now", icon: "now" },
    { id: "miblo", icon: "miblo" },
    { id: "settings", icon: "settings" },
  ];
  return (
    <nav className={styles.tabbar} aria-label={t.tabsLabel}>
      <div className={styles.tabbarInner}>
        {items.map((it) => (
          <button
            key={it.id}
            type="button"
            className={styles.tabItem}
            aria-current={tab === it.id ? "page" : undefined}
            onClick={() => onTab(it.id)}
          >
            <span className={styles.tabIcon}>
              <Icon name={it.icon} />
              {it.id === "now" && badge > 0 && (
                <span className={styles.tabCount} aria-hidden="true">
                  {badge > 9 ? "9+" : badge}
                </span>
              )}
            </span>
            <span>
              {t.tabs[it.id]}
              {it.id === "now" && badge > 0 && <span className="sr-only"> ({badge})</span>}
            </span>
          </button>
        ))}
      </div>
    </nav>
  );
}

// --- notices ---------------------------------------------------------------------------------

/** A terminal command for people who use one, folded away under the plain instruction. */
export function Tech({ t, commands }: { t: PhoneStrings; commands: string[] }) {
  return (
    <details className={styles.tech}>
      <summary>
        <Icon name="terminal" size={16} />
        {t.tech.label}
      </summary>
      {commands.map((c) => (
        <code key={c} className={styles.techCode}>
          {c}
        </code>
      ))}
    </details>
  );
}

export function Notice({
  tone = "info",
  children,
  role,
  action,
}: {
  tone?: "info" | "warn" | "bad" | "ok";
  children: ReactNode;
  role?: "status" | "alert";
  action?: ReactNode;
}) {
  return (
    <div className={styles.notice} data-tone={tone} role={role}>
      <span className={styles.noticeIcon} aria-hidden="true">
        <Icon name={tone === "ok" ? "check" : tone === "info" ? "bell" : "alert"} size={18} />
      </span>
      <div className="min-w-0 flex-1">
        {children}
        {action}
      </div>
    </div>
  );
}

export function Steps({ items, first }: { items: ReactNode[]; first?: ReactNode }) {
  return (
    <ol className={styles.steps}>
      {items.map((step, i) => (
        <li key={i}>
          <span>
            {i === 0 ? first : null}
            {step}
          </span>
        </li>
      ))}
    </ol>
  );
}

/** A group of settings: a small heading and a card. */
export function Group({ title, children, id }: { title: string; children: ReactNode; id?: string }) {
  return (
    <section className={styles.group} aria-labelledby={id}>
      <h2 id={id} className={styles.groupTitle}>
        {title}
      </h2>
      <div className={styles.groupCard}>{children}</div>
    </section>
  );
}

// --- approval countdown ----------------------------------------------------------------------

/** A ring that empties as the approval's time runs out, with the seconds left in the middle. */
export function CountdownRing({ left, fraction, urgent, label }: { left: number; fraction: number; urgent: boolean; label: string }) {
  const r = 19;
  const c = 2 * Math.PI * r;
  return (
    <span className={styles.ring} data-urgent={urgent ? "true" : undefined} role="img" aria-label={label}>
      <svg viewBox="0 0 44 44" width="44" height="44" aria-hidden="true">
        <circle cx="22" cy="22" r={r} className={styles.ringTrack} />
        <circle cx="22" cy="22" r={r} className={styles.ringFill} strokeDasharray={c} strokeDashoffset={c * (1 - fraction)} transform="rotate(-90 22 22)" />
      </svg>
      <span className={styles.ringText} aria-hidden="true">
        {ringText(left)}
      </span>
    </span>
  );
}

// --- pairing illustration --------------------------------------------------------------------

// A fixed, non-scannable QR-like pattern (21 x 21) for the drawing.
const QR_BITS = (() => {
  const cells: [number, number][] = [];
  let seed = 7;
  const finder = (x: number, y: number) => {
    for (let i = 0; i < 7; i++)
      for (let j = 0; j < 7; j++) {
        const edge = i === 0 || j === 0 || i === 6 || j === 6;
        const core = i >= 2 && i <= 4 && j >= 2 && j <= 4;
        if (edge || core) cells.push([x + i, y + j]);
      }
  };
  finder(0, 0);
  finder(14, 0);
  finder(0, 14);
  for (let y = 0; y < 21; y++)
    for (let x = 0; x < 21; x++) {
      const inFinder = (x < 8 && y < 8) || (x > 12 && y < 8) || (x < 8 && y > 12);
      if (inFinder) continue;
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      if (seed % 7 < 3) cells.push([x, y]);
    }
  return cells;
})();

/** The Miblo app on a laptop, on its Phone screen, showing a QR code. */
export function PairIllustration({ label, tab }: { label: string; tab: string }) {
  return (
    <svg className={styles.illustration} viewBox="0 0 320 196" role="img" aria-label={label}>
      {/* laptop lid */}
      <rect x="34" y="6" width="252" height="164" rx="12" className={styles.illLid} />
      <rect x="44" y="16" width="232" height="144" rx="4" className={styles.illScreen} />
      {/* app sidebar */}
      <rect x="44" y="16" width="70" height="144" rx="4" className={styles.illSide} />
      <rect x="54" y="30" width="38" height="6" rx="3" className={styles.illLine} />
      <rect x="54" y="46" width="44" height="6" rx="3" className={styles.illLine} />
      <rect x="50" y="59" width="58" height="18" rx="5" className={styles.illActive} />
      <text x="58" y="72" className={styles.illTab}>
        {tab}
      </text>
      <rect x="54" y="86" width="34" height="6" rx="3" className={styles.illLine} />
      <rect x="54" y="102" width="40" height="6" rx="3" className={styles.illLine} />
      {/* QR code */}
      <rect x="150" y="34" width="96" height="96" rx="6" fill="#fff" />
      <g transform="translate(156 40) scale(4)" shapeRendering="crispEdges">
        {QR_BITS.map(([x, y]) => (
          <rect key={`${x}-${y}`} x={x} y={y} width="1" height="1" fill="#141922" />
        ))}
      </g>
      <rect x="160" y="140" width="76" height="6" rx="3" className={styles.illLine} />
      {/* base */}
      <path d="M12 172h296l-10 14a8 8 0 0 1-6.6 3.5H28.6A8 8 0 0 1 22 186z" className={styles.illBase} />
      {/* scan corners */}
      <path d="M140 46v-16h16M256 46v-16h-16M140 118v16h16M256 118v16h-16" className={styles.illScan} />
    </svg>
  );
}

/** The gadget's resting face: two pixel eyes that blink now and then. */
export function CatEyes({ className }: { className?: string }) {
  return (
    <svg className={`${styles.eyes} ${className ?? ""}`} viewBox="0 0 9 4" aria-hidden="true" shapeRendering="crispEdges">
      <rect x="1" y="0" width="2" height="4" fill="#f6c6b8" />
      <rect x="6" y="0" width="2" height="4" fill="#f6c6b8" />
    </svg>
  );
}
