// The decrypted snapshot (the same fields the gadget gets) and how the phone presents it.
// Parsing is defensive: the payload comes from the user's own computer, but versions differ.
import type { PhoneStrings } from "./strings";
import { decodeLookCode } from "@/lib/look-code";
import type { Look } from "@/lib/miblo-look";
import { cleanLine, parseCard, screenAppOf, type Card, type ScreenApp } from "@/lib/screen-card";

export type SessionView = {
  id: string;
  label: string;
  kind: "needs" | "working" | "done" | "idle";
  /** perm / question, for "needs" sessions. */
  ask: "perm" | "question" | null;
  activity: string;
  /** Epoch ms the session entered its state. */
  since: number | null;
};

export type LimitView = { pct: number; reset: number | null };

/** What a Miblo's screen shows (the plugin works it out as the firmware does: lib/miblo-mirror.js). */
export type MibloScreen = "alert" | "work" | "idle" | "pet" | "sleep";
export const MIBLO_SCREENS: readonly MibloScreen[] = ["alert", "work", "idle", "pet", "sleep"];

/** One of the person's own Miblos, as their computer sees it. */
export type MibloView = {
  /** Its name (the device's own, or its label). */
  name: string;
  /** Its network label, Miblo-XXXX: tells two Miblos with the same name apart. */
  label: string;
  online: boolean;
  /** Its look (pet, colours, accessories); null when unknown. With My pet, the preset, eyes, items and colours (its pet byte means nothing). */
  look: Look | null;
  /** Its look code as sent (MIBLO1:...), for the live screen's module; null when it is not one. */
  code: string | null;
  /** Runs My pet from Miblo Studio, drawn from its own file (`pet`), which comes apart (pet-cache.ts). */
  myPet: boolean;
  /** My pet's file by name: the SHA-256 of it, base64url; null when the computer could not read it. */
  pet: string | null;
  screen: MibloScreen | null;
};

/** At most this many Miblos are shown (the plugin sends no more). */
export const MAX_MIBLOS = 6;

function parseMiblos(v: unknown): MibloView[] {
  if (!Array.isArray(v)) return [];
  return v
    .filter((m): m is Record<string, unknown> => !!m && typeof m === "object")
    .slice(0, MAX_MIBLOS)
    .map((m) => {
      const decoded = typeof m.look === "string" ? decodeLookCode(m.look.slice(0, 64)) : null;
      const label = str(m.label, 20);
      return {
        name: str(m.name, 20).trim() || label || "Miblo",
        label,
        online: m.online === true,
        look: decoded?.ok ? decoded.look : null,
        code: decoded?.ok ? (m.look as string) : null,
        myPet: m.myPet === true,
        pet: m.myPet === true && typeof m.pet === "string" && /^[A-Za-z0-9_-]{43}$/.test(m.pet) ? m.pet : null,
        screen: MIBLO_SCREENS.find((x) => x === m.screen) ?? null,
      } satisfies MibloView;
    });
}

export type SnapshotView = {
  at: number;
  host: string;
  sessions: SessionView[];
  more: number;
  h5: LimitView | null;
  d7: LimitView | null;
  today: { usd: number | null; turns: number | null; work: number | null } | null;
  /** The person's own Miblos; empty from an older plugin or with none paired. */
  miblos: MibloView[];
  /** The snapshot back in the gadget's own shape, for the live screen's module (the firmware's parser). */
  gadget: Record<string, unknown>;
  /** 1.25: a program's App screen (its card, the frame it is drawn over on the Miblo); null: none. */
  app: ScreenApp | null;
  /** 1.25: the computer's Miblo Apps (read-only here: they are set up on the computer). */
  apps: AppView[];
};

/** One of the computer's apps, as the phone shows it. */
export type AppView = {
  id: string;
  name: string;
  enabled: boolean;
  needsSetup: boolean;
  /** The card it shows (sample data when it has not run yet). */
  preview: Card | null;
  /** Its settings, as label and value, in the phone's language. */
  settings: { label: string; value: string }[];
};

const APP_ID = /^[a-z0-9][a-z0-9-]{0,47}$/;
const labelText = (v: unknown, lang: "pt" | "en", max: number): string =>
  typeof v === "string" ? cleanLine(v, max) : v && typeof v === "object" ? cleanLine((v as Record<string, unknown>)[lang] ?? (v as Record<string, unknown>)[lang === "pt" ? "en" : "pt"], max) : "";

/** `apps` in the payload (the plugin's apps list, when it sends it); [] from an older one. */
export function parseApps(v: unknown, lang: "pt" | "en"): AppView[] {
  if (!Array.isArray(v)) return [];
  return v
    .filter((a): a is Record<string, unknown> => !!a && typeof a === "object" && typeof (a as { id?: unknown }).id === "string" && APP_ID.test((a as { id: string }).id))
    .slice(0, 32)
    .map((a) => {
      const schema = Array.isArray(a.schema) ? a.schema : Array.isArray(a.settings) ? a.settings : [];
      const values = a.values && typeof a.values === "object" ? (a.values as Record<string, unknown>) : {};
      const settings = schema
        .filter((s): s is Record<string, unknown> => !!s && typeof s === "object" && typeof (s as { key?: unknown }).key === "string")
        .slice(0, 12)
        .map((s) => {
          const x = values[s.key as string] ?? s.default;
          const value = typeof x === "boolean" ? (x ? (lang === "pt" ? "sim" : "yes") : lang === "pt" ? "não" : "no") : typeof x === "number" || typeof x === "string" ? cleanLine(String(x), 60) : "";
          return { label: labelText(s.label, lang, 40) || (s.key as string), value };
        });
      return {
        id: a.id as string,
        name: labelText(a.names, lang, 24) || labelText(a.name, lang, 24) || (a.id as string),
        enabled: a.enabled === undefined ? true : a.enabled === true,
        needsSetup: a.needsSetup === true,
        preview: parseCard(a.preview),
        settings,
      } satisfies AppView;
    });
}

const ORDER = { needs: 0, working: 1, done: 2, idle: 3 } as const;

const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const str = (v: unknown, max = 80): string => (typeof v === "string" ? v.slice(0, max) : "");
/** Epoch seconds (gadget format) or ms, to ms. */
const toMs = (v: unknown): number | null => {
  const n = num(v);
  if (n === null || n <= 0) return null;
  return n < 1e12 ? n * 1000 : n;
};

/** Frames whose time is further ahead of the phone's clock than this are dropped. */
export const MAX_FUTURE_MS = 60_000;

/** The frame's own time (`at`, epoch ms), or null when it carries none. */
export function frameAt(payload: unknown): number | null {
  if (!payload || typeof payload !== "object") return null;
  return toMs((payload as Record<string, unknown>).at);
}

/**
 * Replay guard: a frame is shown only when its time is newer than the last one accepted for that
 * computer and not more than a minute in the future. The relay cannot forge frames, but it could
 * replay an old one or hold one back. `sameAllowed` is for the first frame after a reload, when
 * the last accepted time comes from storage: the relay's retained frame is that very frame.
 */
export function acceptFrameAt(at: number | null, lastAt: number | undefined, now: number, sameAllowed = false): boolean {
  if (at === null) return false;
  if (lastAt !== undefined && (sameAllowed ? at < lastAt : at <= lastAt)) return false;
  return at <= now + MAX_FUTURE_MS;
}

function kindOf(st: string): SessionView["kind"] {
  if (st === "perm" || st === "question" || st === "needs") return "needs";
  if (st === "running" || st === "working") return "working";
  if (st === "done") return "done";
  return "idle";
}

function activityOf(s: Record<string, unknown>, kind: SessionView["kind"], t: PhoneStrings): string {
  const tool = str(s.tool, 40);
  const det = str(s.det, 80);
  if (kind === "needs") {
    const what = s.st === "question" ? t.question : t.perm;
    return tool ? `${what}: ${[tool, det].filter(Boolean).join(" ")}` : what;
  }
  if (kind !== "working") return "";
  if (tool.startsWith("_")) {
    const label = t.tools[tool] ?? "";
    return label && det && tool !== "_compact" ? `${label} (${det})` : label;
  }
  return [tool, det].filter(Boolean).join(" ");
}

function limit(v: unknown): LimitView | null {
  if (!v || typeof v !== "object") return null;
  const o = v as Record<string, unknown>;
  const pct = num(o.pct);
  if (pct === null) return null;
  return { pct: Math.max(0, Math.min(100, Math.round(pct))), reset: toMs(o.reset) };
}

/**
 * The phone's payload (plugin lib/phone-secrets.js phonePayload: the gadget snapshot's fields,
 * renamed) back in the shape the gadget gets, for the live screen's module: `limits` is `usage`,
 * `limitsMore` is `lims`, and the frame's time stands for `seq` and `now`.
 */
export function gadgetSnapshot(p: Record<string, unknown>, at: number): Record<string, unknown> {
  const arr = (v: unknown, n: number) => (Array.isArray(v) ? v.slice(0, n) : []);
  return {
    v: 1,
    seq: at,
    now: Math.floor(at / 1000),
    host: str(p.host, 40),
    sessions: arr(p.sessions, 50),
    more: Math.max(0, num(p.more) ?? 0),
    alerts: arr(p.alerts, 20),
    usage: p.limits && typeof p.limits === "object" ? p.limits : null,
    ...(Array.isArray(p.limitsMore) ? { lims: p.limitsMore.slice(0, 6) } : {}),
    today: p.today && typeof p.today === "object" ? p.today : null,
    ...(p.screen && typeof p.screen === "object" ? { screen: p.screen } : {}),
  };
}

export function parseSnapshot(payload: unknown, t: PhoneStrings): SnapshotView | null {
  if (!payload || typeof payload !== "object") return null;
  const p = payload as Record<string, unknown>;
  if (p.kind !== undefined && p.kind !== "snapshot") return null;
  const sessions = (Array.isArray(p.sessions) ? p.sessions : [])
    .filter((s): s is Record<string, unknown> => !!s && typeof s === "object")
    .slice(0, 50)
    .map((s, i) => {
      const kind = kindOf(str(s.st, 20));
      return {
        id: str(s.id, 40) || String(i),
        label: str(s.title, 80) || str(s.name, 80) || "Claude",
        kind,
        ask: kind === "needs" ? (s.st === "question" ? "question" : "perm") : null,
        activity: activityOf(s, kind, t),
        since: toMs(s.since),
      } satisfies SessionView;
    })
    .sort((a, b) => ORDER[a.kind] - ORDER[b.kind]);
  const limits = (p.limits ?? p.usage) as Record<string, unknown> | undefined;
  const today = p.today && typeof p.today === "object" ? (p.today as Record<string, unknown>) : null;
  const at = toMs(p.at) ?? toMs(p.now) ?? Date.now();
  return {
    at,
    host: str(p.host, 40),
    sessions,
    more: Math.max(0, num(p.more) ?? 0),
    h5: limit(limits?.h5),
    d7: limit(limits?.d7),
    today: today ? { usd: num(today.usd), turns: num(today.turns), work: num(today.work) } : null,
    miblos: parseMiblos(p.miblos),
    gadget: gadgetSnapshot(p, at),
    app: screenAppOf(p),
    apps: parseApps(p.apps, t.lang),
  };
}

/** "45 s", "12 min", "2 h 05" — compact elapsed time. */
export function elapsed(ms: number, lang: "pt" | "en"): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h} h ${String(m % 60).padStart(2, "0")}`;
  const d = Math.floor(h / 24);
  return lang === "pt" ? `${d} dias` : `${d} days`;
}

/** A work duration in seconds: "1 h 13 min", "25 min". */
export function duration(seconds: number): string {
  const m = Math.round(seconds / 60);
  if (m < 60) return `${m} min`;
  return `${Math.floor(m / 60)} h ${String(m % 60).padStart(2, "0")} min`;
}

/** When a limit resets: a time today, else weekday + time. */
export function resetWhen(ms: number, lang: "pt" | "en", now = Date.now()): string {
  const d = new Date(ms);
  const locale = lang === "pt" ? "pt-BR" : "en";
  const time = d.toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit" });
  const sameDay = new Date(now).toDateString() === d.toDateString();
  if (sameDay) return lang === "pt" ? `às ${time}` : `at ${time}`;
  const day = d.toLocaleDateString(locale, { weekday: "short" }).replace(".", "");
  return lang === "pt" ? `${day} às ${time}` : `${day} at ${time}`;
}

export function money(usd: number, lang: "pt" | "en"): string {
  return new Intl.NumberFormat(lang === "pt" ? "pt-BR" : "en-US", { style: "currency", currency: "USD" }).format(usd);
}
