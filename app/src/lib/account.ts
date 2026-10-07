// The account area (/conta, /en/account): one place for everything a Miblo account has. The
// community, Miblo+, the pairing vault and Studio share the same account and session; each part
// is a section with its own URL in each language. The account's own page is an overview.
import { routes, type Locale } from "./i18n";

export const ACCOUNT_SECTIONS = ["overview", "profile", "security", "plus", "devices", "pets", "orders"] as const;
export type AccountSection = (typeof ACCOUNT_SECTIONS)[number];

/** The URL segment of each section (the overview is the account's own page). */
const SLUG: Record<AccountSection, { pt: string; en: string }> = {
  overview: { pt: "", en: "" },
  profile: { pt: "perfil", en: "profile" },
  security: { pt: "seguranca", en: "security" },
  plus: { pt: "plus", en: "plus" },
  devices: { pt: "dispositivos", en: "devices" },
  pets: { pt: "pets", en: "pets" },
  orders: { pt: "pedidos", en: "orders" },
};

/**
 * Sections whose page needs the account's second factor, passed in this session
 * (docs/miblo-plus.md). Miblo+ is not one: its plan and payments show without it, and every
 * action there (subscribing, the card, cancelling) asks for it where it happens; the server checks
 * each of those calls anyway.
 */
export const MFA_SECTIONS: readonly AccountSection[] = ["devices"];

export function accountUrl(lang: Locale, section: AccountSection = "overview"): string {
  const slug = SLUG[section][lang];
  return slug ? `${routes.account[lang]}/${slug}` : routes.account[lang];
}

/** The section for the segments after /conta (or /en/account); null: no such page. */
export function parseAccountSection(lang: Locale, slug: string[] = []): AccountSection | null {
  if (slug.length === 0) return "overview";
  if (slug.length > 1) return null;
  const found = ACCOUNT_SECTIONS.find((s) => SLUG[s][lang] && SLUG[s][lang] === slug[0]);
  return found ?? null;
}

/** The same account page in the other language, or null when `path` is not one. */
export function switchAccountPath(path: string, to: Locale): string | null {
  for (const from of ["pt", "en"] as const) {
    const base = routes.account[from];
    if (path !== base && !path.startsWith(`${base}/`)) continue;
    const rest = path.slice(base.length).replace(/^\//, "");
    const section = parseAccountSection(from, rest ? rest.split("/") : []);
    if (section) return accountUrl(to, section);
  }
  return null;
}

/** Why the visitor is being asked to sign in, read from where the sign-in lands (`next`). */
export type SignInReason = "look" | "topic" | "reply" | "like" | "studio" | "plus" | "orders" | "phone" | "account";

export function signInReason(next: string | null | undefined): SignInReason | null {
  if (!next) return null;
  const path = next.split(/[?#]/)[0].replace(/\/+$/, "");
  if (/^(\/en)?\/(comunidade\/galeria\/nova|community\/gallery\/new)$/.test(path)) return "look";
  if (/^(\/en)?\/(comunidade\/forum\/novo|community\/forum\/new)$/.test(path)) return "topic";
  if (/^(\/en)?\/(comunidade|community)\/forum\/t\/[^/]+$/.test(path)) return "reply";
  if (/^(\/en)?\/(comunidade\/galeria|community\/gallery)\/[^/]+$/.test(path)) return "like";
  if (/^(\/en)?\/(comunidade|community)\/studio$/.test(path)) return "studio";
  if (/^(\/en)?\/plus(\/|$)/.test(path) || /^(\/conta|\/en\/account)\/plus$/.test(path)) return "plus";
  if (/^(\/conta\/pedidos|\/en\/account\/orders)$/.test(path)) return "orders";
  if (/^(\/en)?\/app$/.test(path)) return "phone";
  if (/^(\/conta|\/en\/account)(\/|$)/.test(path)) return "account";
  return null;
}

/** A computer's operating system as people call it (the plugin reports Node's `process.platform`). */
export function platformName(platform: string | null | undefined): string {
  const p = (platform ?? "").trim().toLowerCase();
  if (p === "darwin" || p === "macos" || p === "mac" || p === "osx") return "Mac";
  if (p === "win32" || p === "windows" || p === "win") return "Windows";
  if (p === "linux") return "Linux";
  if (!p) return "";
  return platform!.trim();
}

/** Where a store order is, as a step of 4 (paid, packing, shipped, delivered), or its end. */
export type OrderStage = { step: 0 | 1 | 2 | 3 | 4; tone: "wait" | "go" | "done" | "stop" };

export function orderStage(status: string): OrderStage {
  switch (status) {
    case "pending_payment":
      return { step: 0, tone: "wait" };
    case "paid":
      return { step: 2, tone: "go" };
    case "shipped":
      return { step: 3, tone: "go" };
    case "delivered":
      return { step: 4, tone: "done" };
    default:
      // failed, canceled, refunded and anything new: not moving
      return { step: 0, tone: "stop" };
  }
}

/** Whether an order is still on its way to the member (the overview shows it first). */
export function orderInProgress(status: string): boolean {
  return status === "pending_payment" || status === "paid" || status === "shipped";
}

/** The welcome checklist after subscribing is asked for with ?bem-vindo=1 (or ?welcome=1). */
export function wantsWelcome(sp: Record<string, string | undefined>): boolean {
  return (sp["bem-vindo"] ?? sp.welcome) === "1";
}
