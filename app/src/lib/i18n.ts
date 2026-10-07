import { switchAccountPath } from "./account";
import { switchCommunityPath } from "./community";

export const locales = ["pt", "en"] as const;
export type Locale = (typeof locales)[number];
export const defaultLocale: Locale = "pt";

export const htmlLang: Record<Locale, string> = { pt: "pt-BR", en: "en" };

/** Every page, with its slug in each language. Portuguese lives at the root, English under /en. */
export const routes = {
  home: { pt: "/", en: "/en" },
  buy: { pt: "/comprar", en: "/en/buy" },
  downloads: { pt: "/downloads", en: "/en/downloads" },
  docs: { pt: "/docs", en: "/en/docs" },
  // Printed on the cards in the box (QR code to https://miblo.ai/guia): keep these paths.
  guide: { pt: "/guia", en: "/en/guide" },
  community: { pt: "/comunidade", en: "/en/community" },
  terms: { pt: "/termos", en: "/en/terms" },
  privacy: { pt: "/privacidade", en: "/en/privacy" },
  checkout: { pt: "/comprar/finalizar", en: "/en/buy/checkout" },
  order: { pt: "/pedido", en: "/en/order" },
  plus: { pt: "/plus", en: "/en/plus" },
  account: { pt: "/conta", en: "/en/account" },
  // The URL `miblo plus` prints (docs/miblo-plus.md): keep these paths.
  plusLink: { pt: "/plus/link", en: "/en/plus/link" },
} as const;

export type PageId = keyof typeof routes;

export function href(lang: Locale, page: PageId, hash?: string): string {
  const base = routes[page][lang];
  return hash ? `${base}#${hash}` : base;
}

/** The same page in the other language (falls back to the home page). */
export function switchPath(pathname: string, to: Locale): string {
  const clean = pathname.replace(/\/$/, "") || "/";
  const community = switchCommunityPath(clean, to);
  if (community) return community;
  const account = switchAccountPath(clean, to);
  if (account) return account;
  for (const page of Object.keys(routes) as PageId[]) {
    if (routes[page].pt === clean || routes[page].en === clean) return routes[page][to];
  }
  // Order pages carry the code: /pedido/MB-XXXXXX <-> /en/order/MB-XXXXXX.
  const order = /^(?:\/pedido|\/en\/order)\/([A-Z0-9-]+)$/.exec(clean);
  if (order) return `${routes.order[to]}/${order[1]}`;
  return routes.home[to];
}

/** Prices are always in BRL (Brazil-only store); only the number formatting follows the language. */
export function formatPrice(lang: Locale, cents: number): string {
  return new Intl.NumberFormat(lang === "pt" ? "pt-BR" : "en-US", {
    style: "currency",
    currency: "BRL",
  }).format(cents / 100);
}

/** "ou 10x de R$ 34,90 sem juros" / "or 10x R$ 34.90 interest-free", from the store config. */
export function installmentText(lang: Locale, cents: number, count: number, interestFree: boolean): string {
  const each = formatPrice(lang, Math.ceil(cents / count));
  if (lang === "pt") return `ou ${count}x de ${each}${interestFree ? " sem juros" : ""}`;
  return `or ${count}x ${each}${interestFree ? " interest-free" : ""}`;
}
