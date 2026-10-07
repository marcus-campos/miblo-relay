// Community structure shared by pages, the API and the language switch: forum categories and the
// URL of every community page in each language.
import type { Locale } from "./i18n";

export const CATEGORY_SLUGS = ["ajuda", "ideias", "setups", "novidades"] as const;
export type Category = (typeof CATEGORY_SLUGS)[number];

export const CATEGORIES: Record<Category, { pt: string; en: string; url: { pt: string; en: string }; adminOnly?: boolean }> = {
  ajuda: { pt: "Ajuda", en: "Help", url: { pt: "ajuda", en: "help" } },
  ideias: { pt: "Ideias", en: "Ideas", url: { pt: "ideias", en: "ideas" } },
  setups: { pt: "Mostre seu setup", en: "Show your setup", url: { pt: "setups", en: "setups" } },
  novidades: { pt: "Novidades", en: "News", url: { pt: "novidades", en: "news" }, adminOnly: true },
};

export function categoryFromUrl(lang: Locale, slug: string): Category | null {
  return CATEGORY_SLUGS.find((c) => CATEGORIES[c].url[lang] === slug) ?? null;
}

const BASE = { pt: "/comunidade", en: "/en/community" } as const;

// Fixed segments of community URLs, per language.
const SEG = {
  gallery: { pt: "galeria", en: "gallery" },
  newItem: { pt: "nova", en: "new" },
  forum: { pt: "forum", en: "forum" },
  newTopic: { pt: "novo", en: "new" },
  topic: { pt: "t", en: "t" },
  map: { pt: "mapa", en: "map" },
  signIn: { pt: "entrar", en: "sign-in" },
  confirm: { pt: "confirmar", en: "confirm" },
  verify: { pt: "verificar", en: "verify" },
  account: { pt: "conta", en: "account" },
  studio: { pt: "studio", en: "studio" },
  member: { pt: "membro", en: "member" },
} as const;

/** The public part of a member id (`usr_` + 12 symbols) used in profile URLs; null for anything else. */
export function memberSlug(userId: string | null | undefined): string | null {
  const m = /^usr_([2-9a-hj-km-np-z]{12})$/.exec(userId ?? "");
  return m ? m[1] : null;
}

/** The member id behind a profile URL's slug. */
export function memberIdFromSlug(slug: string): string {
  return `usr_${slug}`;
}

export const cx = {
  home: (l: Locale) => BASE[l],
  gallery: (l: Locale) => `${BASE[l]}/${SEG.gallery[l]}`,
  galleryNew: (l: Locale) => `${BASE[l]}/${SEG.gallery[l]}/${SEG.newItem[l]}`,
  galleryItem: (l: Locale, id: string) => `${BASE[l]}/${SEG.gallery[l]}/${id}`,
  forum: (l: Locale) => `${BASE[l]}/${SEG.forum[l]}`,
  category: (l: Locale, c: Category) => `${BASE[l]}/${SEG.forum[l]}/${CATEGORIES[c].url[l]}`,
  newTopic: (l: Locale, c?: Category) => `${BASE[l]}/${SEG.forum[l]}/${SEG.newTopic[l]}${c ? `?c=${c}` : ""}`,
  topic: (l: Locale, id: string) => `${BASE[l]}/${SEG.forum[l]}/${SEG.topic[l]}/${id}`,
  map: (l: Locale) => `${BASE[l]}/${SEG.map[l]}`,
  signIn: (l: Locale) => `${BASE[l]}/${SEG.signIn[l]}`,
  confirm: (l: Locale) => `${BASE[l]}/${SEG.signIn[l]}/${SEG.confirm[l]}`,
  /** The second-factor step after the email link, GitHub or Google. */
  verify: (l: Locale) => `${BASE[l]}/${SEG.signIn[l]}/${SEG.verify[l]}`,
  account: (l: Locale) => `${BASE[l]}/${SEG.account[l]}`,
  studio: (l: Locale) => `${BASE[l]}/${SEG.studio[l]}`,
  /** A member's public profile, by its slug (memberSlug). */
  member: (l: Locale, slug: string) => `${BASE[l]}/${SEG.member[l]}/${slug}`,
};

/** A member's profile URL, or null when the author is gone (deleted account) or not a member id. */
export function memberUrl(l: Locale, userId: string | null | undefined): string | null {
  const slug = memberSlug(userId);
  return slug ? cx.member(l, slug) : null;
}

export type CommunityRoute =
  | { view: "home" }
  | { view: "gallery" }
  | { view: "galleryNew" }
  | { view: "galleryItem"; id: string }
  | { view: "forum" }
  | { view: "category"; category: Category }
  | { view: "newTopic" }
  | { view: "topic"; id: string }
  | { view: "map" }
  | { view: "signIn" }
  | { view: "confirm" }
  | { view: "verify" }
  | { view: "account" }
  | { view: "studio" }
  | { view: "member"; slug: string };

/** Parses the segments after /comunidade (or /en/community). Null: not a community page. */
export function parseCommunityPath(lang: Locale, slug: string[] = []): CommunityRoute | null {
  const [a, b, c, ...rest] = slug;
  if (rest.length) return null;
  if (!a) return { view: "home" };
  if (a === SEG.gallery[lang]) {
    if (!b) return { view: "gallery" };
    if (c) return null;
    if (b === SEG.newItem[lang]) return { view: "galleryNew" };
    return /^[2-9a-hj-km-np-z]{12}$/.test(b) ? { view: "galleryItem", id: b } : null;
  }
  if (a === SEG.forum[lang]) {
    if (!b) return { view: "forum" };
    if (b === SEG.topic[lang]) return c && /^[2-9a-hj-km-np-z]{12}$/.test(c) ? { view: "topic", id: c } : null;
    if (c) return null;
    if (b === SEG.newTopic[lang]) return { view: "newTopic" };
    const category = categoryFromUrl(lang, b);
    return category ? { view: "category", category } : null;
  }
  if (a === SEG.member[lang]) return b && !c && /^[2-9a-hj-km-np-z]{12}$/.test(b) ? { view: "member", slug: b } : null;
  if (b && a !== SEG.signIn[lang]) return null;
  if (a === SEG.map[lang]) return { view: "map" };
  if (a === SEG.account[lang]) return { view: "account" };
  if (a === SEG.studio[lang]) return { view: "studio" };
  if (a === SEG.signIn[lang]) {
    if (!b) return { view: "signIn" };
    if (b === SEG.verify[lang] && !c) return { view: "verify" };
    return b === SEG.confirm[lang] && !c ? { view: "confirm" } : null;
  }
  return null;
}

/** The URL of a community route in a language. */
export function communityUrl(lang: Locale, r: CommunityRoute): string {
  switch (r.view) {
    case "home":
      return cx.home(lang);
    case "gallery":
      return cx.gallery(lang);
    case "galleryNew":
      return cx.galleryNew(lang);
    case "galleryItem":
      return cx.galleryItem(lang, r.id);
    case "forum":
      return cx.forum(lang);
    case "category":
      return cx.category(lang, r.category);
    case "newTopic":
      return cx.newTopic(lang);
    case "topic":
      return cx.topic(lang, r.id);
    case "map":
      return cx.map(lang);
    case "signIn":
      return cx.signIn(lang);
    case "confirm":
      return cx.confirm(lang);
    case "verify":
      return cx.verify(lang);
    case "account":
      return cx.account(lang);
    case "studio":
      return cx.studio(lang);
    case "member":
      return cx.member(lang, r.slug);
  }
}

/** The same community page in the other language, or null when `path` is not a community page. */
export function switchCommunityPath(path: string, to: Locale): string | null {
  for (const from of ["pt", "en"] as const) {
    const base = BASE[from];
    if (path !== base && !path.startsWith(`${base}/`)) continue;
    const route = parseCommunityPath(from, path.slice(base.length).split("/").filter(Boolean));
    return route ? communityUrl(to, route) : BASE[to];
  }
  return null;
}

/** Only same-site community and account paths are accepted as a post-sign-in destination. */
export function safeNext(next: string | null | undefined, lang: Locale): string {
  if (next && /^\/(comunidade|en\/community|conta|en\/account|plus|en\/plus|app|en\/app)(\/[A-Za-z0-9/_-]*)?(\?[A-Za-z0-9=&_-]*)?$/.test(next) && !next.includes("//")) return next;
  return cx.home(lang);
}
