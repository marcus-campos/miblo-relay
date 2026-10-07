// A short, human description of a browser from its User-Agent ("Chrome no Mac", "Safari on
// iPhone"), for the sign-in approval page. Approximate on purpose: enough for a person to tell
// whether the waiting browser is theirs, never used for any security decision.
import type { Locale } from "./i18n";

function browserOf(ua: string): string | null {
  if (/EdgA?\/|EdgiOS\//.test(ua)) return "Edge";
  if (/OPR\/|Opera/.test(ua)) return "Opera";
  if (/SamsungBrowser\//.test(ua)) return "Samsung Internet";
  if (/Firefox\/|FxiOS\//.test(ua)) return "Firefox";
  if (/Chrome\/|CriOS\//.test(ua)) return "Chrome";
  if (/Safari\//.test(ua) && /Version\//.test(ua)) return "Safari";
  return null;
}

function systemOf(ua: string): string | null {
  if (/iPhone/.test(ua)) return "iPhone";
  if (/iPad/.test(ua)) return "iPad";
  if (/Android/.test(ua)) return "Android";
  if (/CrOS/.test(ua)) return "ChromeOS";
  if (/Macintosh|Mac OS X/.test(ua)) return "Mac";
  if (/Windows/.test(ua)) return "Windows";
  if (/Linux/.test(ua)) return "Linux";
  return null;
}

export function describeAgent(ua: string, lang: Locale): string {
  const b = browserOf(ua ?? "");
  const s = systemOf(ua ?? "");
  const on = lang === "pt" ? "no" : "on";
  if (b && s) return `${b} ${on} ${s}`;
  if (b) return b;
  if (s) return lang === "pt" ? `Um navegador ${on} ${s}` : `A browser ${on} ${s}`;
  return lang === "pt" ? "Um navegador desconhecido" : "An unknown browser";
}

/** "Brasília, Brasil" from a stored "city|CC" place; null when nothing is known. */
export function describePlace(place: string | null | undefined, lang: Locale): string | null {
  if (!place) return null;
  const [city, cc] = place.split("|");
  let country = "";
  if (cc && /^[A-Z]{2}$/.test(cc)) {
    try {
      country = new Intl.DisplayNames([lang === "pt" ? "pt-BR" : "en"], { type: "region" }).of(cc) ?? cc;
    } catch {
      country = cc;
    }
  }
  const out = [city, country].filter(Boolean).join(", ");
  return out || null;
}
