// Service worker registration and the Web Push subscription the relay rooms send alerts to.
import { fromB64url } from "@/lib/relay-crypto";

/** The service worker's scope: the app's folder, with the slash (it never covers /apps etc.). */
export function appScope(lang: "pt" | "en"): string {
  return lang === "en" ? "/en/app/" : "/app/";
}

/** Earlier builds registered the scope without the slash: those registrations are retired. */
async function retireLegacyWorkers(): Promise<void> {
  const all = await navigator.serviceWorker.getRegistrations();
  await Promise.all(
    all.filter((r) => ["/app", "/en/app"].includes(new URL(r.scope).pathname)).map((r) => r.unregister().catch(() => false)),
  );
}

export async function registerWorker(lang: "pt" | "en"): Promise<ServiceWorkerRegistration | null> {
  if (!("serviceWorker" in navigator)) return null;
  try {
    await retireLegacyWorkers().catch(() => {});
    return await navigator.serviceWorker.register("/sw.js", { scope: appScope(lang) });
  } catch {
    return null;
  }
}

export function pushSupported(): boolean {
  return typeof window !== "undefined" && "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
}

export function isIos(): boolean {
  const ua = navigator.userAgent;
  return /iPhone|iPad|iPod/.test(ua) || (ua.includes("Macintosh") && navigator.maxTouchPoints > 1);
}

export function isStandalone(): boolean {
  return matchMedia("(display-mode: standalone)").matches || (navigator as Navigator & { standalone?: boolean }).standalone === true;
}

async function vapidKey(): Promise<Uint8Array<ArrayBuffer>> {
  const res = await fetch("/api/relay/vapid");
  if (!res.ok) throw new Error("vapid_unavailable");
  const { publicKey } = (await res.json()) as { publicKey: string };
  return fromB64url(publicKey);
}

/** The current subscription, if alerts were already turned on (and still allowed). */
export async function currentSubscription(lang: "pt" | "en"): Promise<PushSubscription | null> {
  if (!pushSupported() || Notification.permission !== "granted") return null;
  const reg = await navigator.serviceWorker.getRegistration(appScope(lang));
  return (await reg?.pushManager.getSubscription()) ?? null;
}

/** Asks for permission and subscribes. Throws "denied" when the person (or browser) said no. */
export async function subscribe(lang: "pt" | "en"): Promise<PushSubscription> {
  const permission = await Notification.requestPermission();
  if (permission !== "granted") throw new Error("denied");
  const reg = (await registerWorker(lang)) ?? (await navigator.serviceWorker.ready);
  await navigator.serviceWorker.ready;
  const existing = await reg.pushManager.getSubscription();
  if (existing) return existing;
  return reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: await vapidKey() });
}

/**
 * A fresh endpoint: the old one stops working, so rooms that still hold it (a computer removed
 * from this phone) drop it on their next push (410) while the remaining rooms get the new one.
 */
export async function rotateSubscription(lang: "pt" | "en"): Promise<PushSubscription | null> {
  const old = await currentSubscription(lang);
  if (!old) return null;
  await old.unsubscribe().catch(() => false);
  return subscribe(lang);
}

export async function unsubscribeAll(lang: "pt" | "en"): Promise<void> {
  const sub = await currentSubscription(lang);
  await sub?.unsubscribe().catch(() => false);
}

export function subFrame(sub: PushSubscription, lang: "pt" | "en") {
  return { t: "sub", sub: sub.toJSON(), lang: lang === "pt" ? "pt-BR" : "en" };
}
