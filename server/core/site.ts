// The whole server as one fetch handler: the API (app.ts), then the pages and files of the phone
// app and the account page (built by Vite into dist/public, served by the runtime through
// `assets`), every response with the security headers.
import type { RequestScope } from "./env";
import { handleApi } from "./app";
import { publicOrigin } from "./config";

/** Reads one built file (a path like "/app/index.html"), or null when there is none. */
export type Assets = (path: string, request: Request) => Promise<Response | null>;

/** Where a page path is served from: a file of the build, or a redirect. */
export function pageFor(pathname: string): { file: string } | { redirect: string } | null {
  if (pathname === "/" || pathname === "/index.html") return { file: "/index.html" };
  // The phone app lives at /app/ (its service worker's scope); /app redirects there.
  if (pathname === "/app" || pathname === "/en/app") return { redirect: `${pathname}/` };
  if (pathname === "/app/" || pathname === "/app/index.html") return { file: "/app/index.html" };
  if (pathname === "/en/app/" || pathname === "/en/app/index.html") return { file: "/en/app/index.html" };
  // The account page (the phone app's links, the plugin's device-link address).
  if (pathname === "/conta" || pathname.startsWith("/conta/") || pathname === "/plus/link") return { file: "/conta/index.html" };
  if (pathname === "/en/account" || pathname.startsWith("/en/account/") || pathname === "/en/plus/link") return { file: "/en/account/index.html" };
  // Links of the shared phone app code that point at miblo.ai's own pages.
  if (pathname === "/plus") return { redirect: "/conta" };
  if (pathname === "/en/plus") return { redirect: "/en/account" };
  if (/^\/(en\/)?(docs|downloads|guia|guide)(\/.*)?$/.test(pathname)) return { redirect: pathname.startsWith("/en/") ? "/en/app/" : "/" };
  if (pathname === "/en") return { redirect: "/en/app/" };
  return null;
}

export function contentSecurityPolicy(origin: URL): string {
  const ws = `${origin.protocol === "https:" ? "wss" : "ws"}://${origin.host}`;
  return [
    "default-src 'self'",
    // 'wasm-unsafe-eval': the Miblo's own pet renderer (/miblo-look/*.wasm, from 'self'); it
    // allows WebAssembly compilation only, never eval() or an inline script.
    "script-src 'self' 'wasm-unsafe-eval'",
    "script-src-attr 'none'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    // The relay WebSocket ('self' covers it in CSP3 browsers; older Safari needs it named).
    `connect-src 'self' ${ws}`,
    "worker-src 'self'",
    "manifest-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}

const HEADERS: Record<string, string> = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=(), interest-cohort=()",
  "Cross-Origin-Opener-Policy": "same-origin",
};

export function withSecurityHeaders(response: Response, origin: URL): Response {
  // Upgrades carry no document and cannot be re-wrapped.
  if (response.status === 101 || (response as Response & { webSocket?: unknown }).webSocket || response.headers.has("x-miblo-upgrade")) return response;
  const out = new Response(response.body, response);
  for (const [name, value] of Object.entries(HEADERS)) if (!out.headers.has(name)) out.headers.set(name, value);
  if (origin.protocol === "https:" && !out.headers.has("Strict-Transport-Security")) out.headers.set("Strict-Transport-Security", "max-age=31536000");
  if (!out.headers.has("Content-Security-Policy")) out.headers.set("Content-Security-Policy", contentSecurityPolicy(origin));
  return out;
}

export async function handle(scope: RequestScope, request: Request, assets: Assets): Promise<Response> {
  const origin = publicOrigin(scope.env);
  if (!origin) return new Response("This server is not configured: set PUBLIC_ORIGIN (see the README).", { status: 503 });
  const api = await handleApi(scope, request);
  if (api) return withSecurityHeaders(api, origin);
  if (request.method !== "GET" && request.method !== "HEAD") return withSecurityHeaders(new Response("method not allowed", { status: 405 }), origin);
  const url = new URL(request.url);
  const page = pageFor(url.pathname);
  if (page && "redirect" in page) {
    return withSecurityHeaders(new Response(null, { status: 308, headers: { Location: `${page.redirect}${url.search}`, "Cache-Control": "no-store" } }), origin);
  }
  const file = page ? page.file : url.pathname;
  // No dot segments or encoded tricks reach the files.
  if (file.includes("..") || file.includes("\\") || file.includes("%")) return withSecurityHeaders(new Response("not found", { status: 404 }), origin);
  const res = await assets(file, request);
  if (!res) return withSecurityHeaders(new Response("not found", { status: 404, headers: { "Content-Type": "text/plain; charset=utf-8" } }), origin);
  const out = new Response(res.body, res);
  // Pages and the service worker are always fetched fresh; hashed build files are immutable.
  if (page || file === "/sw.js" || file.endsWith(".webmanifest")) out.headers.set("Cache-Control", "no-cache");
  else if (file.startsWith("/assets/")) out.headers.set("Cache-Control", "public, max-age=31536000, immutable");
  return withSecurityHeaders(out, origin);
}
