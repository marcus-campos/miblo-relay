import "@/app/globals.css";
import type { Metadata, Viewport } from "next";
import { ThemeScript } from "@/components/ThemeScript";
import { fontVars } from "@/lib/fonts";
import { htmlLang, type Locale } from "@/lib/i18n";

// Root document of the phone app: its own <html>, outside the site's header and footer, so the
// installed app is just the app.

export const phoneViewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  viewportFit: "cover",
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#e6e9ee" },
    { media: "(prefers-color-scheme: dark)", color: "#10141b" },
  ],
};

export function phoneMetadata(lang: Locale): Metadata {
  const base = lang === "en" ? "/en/app" : "/app";
  return {
    title: "Miblo",
    description: lang === "en" ? "Your Claude Code sessions, live on your phone." : "Suas sessões do Claude Code, ao vivo no celular.",
    manifest: `${base}/manifest.webmanifest`,
    applicationName: "Miblo",
    appleWebApp: { capable: true, title: "Miblo", statusBarStyle: "default" },
    icons: {
      icon: [{ url: "/app/icon-192.png", sizes: "192x192", type: "image/png" }],
      apple: [{ url: "/app/apple-touch-icon.png", sizes: "180x180" }],
    },
    robots: { index: false, follow: false },
    formatDetection: { telephone: false },
  };
}

export function PhoneShell({ lang, children }: { lang: Locale; children: React.ReactNode }) {
  return (
    <html lang={htmlLang[lang]} className={fontVars} suppressHydrationWarning>
      {/* App Router root layout: a plain <head> is correct here. */}
      {/* eslint-disable-next-line @next/next/no-head-element */}
      <head>
        <ThemeScript />
      </head>
      <body className="min-h-dvh antialiased">
        <main id="main">{children}</main>
      </body>
    </html>
  );
}
