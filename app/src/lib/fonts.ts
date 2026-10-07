import { Atkinson_Hyperlegible_Mono, Atkinson_Hyperlegible_Next, Pixelify_Sans } from "next/font/google";

// Self-hosted at build time by next/font.
// Pixelify Sans echoes the device's pixel screen; Atkinson Hyperlegible keeps body text easy to read.
export const pixel = Pixelify_Sans({ subsets: ["latin"], weight: ["500", "600"], variable: "--font-pixel", display: "swap" });
export const body = Atkinson_Hyperlegible_Next({ subsets: ["latin"], weight: ["400", "700"], variable: "--font-body", display: "swap", adjustFontFallback: false });
export const code = Atkinson_Hyperlegible_Mono({ subsets: ["latin"], weight: ["400"], variable: "--font-code", display: "swap", adjustFontFallback: false });

export const fontVars = `${pixel.variable} ${body.variable} ${code.variable}`;
