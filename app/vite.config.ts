// The phone app (the same React code as miblo.ai/app), the account page and the front page,
// built into dist/public for both runtimes. Deterministic output (content-hashed file names).
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));

export default defineConfig({
  root: here("."),
  publicDir: here("./public"),
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: [
      { find: /^@\//, replacement: `${here("./src")}/` },
      { find: /^next\/navigation$/, replacement: here("./shims/next-navigation.ts") },
      { find: /^next\/font\/google$/, replacement: here("./shims/next-font.ts") },
      { find: /^next$/, replacement: here("./shims/next.ts") },
    ],
  },
  build: {
    outDir: here("../dist/public"),
    emptyOutDir: true,
    sourcemap: false,
    assetsInlineLimit: 0,
    rollupOptions: {
      input: {
        index: here("./index.html"),
        app: here("./app/index.html"),
        "en-app": here("./en/app/index.html"),
        conta: here("./conta/index.html"),
        "en-account": here("./en/account/index.html"),
      },
    },
  },
});
