import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@": new URL("./app/src", import.meta.url).pathname,
      // The app build's shim (app/vite.config.ts): lets tests render phone screens that import it.
      "next/navigation": new URL("./app/shims/next-navigation.ts", import.meta.url).pathname,
    },
  },
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
});
