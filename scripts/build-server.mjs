// Bundles the Node runtime into dist/server.mjs (one file; `ws` and `zod` included), so the
// Docker image needs no node_modules. Deterministic: no timestamps, no absolute paths.
import { build } from "esbuild";

await build({
  entryPoints: ["server/node/main.ts"],
  outfile: "dist/server.mjs",
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  legalComments: "inline",
  sourcemap: false,
  logLevel: "warning",
  // ws optionally loads native helpers; without them it uses its JavaScript fallbacks.
  external: ["bufferutil", "utf-8-validate"],
  banner: { js: "import { createRequire as __mibloRequire } from 'node:module'; const require = __mibloRequire(import.meta.url);" },
});
console.log("dist/server.mjs");
