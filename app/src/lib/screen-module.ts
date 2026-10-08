// Where the phone app fetches the Miblo's screen module (lib/generated/miblo-screen.js, the
// product repository's `make screenweb`): a versioned name under /miblo-screen/, so it never
// changes and is cached for good (public/_headers). The self-hosted relay serves the same file.
import meta from "./generated/miblo-screen.json";

export const SCREEN_WASM = `/miblo-screen/miblo-screen-${meta.firmware}-${meta.sha256.slice(0, 12)}.wasm`;
