// next/font for the plain (Vite) build: the fonts come from @fontsource (app/entries/fonts.css),
// self-hosted with the build like next/font does; the CSS variables are set there.
type FontOptions = { variable?: string; [k: string]: unknown };
const font = (o: FontOptions = {}) => ({ variable: "", className: "", style: { fontFamily: o.variable ?? "" } });
export const Pixelify_Sans = font;
export const Atkinson_Hyperlegible_Next = font;
export const Atkinson_Hyperlegible_Mono = font;
