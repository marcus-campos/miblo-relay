// Types of src/lib/qr.js (the QR encoder copied from the Miblo plugin).
export type Qr = { size: number; modules: boolean[][] };
export declare const ECC: Readonly<Record<"L" | "M" | "Q" | "H", { ord: number; fmt: number }>>;
export declare function encodeQr(text: string, opts?: { minEcc?: { ord: number; fmt: number }; mask?: number }): Qr;
export declare function qrToSvg(qr: Qr, opts?: { quiet?: number; scale?: number }): string;
/** The dark modules as one SVG path, `size` modules square including the quiet zone. */
export declare function qrPath(text: string, opts?: { quiet?: number }): { size: number; d: string };
