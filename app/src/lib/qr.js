// A small QR Code encoder (byte mode, versions 1-40): the account's TOTP setup shows its otpauth://
// URI as a QR code. Copied from the Miblo plugin's lib/qr.js (the phone companion's pairing link),
// with UTF-8 through TextEncoder and the terminal renderer dropped. No dependencies.
//
// Ported from Project Nayuki's QR Code generator library (https://www.nayuki.io/page/qr-code-generator-library),
// trimmed to byte mode. Copyright (c) Project Nayuki. MIT License:
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
// associated documentation files (the "Software"), to deal in the Software without restriction,
// including without limitation the rights to use, copy, modify, merge, publish, distribute,
// sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions: The above copyright notice and this
// permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.

// Error correction levels, in increasing strength; `fmt` is the 2-bit value in the format bits.
export const ECC = Object.freeze({ L: { ord: 0, fmt: 1 }, M: { ord: 1, fmt: 0 }, Q: { ord: 2, fmt: 3 }, H: { ord: 3, fmt: 2 } });
const LEVELS = [ECC.L, ECC.M, ECC.Q, ECC.H];

const ECC_CODEWORDS_PER_BLOCK = [
  [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
];
const NUM_ERROR_CORRECTION_BLOCKS = [
  [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
];

const bit = (x, i) => ((x >>> i) & 1) !== 0;

function rawDataModules(ver) {
  let r = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const n = Math.floor(ver / 7) + 2;
    r -= (25 * n - 10) * n - 55;
    if (ver >= 7) r -= 36;
  }
  return r;
}

export function dataCodewords(ver, ecl) {
  return Math.floor(rawDataModules(ver) / 8) - ECC_CODEWORDS_PER_BLOCK[ecl.ord][ver] * NUM_ERROR_CORRECTION_BLOCKS[ecl.ord][ver];
}

function gfMul(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z;
}

function rsDivisor(degree) {
  const r = new Array(degree).fill(0);
  r[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < r.length; j++) {
      r[j] = gfMul(r[j], root);
      if (j + 1 < r.length) r[j] ^= r[j + 1];
    }
    root = gfMul(root, 0x02);
  }
  return r;
}

function rsRemainder(data, divisor) {
  const r = divisor.map(() => 0);
  for (const b of data) {
    const factor = b ^ r.shift();
    r.push(0);
    divisor.forEach((coef, i) => { r[i] ^= gfMul(coef, factor); });
  }
  return r;
}

// Encodes `text` (UTF-8, byte mode) at the smallest version that fits with at least `minEcc`,
// then raises the error correction while it still fits that version. `mask` 0-7 forces a mask
// (tests); by default the one with the lowest penalty is used.
// Returns { size, version, ecc, mask, modules } with modules[y][x] true = dark.
export function encodeQr(text, { minEcc = ECC.M, mask = -1 } = {}) {
  const data = [...new TextEncoder().encode(String(text))];
  let ver;
  let used;
  for (ver = 1; ; ver++) {
    used = 4 + (ver < 10 ? 8 : 16) + data.length * 8;
    if (used <= dataCodewords(ver, minEcc) * 8) break;
    if (ver >= 40) throw new RangeError('text too long for a QR code');
  }
  let ecl = minEcc;
  for (const e of LEVELS) if (e.ord > ecl.ord && used <= dataCodewords(ver, e) * 8) ecl = e;

  const bits = [];
  const put = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
  put(4, 4);
  put(data.length, ver < 10 ? 8 : 16);
  for (const b of data) put(b, 8);
  const cap = dataCodewords(ver, ecl) * 8;
  put(0, Math.min(4, cap - bits.length));
  put(0, (8 - (bits.length % 8)) % 8);
  for (let pad = 0xec; bits.length < cap; pad ^= 0xec ^ 0x11) put(pad, 8);
  const codewords = [];
  for (let i = 0; i < bits.length; i += 8) codewords.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));

  return new Matrix(ver, ecl, codewords, mask).result();
}

class Matrix {
  constructor(ver, ecl, codewords, mask) {
    this.ver = ver;
    this.ecl = ecl;
    this.size = ver * 4 + 17;
    this.mod = Array.from({ length: this.size }, () => new Array(this.size).fill(false));
    this.fn = Array.from({ length: this.size }, () => new Array(this.size).fill(false));
    this.drawFunctionPatterns();
    this.drawCodewords(this.interleave(codewords));
    if (mask < 0) {
      let best = Infinity;
      for (let m = 0; m < 8; m++) {
        this.applyMask(m);
        this.drawFormat(m);
        const p = this.penalty();
        if (p < best) { best = p; mask = m; }
        this.applyMask(m);
      }
    }
    this.mask = mask;
    this.applyMask(mask);
    this.drawFormat(mask);
  }

  result() {
    return { size: this.size, version: this.ver, ecc: this.ecl, mask: this.mask, modules: this.mod };
  }

  set(x, y, dark) {
    this.mod[y][x] = dark;
    this.fn[y][x] = true;
  }

  drawFunctionPatterns() {
    const n = this.size;
    for (let i = 0; i < n; i++) {
      this.set(6, i, i % 2 === 0);
      this.set(i, 6, i % 2 === 0);
    }
    this.finder(3, 3);
    this.finder(n - 4, 3);
    this.finder(3, n - 4);
    const pos = this.alignmentPositions();
    const k = pos.length;
    for (let i = 0; i < k; i++) {
      for (let j = 0; j < k; j++) {
        if (!((i === 0 && j === 0) || (i === 0 && j === k - 1) || (i === k - 1 && j === 0))) this.alignment(pos[i], pos[j]);
      }
    }
    this.drawFormat(0);
    this.drawVersion();
  }

  drawFormat(mask) {
    const data = (this.ecl.fmt << 3) | mask;
    let rem = data;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    const bits = ((data << 10) | rem) ^ 0x5412;
    const n = this.size;
    for (let i = 0; i <= 5; i++) this.set(8, i, bit(bits, i));
    this.set(8, 7, bit(bits, 6));
    this.set(8, 8, bit(bits, 7));
    this.set(7, 8, bit(bits, 8));
    for (let i = 9; i < 15; i++) this.set(14 - i, 8, bit(bits, i));
    for (let i = 0; i < 8; i++) this.set(n - 1 - i, 8, bit(bits, i));
    for (let i = 8; i < 15; i++) this.set(8, n - 15 + i, bit(bits, i));
    this.set(8, n - 8, true);
  }

  drawVersion() {
    if (this.ver < 7) return;
    let rem = this.ver;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (this.ver << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const a = this.size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      this.set(a, b, bit(bits, i));
      this.set(b, a, bit(bits, i));
    }
  }

  finder(x, y) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const d = Math.max(Math.abs(dx), Math.abs(dy));
        const xx = x + dx;
        const yy = y + dy;
        if (xx >= 0 && xx < this.size && yy >= 0 && yy < this.size) this.set(xx, yy, d !== 2 && d !== 4);
      }
    }
  }

  alignment(x, y) {
    for (let dy = -2; dy <= 2; dy++) {
      for (let dx = -2; dx <= 2; dx++) this.set(x + dx, y + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
  }

  alignmentPositions() {
    if (this.ver === 1) return [];
    const k = Math.floor(this.ver / 7) + 2;
    const step = Math.floor((this.ver * 8 + k * 3 + 5) / (k * 4 - 4)) * 2;
    const r = [6];
    for (let p = this.size - 7; r.length < k; p -= step) r.splice(1, 0, p);
    return r;
  }

  interleave(data) {
    const numBlocks = NUM_ERROR_CORRECTION_BLOCKS[this.ecl.ord][this.ver];
    const eccLen = ECC_CODEWORDS_PER_BLOCK[this.ecl.ord][this.ver];
    const raw = Math.floor(rawDataModules(this.ver) / 8);
    const numShort = numBlocks - (raw % numBlocks);
    const shortLen = Math.floor(raw / numBlocks);
    const div = rsDivisor(eccLen);
    const blocks = [];
    for (let i = 0, k = 0; i < numBlocks; i++) {
      const dat = data.slice(k, k + shortLen - eccLen + (i < numShort ? 0 : 1));
      k += dat.length;
      const ecc = rsRemainder(dat, div);
      if (i < numShort) dat.push(0);
      blocks.push(dat.concat(ecc));
    }
    const out = [];
    for (let i = 0; i < blocks[0].length; i++) {
      blocks.forEach((b, j) => {
        if (i !== shortLen - eccLen || j >= numShort) out.push(b[i]);
      });
    }
    return out;
  }

  drawCodewords(data) {
    const n = this.size;
    let i = 0;
    for (let right = n - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let v = 0; v < n; v++) {
        for (let j = 0; j < 2; j++) {
          const x = right - j;
          const up = ((right + 1) & 2) === 0;
          const y = up ? n - 1 - v : v;
          if (!this.fn[y][x] && i < data.length * 8) {
            this.mod[y][x] = bit(data[i >>> 3], 7 - (i & 7));
            i++;
          }
        }
      }
    }
  }

  applyMask(m) {
    for (let y = 0; y < this.size; y++) {
      for (let x = 0; x < this.size; x++) {
        let inv;
        switch (m) {
          case 0: inv = (x + y) % 2 === 0; break;
          case 1: inv = y % 2 === 0; break;
          case 2: inv = x % 3 === 0; break;
          case 3: inv = (x + y) % 3 === 0; break;
          case 4: inv = (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0; break;
          case 5: inv = ((x * y) % 2) + ((x * y) % 3) === 0; break;
          case 6: inv = (((x * y) % 2) + ((x * y) % 3)) % 2 === 0; break;
          default: inv = (((x + y) % 2) + ((x * y) % 3)) % 2 === 0; break;
        }
        if (inv && !this.fn[y][x]) this.mod[y][x] = !this.mod[y][x];
      }
    }
  }

  // The standard penalty rules (runs, 2x2 blocks, finder-like patterns, dark/light balance),
  // used only to pick a mask that scans well; any mask gives a valid code.
  penalty() {
    const n = this.size;
    const m = this.mod;
    let p = 0;
    const lines = [];
    for (let y = 0; y < n; y++) lines.push(m[y]);
    for (let x = 0; x < n; x++) lines.push(m.map((row) => row[x]));
    const finder = [true, false, true, true, true, false, true];
    for (const line of lines) {
      let run = 1;
      for (let i = 1; i <= n; i++) {
        if (i < n && line[i] === line[i - 1]) run++;
        else {
          if (run >= 5) p += run - 2;
          run = 1;
        }
      }
      for (let i = 0; i + 7 <= n; i++) {
        if (!finder.every((v, k) => line[i + k] === v)) continue;
        const lightBefore = [1, 2, 3, 4].every((k) => i - k < 0 || !line[i - k]);
        const lightAfter = [0, 1, 2, 3].every((k) => i + 7 + k >= n || !line[i + 7 + k]);
        if (lightBefore || lightAfter) p += 40;
      }
    }
    let dark = 0;
    for (let y = 0; y < n; y++) {
      for (let x = 0; x < n; x++) {
        if (m[y][x]) dark++;
        if (x + 1 < n && y + 1 < n && m[y][x] === m[y][x + 1] && m[y][x] === m[y + 1][x] && m[y][x] === m[y + 1][x + 1]) p += 3;
      }
    }
    const total = n * n;
    p += (Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1) * 10;
    return p;
  }
}

// The code as a standalone SVG (black on white, `quiet` modules of margin).
export function qrToSvg(qr, { quiet = 4, scale = 8 } = {}) {
  const n = qr.size + quiet * 2;
  let d = '';
  for (let y = 0; y < qr.size; y++) {
    for (let x = 0; x < qr.size; x++) if (qr.modules[y][x]) d += `M${x + quiet},${y + quiet}h1v1h-1z`;
  }
  return `<?xml version="1.0" encoding="UTF-8"?>\n<svg xmlns="http://www.w3.org/2000/svg" width="${n * scale}" height="${n * scale}" viewBox="0 0 ${n} ${n}" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#fff"/><path d="${d}" fill="#000"/></svg>\n`;
}

// The dark modules as one SVG path (for a React <path d>), with `quiet` modules of margin.
export function qrPath(text, { quiet = 4 } = {}) {
  const qr = encodeQr(text, { minEcc: ECC.M });
  let d = '';
  for (let y = 0; y < qr.size; y++) {
    for (let x = 0; x < qr.size; x++) if (qr.modules[y][x]) d += `M${x + quiet},${y + quiet}h1v1h-1z`;
  }
  return { size: qr.size + quiet * 2, d };
}
