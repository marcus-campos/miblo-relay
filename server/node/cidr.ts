// Address ranges for TRUSTED_PROXY: "10.0.0.5", "172.30.247.0/24", "fd00::/8", comma-separated.
// Only a connection from one of them may say who the client is (X-Forwarded-For).
import net from "node:net";

type Range = { v: 4 | 6; bytes: Buffer; bits: number };

function bytesOf(ip: string): { v: 4 | 6; bytes: Buffer } | null {
  let a = ip.trim().replace(/^\[|\]$/g, "").split("%")[0];
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(a);
  if (mapped) a = mapped[1];
  if (net.isIPv4(a)) return { v: 4, bytes: Buffer.from(a.split(".").map(Number)) };
  if (!net.isIPv6(a)) return null;
  const [head, tail = ""] = a.split("::");
  const h = head ? head.split(":") : [];
  const t = a.includes("::") ? (tail ? tail.split(":") : []) : [];
  const groups = a.includes("::") ? [...h, ...Array(8 - h.length - t.length).fill("0"), ...t] : h;
  const out = Buffer.alloc(16);
  groups.forEach((g, i) => out.writeUInt16BE(parseInt(g, 16), i * 2));
  return { v: 6, bytes: out };
}

/** The ranges in a TRUSTED_PROXY value; null when any entry is not an address or a CIDR. */
export function parseRanges(value: string | undefined): Range[] | null {
  if (!value) return [];
  const out: Range[] = [];
  for (const part of value.split(",").map((x) => x.trim()).filter(Boolean)) {
    const [addr, b] = part.split("/");
    const ip = bytesOf(addr);
    if (!ip) return null;
    const max = ip.v === 4 ? 32 : 128;
    const bits = b === undefined ? max : Number(b);
    if (!Number.isInteger(bits) || bits < 0 || bits > max) return null;
    out.push({ ...ip, bits });
  }
  return out;
}

export function inRanges(ip: string | undefined, ranges: Range[]): boolean {
  const a = ip ? bytesOf(ip) : null;
  if (!a) return false;
  return ranges.some((r) => {
    if (r.v !== a.v) return false;
    const full = Math.floor(r.bits / 8);
    if (!a.bytes.subarray(0, full).equals(r.bytes.subarray(0, full))) return false;
    const rest = r.bits % 8;
    if (!rest) return true;
    const mask = (0xff << (8 - rest)) & 0xff;
    return (a.bytes[full] & mask) === (r.bytes[full] & mask);
  });
}
