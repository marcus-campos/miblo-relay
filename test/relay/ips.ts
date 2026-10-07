// Client addresses for tests that need "some other visitor". Rate limits and caps count by
// address, and the state they keep (a D1 table, the relay's budget object) is shared by every test
// in a file: a random pick from a small range sometimes lands on an address another test already
// spent, and that test then sees a 429 it did not cause. These come from 100.64.0.0/10 (shared
// address space), which no test names explicitly, and never repeat within a test file.
let next = 0;

/** A fresh IPv4 address, distinct from every other one this helper gave out in this file. */
export function uniqueIp(): string {
  // Host numbers 1..254 only (no .0 or .255), 254 per /24, across the whole /10.
  const n = next++;
  const block = Math.floor(n / 254);
  if (block >= 1 << 14) throw new Error("uniqueIp: out of addresses");
  return `100.${64 + (block >> 8)}.${block & 255}.${(n % 254) + 1}`;
}
