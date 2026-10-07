// TRUSTED_PROXY: only connections from the proxy's own addresses may name the client.
import { describe, expect, it } from "vitest";
import { inRanges, parseRanges } from "../server/node/cidr";

describe("trusted proxy ranges", () => {
  it("matches IPv4, IPv6 and v4-mapped addresses against CIDRs", () => {
    const r = parseRanges("172.30.247.0/24, fd00::/8, 10.0.0.5")!;
    expect(inRanges("172.30.247.9", r)).toBe(true);
    expect(inRanges("::ffff:172.30.247.9", r)).toBe(true);
    expect(inRanges("172.30.248.9", r)).toBe(false);
    expect(inRanges("fd12::1", r)).toBe(true);
    expect(inRanges("fe80::1", r)).toBe(false);
    expect(inRanges("10.0.0.5", r)).toBe(true);
    expect(inRanges("10.0.0.6", r)).toBe(false);
    expect(inRanges(undefined, r)).toBe(false);
  });
  it("refuses what is not a list of addresses (TRUSTED_PROXY=1 trusts nobody)", () => {
    expect(parseRanges("1")).toBeNull();
    expect(parseRanges("10.0.0.0/33")).toBeNull();
    expect(parseRanges("")).toEqual([]);
  });
});
