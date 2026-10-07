// The in-memory rate limiter fails closed: a flood of new keys never resets a live count.
import { afterEach, describe, expect, it } from "vitest";
import { LIMIT_KEYS, memoryLimit, resetLimits } from "../server/core/http";

afterEach(() => resetLimits());

describe("the rate limiter", () => {
  it("keeps a live count when the table is full and refuses the new key instead", () => {
    const t = 1_000_000;
    for (let i = 0; i < 3; i++) memoryLimit("victim-attacker", 3, 60_000, t);
    // The table fills with other live keys.
    for (let i = 0; i < LIMIT_KEYS; i++) memoryLimit(`flood-${i}`, 3, 60_000, t + 1);
    // A new key is refused (fail closed) and the old count was not dropped: still over the limit.
    expect(memoryLimit("brand-new", 3, 60_000, t + 2)).toBe(false);
    expect(memoryLimit("victim-attacker", 3, 60_000, t + 3)).toBe(false);
    // Once the windows expire, new keys are counted again.
    expect(memoryLimit("brand-new", 3, 60_000, t + 60_002)).toBe(true);
  });
});
