// Periodic cleanup (Node: hourly timer; Cloudflare: the cron trigger): what has expired goes, so
// the database keeps only what is still in use.
import type { RequestScope } from "./env";

const DAY = 86_400_000;

export async function housekeeping(scope: RequestScope, now = Date.now()): Promise<void> {
  const { DB } = scope.env;
  const iso = (ms: number) => new Date(ms).toISOString();
  await DB.batch([
    DB.prepare(`DELETE FROM sessions WHERE expires_at < ?`).bind(iso(now)),
    DB.prepare(`DELETE FROM mfa_challenges WHERE expires_at < ?`).bind(iso(now)),
    DB.prepare(`DELETE FROM mfa_failures WHERE window_start < ? AND (locked_until IS NULL OR locked_until < ?)`).bind(iso(now - DAY), iso(now)),
    // Device codes: a day after they expired (consumed ones too: their token lives in plus_devices).
    DB.prepare(`DELETE FROM plus_device_codes WHERE expires_at < ?`).bind(iso(now - DAY)),
    // Phones revoked more than 90 days ago (the computers have revoked them by then).
    DB.prepare(`DELETE FROM phone_requests WHERE phone_id IN (SELECT id FROM account_phones WHERE revoked_at IS NOT NULL AND revoked_at < ?)`).bind(iso(now - 90 * DAY)),
    DB.prepare(`DELETE FROM phone_grants WHERE phone_id IN (SELECT id FROM account_phones WHERE revoked_at IS NOT NULL AND revoked_at < ?)`).bind(iso(now - 90 * DAY)),
    DB.prepare(`DELETE FROM account_phones WHERE revoked_at IS NOT NULL AND revoked_at < ?`).bind(iso(now - 90 * DAY)),
  ]);
}
