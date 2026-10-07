// How long a passed second factor counts.
/** The phone registry and linked computers need the second factor passed in this session within this long. */
export const MFA_SESSION_MS = 12 * 60 * 60 * 1000;
/** Sensitive changes need it passed within this long (a "fresh" check). */
export const MFA_FRESH_MS = 5 * 60 * 1000;
/** Failed second-factor (and password) attempts per account before it locks, the window they count in, the lock. */
export const MFA_MAX_FAILURES = 5;
export const MFA_FAILURE_WINDOW_MS = 15 * 60 * 1000;
export const MFA_LOCK_MS = 15 * 60 * 1000;
