// Whether the phone app is locked right now (PIN not typed yet, idle lock, or blocked), read by the
// functions that act on a computer or the account (RelayClient.sendUp, answerCode,
// confirmComputer): they refuse while it is locked, whatever the screen shows. Locked until the
// app's lock says otherwise (useAppLock).
let locked = true;

export function isAppLocked(): boolean {
  return locked;
}

export function setAppLocked(value: boolean): void {
  locked = value;
}

/** Thrown by a gated function called while the app is locked. */
export class AppLockedError extends Error {
  constructor() {
    super("app_locked");
  }
}
