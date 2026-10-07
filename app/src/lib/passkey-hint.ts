// A per-browser hint that this browser has an account passkey (it signed in with one, created one
// or passed the second factor with one), so the sign-in page offers "Sign in with a passkey" first.
// Not a secret and never trusted by the server; storage may be blocked (private mode).
const KEY = "miblo.passkey";

export function rememberPasskey(): void {
  try {
    localStorage.setItem(KEY, "1");
  } catch {
    // Storage blocked: the passkey button simply stays second.
  }
}

export function passkeyHinted(): boolean {
  try {
    return localStorage.getItem(KEY) === "1";
  } catch {
    return false;
  }
}
