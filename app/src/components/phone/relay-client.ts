// A reader connection to one room of the phone relay (docs/phone-relay-protocol.md):
// authenticates, decrypts frames, keeps the socket alive and reconnects with backoff.
//
// v5: an enrolled phone authenticates with its own reader token (derived from its MAC key) and its
// phone id, so the relay knows it apart from the others and drops it once it is revoked (4411).
// Miblo+ frames reach it sealed to it alone (openSealed) and everything it sends goes sealed under
// its own key (sealUp). Without an identity (not enrolled yet, or restored from the vault) it is a
// guest: the status, plus the answer to its enrollment, which travels under the pairing window's
// key (sendEnroll / openEnrolled).
import { decryptFrame, enrollKey, openEnrolled, openSealed, phoneFrameKey, readerToken, sealEnroll, sealUp, type Frame } from "@/lib/relay-crypto";
import { isAppLocked } from "./lock-state";
import type { StoredPairing } from "./store";

/**
 * "limit": the room's plan allows no more phones right now (free: 1 at a time, close 4406).
 * "revoked": this phone was removed on the computer (4411).
 */
export type LinkState = "connecting" | "open" | "retrying" | "offline" | "refused" | "deleted" | "limit" | "revoked";

/** Channels the phone reads (v3): the snapshot and, on Miblo+, history, replies' acks and approvals. */
const READ_CHANNELS = new Set(["status", "history", "reply", "approval"]);

/** This phone's identity at the relay for one pairing (derived from its MAC key). */
type Identity = { phone: string; token: string; key: CryptoKey };

type Listener = {
  onState(state: LinkState): void;
  /** `sealed`: it came sealed to this phone alone (never true for the shared-key status). */
  onPayload(payload: unknown, ch: string, sealed?: boolean): void;
  /** v3: the relay closed this phone's socket with 4402: the room is not on Miblo+ (any more). */
  onPlanRefused?(): void;
};

const PING_MS = 25_000;
/** Spacing between a phone's "up" frames (the relay allows one per second). */
const UP_SPACING_MS = 1_100;
const PONG_TIMEOUT_MS = 10_000;

export function relayUrl(room: string): string {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${location.host}/api/relay/${room}?role=reader`;
}

export class RelayClient {
  private ws: WebSocket | null = null;
  private attempt = 0;
  /** Consecutive 4403 closes (room not registered by the computer yet). */
  private notReady = 0;
  private retryTimer: ReturnType<typeof setTimeout> | undefined;
  private pingTimer: ReturnType<typeof setInterval> | undefined;
  private pongTimer: ReturnType<typeof setTimeout> | undefined;
  private stopped = false;
  private state: LinkState = "connecting";
  private identity: Promise<Identity | null> = Promise.resolve(null);
  /** The relay refused this phone's own token (4401): try once as a guest (the shared token). */
  private guest = false;

  constructor(
    private readonly pairing: StoredPairing,
    private readonly listener: Listener,
  ) {}

  /** What this client was made for: a new identity or new keys need a new client. */
  get signature(): string {
    return `${this.pairing.phone?.id ?? ""}|${this.pairing.readToken}`;
  }

  start(): void {
    this.stopped = false;
    const ph = this.pairing.phone;
    this.identity = ph
      ? (async () => ({
          phone: ph.id,
          token: await readerToken(ph.macKey, this.pairing.room, ph.id),
          key: await phoneFrameKey(ph.macKey, this.pairing.room, ph.id),
        }))().catch(() => null)
      : Promise.resolve(null);
    window.addEventListener("online", this.wake);
    document.addEventListener("visibilitychange", this.wake);
    this.connect();
  }

  stop(): void {
    this.stopped = true;
    window.removeEventListener("online", this.wake);
    document.removeEventListener("visibilitychange", this.wake);
    this.clearTimers();
    this.ws?.close(1000);
    this.ws = null;
  }

  /** Sends a control frame (e.g. a push subscription) once the socket is authenticated. */
  send(data: unknown): boolean {
    if (this.ws?.readyState !== WebSocket.OPEN) return false;
    this.ws.send(JSON.stringify(data));
    return true;
  }

  /**
   * Miblo+: a frame to the computer, sealed under this phone's own key ({"t":"up","ch",iv,ct}; the
   * relay adds which phone sent it). False when the socket is not open or this phone has no
   * identity for this computer (not enrolled), and while the app is locked (PIN): nothing is sent
   * to a computer then, whatever the screen shows.
   */
  async sendUp(ch: "history" | "reply" | "approval", payload: unknown): Promise<boolean> {
    if (isAppLocked()) return false;
    return this.spaced(async () => {
      if (isAppLocked()) return null;
      const id = await this.identity;
      if (!id || this.guest) return null;
      return sealUp(id.key, this.pairing.room, id.phone, ch, payload);
    });
  }

  /** The enrollment frame, sealed under the QR code's pairing window key (this phone has no identity yet). */
  async sendEnroll(payload: unknown): Promise<boolean> {
    return this.spaced(async () => {
      const secret = this.pairing.enroll?.secret;
      if (!secret) return null;
      return sealEnroll(await enrollKey(secret, this.pairing.room), this.pairing.room, payload);
    });
  }

  // The relay takes at most one "up" frame per second from a phone and drops the rest: frames go
  // out one after the other, spaced a little over a second apart.
  private spaced(make: () => Promise<Frame | null>): Promise<boolean> {
    const turn = this.upChain.then(async () => {
      const wait = this.lastUpAt + UP_SPACING_MS - Date.now();
      if (wait > 0) await new Promise((r) => setTimeout(r, wait));
      const sent = await this.sendFrame(make);
      if (sent) this.lastUpAt = Date.now();
      return sent;
    });
    this.upChain = turn.then(() => undefined, () => undefined);
    return turn;
  }

  private upChain: Promise<void> = Promise.resolve();
  private lastUpAt = 0;

  private async sendFrame(make: () => Promise<Frame | null>): Promise<boolean> {
    if (this.ws?.readyState !== WebSocket.OPEN) return false;
    try {
      const frame = await make();
      if (!frame || this.ws?.readyState !== WebSocket.OPEN) return false;
      this.ws.send(JSON.stringify(frame));
      return true;
    } catch {
      return false;
    }
  }

  get isOpen(): boolean {
    return this.state === "open";
  }

  /** Back in the foreground or back online: reconnect now instead of waiting out the backoff. */
  private wake = () => {
    if (this.stopped || document.visibilityState !== "visible") return;
    if (this.state === "refused" || this.state === "deleted" || this.state === "revoked") return;
    if (!this.ws || this.ws.readyState > WebSocket.OPEN) {
      this.attempt = 0;
      this.connect();
    } else {
      this.ping();
    }
  };

  private setState(state: LinkState) {
    this.state = state;
    this.listener.onState(state);
  }

  private clearTimers() {
    clearTimeout(this.retryTimer);
    clearInterval(this.pingTimer);
    clearTimeout(this.pongTimer);
  }

  private connect() {
    this.clearTimers();
    if (this.stopped) return;
    if (!navigator.onLine) {
      this.setState("offline");
      return;
    }
    this.setState("connecting");
    const ws = new WebSocket(relayUrl(this.pairing.room));
    this.ws = ws;
    ws.onopen = () => {
      void this.identity.then((id) => {
        if (this.ws !== ws || ws.readyState !== WebSocket.OPEN) return;
        // This phone's own token when it has one; the pairing's shared one as a guest.
        ws.send(JSON.stringify(id && !this.guest ? { t: "auth", token: id.token, phone: id.phone } : { t: "auth", token: this.pairing.readToken }));
        this.attempt = 0;
        this.setState("open");
        this.pingTimer = setInterval(() => this.ping(), PING_MS);
      });
    };
    ws.onmessage = (event) => {
      clearTimeout(this.pongTimer);
      let data: { t?: string; iv?: string; ct?: string; ch?: string; k?: string; g?: number };
      try {
        data = JSON.parse(String(event.data));
      } catch {
        return;
      }
      if (data.t !== "msg" || typeof data.iv !== "string" || typeof data.ct !== "string") return;
      this.notReady = 0;
      const ch = data.ch ?? "status";
      if (!READ_CHANNELS.has(ch)) return;
      const { iv, ct } = data;
      const ignore = () => {
        // Not ours (wrong key, not for this phone, or tampered): ignore it.
      };
      if (typeof data.k === "string") {
        // Sealed to this phone.
        void this.identity
          .then((id) => (id ? openSealed(id.key, this.pairing.room, id.phone, { t: "msg", ch, iv, ct, k: data.k! }) : Promise.reject(new Error("no identity"))))
          .then((payload) => this.listener.onPayload(payload, ch, true), ignore);
      } else if (data.g === 1) {
        // The answer to this phone's enrollment, under the pairing window's key.
        const secret = this.pairing.enroll?.secret;
        if (!secret) return;
        void enrollKey(secret, this.pairing.room)
          .then((key) => openEnrolled(key, this.pairing.room, { iv, ct }))
          .then((payload) => this.listener.onPayload(payload, ch), ignore);
      } else if (ch === "status") {
        decryptFrame(this.pairing.key, this.pairing.room, { t: "msg", ch: data.ch, iv, ct }).then((payload) => this.listener.onPayload(payload, ch, false), ignore);
      }
    };
    ws.onclose = (event) => {
      if (this.ws !== ws) return;
      this.clearTimers();
      this.ws = null;
      if (this.stopped) return;
      if (event.code === 4411) return this.setState("revoked");
      if (event.code === 4401) {
        // This phone's own token refused (the computer has not registered it yet, or forgot it):
        // try as a guest once; refused as a guest too, the pairing no longer works.
        if (this.pairing.phone && !this.guest) {
          this.guest = true;
          this.setState("retrying");
          this.retryTimer = setTimeout(() => this.connect(), 1000 + Math.random() * 500);
          return;
        }
        return this.setState("refused");
      }
      if (event.code === 4404) return this.setState("deleted");
      if (event.code === 4402) this.listener.onPlanRefused?.();
      if (event.code === 4406) {
        // Another phone holds the free plan's single place: look again in a minute.
        this.setState("limit");
        this.attempt += 1;
        this.retryTimer = setTimeout(() => this.connect(), 60_000 + Math.random() * 5_000);
        return;
      }
      this.setState(navigator.onLine ? "retrying" : "offline");
      // 4409: another phone took the place; come back slowly so two phones don't ping-pong.
      // 4403: the computer has not connected to this room yet (just paired); try again soon.
      let base = event.code === 4409 ? 30_000 : Math.min(30_000, 1000 * 2 ** this.attempt);
      if (event.code === 4403) base = Math.min(60_000, 5_000 * 2 ** this.notReady++);
      this.attempt += 1;
      this.retryTimer = setTimeout(() => this.connect(), base + Math.random() * 500);
    };
  }

  private ping() {
    if (this.ws?.readyState !== WebSocket.OPEN) return;
    this.ws.send('{"t":"ping"}');
    clearTimeout(this.pongTimer);
    // No answer: the socket is dead without knowing it (phone slept, network changed).
    this.pongTimer = setTimeout(() => this.ws?.close(), PONG_TIMEOUT_MS);
  }
}
