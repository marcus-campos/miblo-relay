// 1.26 automatic tasks in the phone app this server serves: the "Automático (sem aprovações)"
// switch appears only while the computer's status frame says `tasksAuto` and Claude Code is the
// chosen AI; a task sent with it carries `auto: true` under its MAC and passkey challenge. The
// expected values are the plugin's shared vector (plugin test/fixtures/plus-v6-vector.json, autoTask).
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { b64url, fromB64url, importMacKey, phoneMac, taskChallenge, taskMacText } from "@/lib/relay-crypto";
import { parseTaskInfo, plusCaps, taskPayload, type TaskInfo } from "@/components/phone/plus";
import { TaskSheet } from "@/components/phone/TaskViews";
import { phoneStrings } from "@/components/phone/strings";

const ROOM = "dmVjdG9yLXJvb20tdmVjdG";
const MAC_KEY = "dYKNzOQshOTTN4Paqd0i-k8maH3x0ilQ3C7HDTA4SXk";
const FIELDS = { phone: "0nOB7OfzalgwAnT_qxU3LQ", tool: "claude", folder: "Zm9sZGVyaWQx", nonce: "bm9uY2Utbm9uY2Utbm9uY2U", ts: 1791300000123, tt: "dGFzay10b2tlbi10YXNrLX", text: "Rode os testes e corrija ✓" };
const TASK_TEXT = "miblo-task-v6|dmVjdG9yLXJvb20tdmVjdG|0nOB7OfzalgwAnT_qxU3LQ|claude|Zm9sZGVyaWQx|bm9uY2Utbm9uY2Utbm9uY2U|1791300000123|dGFzay10b2tlbi10YXNrLX|iy4cAbKmBZvw1WbvWW9JMl2DLug1g6d_-_yIimUpAsY";
const AUTO = { macText: `${TASK_TEXT}|auto`, mac: "p_HdEr8GIMfJYBP8H0mYCf0ZW3c4IVJiLRE54Hbomuk", challenge: "NPvfB6Kk6Uf3sNbP-sJfS53u2Q19EZdcJriJcxbagPM" };

const info = (tools: string[]): TaskInfo => ({
  at: 1,
  on: true,
  tools: tools.map((id) => ({ id, name: id === "claude" ? "Claude Code" : id, mode: "modo padrão" })),
  folders: [{ id: "Zm9sZGVyaWQx", name: "proj", path: "~/proj" }],
  tt: "dGFzay10b2tlbi10YXNrLX",
  maxMin: 30,
  tasks: [{ id: "tAbCdEf1", tool: "claude", folder: "proj", state: "done", started: 1, ended: 2, text: "refatorar", reason: null, auto: true }],
});
const sheet = (lang: "pt" | "en", allowAuto: boolean, tools = ["claude", "codex"]) =>
  renderToStaticMarkup(
    createElement(TaskSheet, { t: phoneStrings(lang), info: info(tools), online: true, canSign: true, allowAuto, onClose: () => {}, onSend: async () => "ok" as const, onOpenTask: () => {} }),
  );

describe("automatic tasks: the switch", () => {
  it("shows only while the computer allows it, for Claude Code; automatic tasks are labelled", () => {
    expect(sheet("pt", true)).toContain("Automático (sem aprovações)");
    expect(sheet("en", true)).toContain("Automatic (no approvals)");
    expect(sheet("pt", false)).not.toContain('data-testid="task-auto"');
    expect(sheet("pt", true, ["codex", "claude"])).not.toContain('data-testid="task-auto"');
    expect(sheet("pt", false)).toContain("automática");
  });

  it("reads tasksAuto from the status frame (only with tasks on) and auto from task_info", () => {
    expect(plusCaps({ plus: { on: true, tasks: true, tasksAuto: true } })!.tasksAuto).toBe(true);
    expect(plusCaps({ plus: { on: true, tasks: false, tasksAuto: true } })!.tasksAuto).toBe(false);
    expect(plusCaps({ plus: { on: true, tasks: true } })!.tasksAuto).toBe(false);
    expect(parseTaskInfo({ kind: "task_info", at: 1, on: true, tasks: [{ id: "tAbCdEf1", state: "running", started: 1, auto: true }] })!.tasks[0].auto).toBe(true);
  });
});

describe("automatic tasks: the request", () => {
  it("auto is appended to the MAC text and the challenge, as the computer checks them", async () => {
    const f = { ...FIELDS, auto: true };
    expect(await taskMacText(ROOM, f)).toBe(AUTO.macText);
    const mk = await importMacKey(fromB64url(MAC_KEY));
    expect(await phoneMac(mk, AUTO.macText)).toBe(AUTO.mac);
    expect(b64url(await taskChallenge(ROOM, f))).toBe(AUTO.challenge);
    expect(await taskMacText(ROOM, FIELDS)).toBe(TASK_TEXT);
  });

  it("taskPayload carries auto: true only when asked", async () => {
    const signer = { phone: FIELDS.phone, macKey: await importMacKey(fromB64url(MAC_KEY)) };
    const auto = await taskPayload(signer, ROOM, "claude", FIELDS.folder, FIELDS.tt, "refatore", 7, true);
    if ("error" in auto) throw new Error(auto.error);
    expect(auto.payload).toMatchObject({ v: 6, kind: "task", tool: "claude", auto: true });
    const plain = await taskPayload(signer, ROOM, "claude", FIELDS.folder, FIELDS.tt, "refatore", 7);
    if ("error" in plain) throw new Error(plain.error);
    expect("auto" in plain.payload).toBe(false);
  });
});
