// Miblo+ on the phone (docs/phone-relay-protocol.md v4): the decrypted history, approval and reply
// frames, parsed defensively, and the frames the phone sends back. Everything here is plain data:
// the UI renders it as React text only (never as HTML), so a message cannot inject markup.
//
// What an approval card shows is exactly what the computer would run: the input is checked against
// the hash the decision signs, and nothing in it is dropped or hidden. Line breaks show as ↵, tabs
// as ⇥ and every invisible or control character (bidi overrides, zero-width, ESC, CR) as a visible
// escape such as ⟨U+202E⟩, and so is every combining mark past the second on one character
// (stacked marks could paint over the rest of the card); when any of those is present the phone
// can only deny.
import {
  approveChallenge,
  decisionMacText,
  phoneMac,
  randomNonce,
  replyChallenge,
  replyMacText,
  sha256Text,
  stopMacText,
  taskChallenge,
  taskMacText,
  type DecisionFields,
} from "@/lib/relay-crypto";
import type { Assertion } from "@/lib/webauthn";

export type Role = "assistant" | "tool" | "user" | "phone";
/** v6: what a tool call's card shows (every string already cleaned; the computer redacted secrets). */
export type ToolKindV6 = "edit" | "write" | "read" | "run" | "search" | "web" | "agent" | "todo" | "other";
export type ToolInfo = {
  name: string;
  kind: ToolKindV6;
  path: string | null;
  cmd: string | null;
  add: number | null;
  del: number | null;
  n: number | null;
  out: string | null;
  err: boolean;
  diff: { sign: "+" | "-"; text: string }[];
};
export type HistoryMsg = { id: string; role: Role; text: string; at: number | null; md?: boolean; tool?: ToolInfo };
/** v6: a remote task's state ("Nova tarefa"). */
export type TaskState = "running" | "done" | "failed" | "stopped";
export type TaskView = { id: string; tool: string; folder: string; path: string | null; state: TaskState; started: number; ended: number | null; code: number | null; reason: string | null };
/**
 * 1.24: how a reply to this session would go in now (the history frame's `replyHow`): at once, when
 * the session finishes its turn, or the reason the computer would refuse it.
 */
export type ReplyHow = "now" | "turn_end" | "unknown_mode" | "permissive_session" | "old_session" | "idle_unsupported" | "unsupported" | "off";
const REPLY_HOWS = new Set<ReplyHow>(["now", "turn_end", "unknown_mode", "permissive_session", "old_session", "idle_unsupported", "unsupported", "off"]);
/** `rt`: the reply token the computer issued with this history (a reply must answer it). */
export type HistoryView = {
  session: string;
  title: string;
  harness: string;
  reply: boolean;
  /** 1.24: how a reply would go in (null: a computer before 1.24, which says only `reply`). */
  replyHow: ReplyHow | null;
  rt: string | null;
  at: number;
  msgs: HistoryMsg[];
  /** v6: the session's state when the computer said it ("working" shows a typing indicator). */
  state: "working" | "needs" | "idle" | "done" | null;
  task: TaskView | null;
};
export type ApprovalView = {
  id: string;
  session: string;
  tool: string;
  /** The exact input (canonical JSON) the computer will run, when `full`. */
  input: string;
  /** False when the input was too large to send whole: then the phone may only deny. */
  full: boolean;
  hash: string;
  /** The request's nonce: part of the passkey challenge of an allow. */
  nonce: string;
  /** The input shown hashes to `hash`: the phone shows exactly what it would approve. */
  verified: boolean;
  at: number;
  expires: number;
};
export type ApprovalDone = { id: string; outcome: "allow" | "deny" | "timeout" | "answered" };
/** `queued` (1.24): waiting for the session to finish its turn (`how`: "turn_end"). */
export type ReplyAck = { nonce: string; state: "queued" | "sent" | "delivered" | "refused"; reason: string; how: "now" | "turn_end" | null };
/** The Miblo+ capabilities a status frame announces; `phones`: the ids of the enrolled phones. */
/**
 * `history`: the computer sends conversations to the phone. False when it is off there or waiting to
 * be confirmed again (`rearm`: the computer reads it as off until then); a computer that does not
 * say reads as on.
 */
export type PlusCaps = { on: boolean; approvals: boolean; replies: boolean; tasks: boolean; history: boolean; phones: string[] };
export type EnrollResult = { phone: string; ok: boolean; fp: string | null; reason: string };

export const HISTORY_MAX = 50;
export const MSG_MAX = 4000;
/** UTF-8 bytes of a reply: the computer refuses longer ones. */
export const REPLY_MAX_BYTES = 4000;
/** An approval card is never shown longer than this, whatever the frame says. */
/** The longest an approval may wait: the computer's setting tops at 1 h (plugin TIMEOUT_MAX_S). */
export const APPROVAL_MAX_MS = 60 * 60 * 1000;
/** A command longer than this gets the "long command" warning. */
export const LONG_COMMAND = 300;
const MAX_FUTURE_MS = 60_000;
const ID_RE = /^[A-Za-z0-9_:.-]{1,64}$/;
const REQ_RE = /^[A-Za-z0-9_-]{22}$/;
const HASH_RE = /^[A-Za-z0-9_-]{43}$/;
const NONCE_RE = /^[A-Za-z0-9_-]{16,43}$/;
/** Tool names (Bash, Edit, mcp__server__tool): signed as is, so they must need no cleaning. */
const TOOL_RE = /^[A-Za-z0-9_.:-]{1,128}$/;

// C0/C1 controls (except the line feed), DEL, bidi marks, overrides and isolates, zero-width and
// invisible formatting characters: none of them may change how a message reads. History and
// titles drop them (nothing is signed there); approvals show them (below).
const HIDDEN = /[\u0000-\u0009\u000B-\u001F\u007F-\u009F­؜᠎​-‏‪-‮⁠-⁩﻿]/g;

/** Text safe to show in history: hidden characters out, CRLF folded, length capped (by code points). */
export function cleanDisplay(value: unknown, max = MSG_MAX): string {
  if (typeof value !== "string") return "";
  const s = value.replace(/\r\n?/g, "\n").replace(HIDDEN, "");
  const chars = Array.from(s);
  return chars.length > max ? chars.slice(0, max).join("") + "…" : s;
}

// --- approvals: the input, every character visible -----------------------------------------------

/** A piece of shown text: plain, or an escape the UI styles apart (↵, ⇥, ⟨U+202E⟩). */
export type Seg = { t: string; esc?: true };
export type Visible = { segs: Seg[]; lines: number; chars: number; hidden: boolean; nonAscii: boolean };

const FORMAT = /\p{Cf}/u;
const MARK = /\p{M}/u;
/** Combining marks one character may carry and still show as is (enough for any real script). */
export const MAX_MARKS = 2;
const hex = (cp: number) => cp.toString(16).toUpperCase().padStart(4, "0");

/** `s` with every line break, tab and invisible or control character made visible. */
export function visible(s: string): Visible {
  const segs: Seg[] = [];
  let plain = "";
  let hidden = false;
  let nonAscii = false;
  let lines = 1;
  let chars = 0;
  let marks = 0;
  const flush = () => {
    if (plain) segs.push({ t: plain });
    plain = "";
  };
  const esc = (t: string) => {
    flush();
    segs.push({ t, esc: true });
  };
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    chars += 1;
    if (MARK.test(ch)) {
      marks += 1;
      if (cp > 0x7e) nonAscii = true;
      if (marks > MAX_MARKS) {
        // Stacked marks: shown as escapes, and the card becomes deny-only.
        hidden = true;
        esc(`⟨U+${hex(cp)}⟩`);
      } else {
        plain += ch;
      }
      continue;
    }
    marks = 0;
    if (ch === "\n") {
      esc("↵");
      plain += "\n";
      lines += 1;
    } else if (ch === "\t") {
      esc("⇥");
      plain += " ";
    } else if (cp < 0x20 || (cp >= 0x7f && cp <= 0x9f)) {
      hidden = true;
      esc(cp === 0x1b ? "⟨ESC⟩" : cp === 0x0d ? "⟨CR⟩" : `⟨U+${hex(cp)}⟩`);
    } else if (FORMAT.test(ch) || cp === 0x180e || cp === 0x115f || cp === 0x1160 || cp === 0x3164 || cp === 0xffa0) {
      // Bidi controls, zero-width characters, soft hyphen and other invisible format characters.
      hidden = true;
      esc(`⟨U+${hex(cp)}⟩`);
    } else {
      if (cp > 0x7e) nonAscii = true;
      plain += ch;
    }
  }
  flush();
  return { segs, lines, chars, hidden, nonAscii };
}

export type DiffLine = { sign: "-" | "+"; text: Visible };
export type InputView = {
  /** The command (Bash and the like), shown first and in full. */
  command: Visible | null;
  /** The file a tool edits or writes, shown prominently. */
  path: Visible | null;
  /** A file edit as a full diff: every removed line, then every added line. */
  diff: { title: string | null; lines: DiffLine[] }[];
  /** What the AI wrote about the call (Bash's description): shown apart, as secondary. */
  description: Visible | null;
  /** Every other field. */
  fields: { key: string; value: Visible }[];
  /** Anything invisible or a control character anywhere: the phone may only deny. */
  hidden: boolean;
  /** A non-ASCII character anywhere: command, path, description, diff or any field (look-alike letters). */
  nonAscii: boolean;
  multiline: boolean;
  long: boolean;
  lines: number;
  chars: number;
};

const FILE_TOOLS = new Set(["Edit", "MultiEdit", "Write", "NotebookEdit"]);
const asText = (v: unknown): string => (typeof v === "string" ? v : JSON.stringify(v, null, 2) ?? "null");
const diffLines = (sign: "-" | "+", text: string): DiffLine[] => text.split("\n").map((l) => ({ sign, text: visible(l) }));

/** The input as the card shows it: what runs first, every character visible, file edits as a diff. */
export function inputView(tool: string, input: string): InputView {
  let o: Record<string, unknown> | null = null;
  try {
    o = obj(JSON.parse(input));
  } catch {
    o = null;
  }
  const view: InputView = { command: null, path: null, diff: [], description: null, fields: [], hidden: false, nonAscii: false, multiline: false, long: false, lines: 0, chars: 0 };
  const all: Visible[] = [];
  const see = (s: string) => {
    const v = visible(s);
    all.push(v);
    return v;
  };
  if (!o) {
    view.fields.push({ key: "input", value: see(input) });
  } else {
    const rest = { ...o };
    if (typeof rest.command === "string") {
      view.command = see(rest.command);
      delete rest.command;
    }
    const pathKey = typeof rest.file_path === "string" ? "file_path" : typeof rest.notebook_path === "string" ? "notebook_path" : null;
    if (FILE_TOOLS.has(tool) && pathKey) {
      view.path = see(rest[pathKey] as string);
      delete rest[pathKey];
    }
    if (FILE_TOOLS.has(tool)) {
      const edit = (title: string | null, e: Record<string, unknown>) => {
        const lines: DiffLine[] = [];
        if (typeof e.old_string === "string") lines.push(...diffLines("-", e.old_string));
        if (typeof e.new_string === "string") lines.push(...diffLines("+", e.new_string));
        if (lines.length) view.diff.push({ title, lines });
      };
      if (typeof rest.old_string === "string" || typeof rest.new_string === "string") {
        edit(null, rest);
        delete rest.old_string;
        delete rest.new_string;
      }
      if (Array.isArray(rest.edits)) {
        rest.edits.forEach((e, i) => {
          const eo = obj(e);
          if (eo) edit(`#${i + 1}`, eo);
        });
        delete rest.edits;
      }
      for (const k of ["content", "new_source"]) {
        if (typeof rest[k] === "string") {
          view.diff.push({ title: null, lines: diffLines("+", rest[k] as string) });
          delete rest[k];
        }
      }
      for (const d of view.diff) for (const l of d.lines) all.push(l.text);
    }
    if (tool === "Bash" && typeof rest.description === "string") {
      view.description = see(rest.description);
      delete rest.description;
    }
    for (const key of Object.keys(rest)) {
      const k = visible(key);
      all.push(k);
      view.fields.push({ key: k.segs.map((s) => s.t).join(""), value: see(asText(rest[key])) });
    }
  }
  view.hidden = all.some((v) => v.hidden);
  view.nonAscii = all.some((v) => v.nonAscii);
  const main = view.command ?? null;
  view.lines = main ? main.lines : all.reduce((n, v) => n + v.lines, 0);
  view.chars = main ? main.chars : all.reduce((n, v) => n + v.chars, 0);
  view.multiline = view.lines > 1;
  view.long = view.chars > LONG_COMMAND;
  return view;
}

// --- frames ------------------------------------------------------------------------------------

const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const obj = (v: unknown): Record<string, unknown> | null => (v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null);
const ROLES = new Set<Role>(["assistant", "tool", "user", "phone"]);
const PHONE_RE = /^[A-Za-z0-9_-]{22}$/;

/** The Miblo+ capabilities a status frame announces (absent: free plan, or an older plugin). */
export function plusCaps(payload: unknown): PlusCaps | null {
  const p = obj(payload);
  const plus = obj(p?.plus);
  if (!plus || plus.on !== true) return null;
  const phones = Array.isArray(plus.phones) ? plus.phones.filter((x): x is string => typeof x === "string" && PHONE_RE.test(x)).slice(0, 16) : [];
  return { on: true, approvals: plus.approvals === true, replies: plus.replies === true, tasks: plus.tasks === true, history: plus.history !== false, phones };
}

export function parseHistory(payload: unknown): HistoryView | null {
  const p = obj(payload);
  if (!p || p.kind !== "history" || typeof p.session !== "string" || !ID_RE.test(p.session)) return null;
  const at = num(p.at);
  if (at === null) return null;
  const msgs = (Array.isArray(p.msgs) ? p.msgs : [])
    .slice(-HISTORY_MAX)
    .map((m, i): HistoryMsg | null => {
      const o = obj(m);
      if (!o || !ROLES.has(o.role as Role)) return null;
      const text = cleanDisplay(o.text);
      if (!text.trim()) return null;
      const tool = o.role === "tool" ? parseTool(o.tool) : null;
      return {
        id: typeof o.id === "string" ? o.id.slice(0, 64) : String(i),
        role: o.role as Role,
        text,
        at: num(o.at),
        ...(o.md === 1 && o.role === "assistant" ? { md: true } : {}),
        ...(tool ? { tool } : {}),
      };
    })
    .filter((m): m is HistoryMsg => m !== null);
  const state = p.state === "working" || p.state === "needs" || p.state === "idle" || p.state === "done" ? p.state : null;
  return {
    session: p.session,
    title: cleanDisplay(p.title, 80),
    harness: typeof p.harness === "string" && ID_RE.test(p.harness) ? p.harness : "claude",
    reply: p.reply === true,
    replyHow: typeof p.replyHow === "string" && REPLY_HOWS.has(p.replyHow as ReplyHow) ? (p.replyHow as ReplyHow) : null,
    rt: typeof p.rt === "string" && /^[A-Za-z0-9_-]{22}$/.test(p.rt) ? p.rt : null,
    at,
    msgs,
    state,
    task: parseTask(p.task),
  };
}

const KINDS = new Set<ToolKindV6>(["edit", "write", "read", "run", "search", "web", "agent", "todo", "other"]);
const count = (v: unknown): number | null => (typeof v === "number" && Number.isSafeInteger(v) && v >= 0 && v < 1e7 ? v : null);
const textOrNull = (v: unknown, max: number): string | null => {
  const t = cleanDisplay(v, max);
  return t.trim() ? t : null;
};

/** v6: a tool card's details, every field checked and capped (absent: an older computer). */
export function parseTool(v: unknown): ToolInfo | null {
  const o = obj(v);
  if (!o) return null;
  const name = textOrNull(o.name, 64);
  if (!name) return null;
  const diff = (Array.isArray(o.diff) ? o.diff : [])
    .slice(0, 40)
    .map((d) => (Array.isArray(d) && (d[0] === "+" || d[0] === "-") ? { sign: d[0] as "+" | "-", text: cleanDisplay(d[1], 200) } : null))
    .filter((d): d is { sign: "+" | "-"; text: string } => d !== null);
  return {
    name: name.replace(/\n/g, " "),
    kind: KINDS.has(o.kind as ToolKindV6) ? (o.kind as ToolKindV6) : "other",
    path: textOrNull(o.path, 240),
    cmd: textOrNull(o.cmd, 500),
    add: count(o.add),
    del: count(o.del),
    n: count(o.n),
    out: textOrNull(o.out, 1500),
    err: o.err === true,
    diff,
  };
}

const TASK_ID_RE = /^t[A-Za-z0-9]{7}$/;
const TASK_STATES = new Set<TaskState>(["running", "done", "failed", "stopped"]);

export function parseTask(v: unknown): TaskView | null {
  const o = obj(v);
  if (!o || typeof o.id !== "string" || !TASK_ID_RE.test(o.id) || !TASK_STATES.has(o.state as TaskState)) return null;
  const started = num(o.started);
  if (started === null) return null;
  return {
    id: o.id,
    tool: typeof o.tool === "string" && ID_RE.test(o.tool) ? o.tool : "?",
    folder: cleanDisplay(o.folder, 80),
    path: textOrNull(o.path, 240),
    state: o.state as TaskState,
    started,
    ended: num(o.ended),
    code: typeof o.code === "number" && Number.isSafeInteger(o.code) ? o.code : null,
    reason: typeof o.reason === "string" ? o.reason.slice(0, 40) : null,
  };
}

// --- v6 remote tasks ("Nova tarefa") ---------------------------------------------------------------

export type TaskTool = { id: string; name: string; mode: string };
export type TaskFolder = { id: string; name: string; path: string };
export type TaskListItem = { id: string; tool: string; folder: string; state: TaskState; started: number; ended: number | null; text: string; reason: string | null };
export type TaskInfo = { at: number; on: boolean; tools: TaskTool[]; folders: TaskFolder[]; tt: string | null; maxMin: number; tasks: TaskListItem[] };
export type TaskAck = { nonce: string; state: "started" | "refused"; reason: string; task: string | null };

export function parseTaskInfo(payload: unknown): TaskInfo | null {
  const p = obj(payload);
  if (!p || p.kind !== "task_info") return null;
  const at = num(p.at);
  if (at === null) return null;
  const tools = (Array.isArray(p.tools) ? p.tools : []).slice(0, 8).map((t) => {
    const o = obj(t);
    return o && typeof o.id === "string" && ID_RE.test(o.id) ? { id: o.id, name: cleanDisplay(o.name, 40) || o.id, mode: cleanDisplay(o.mode, 160) } : null;
  }).filter((t): t is TaskTool => t !== null);
  const folders = (Array.isArray(p.folders) ? p.folders : []).slice(0, 12).map((f) => {
    const o = obj(f);
    return o && typeof o.id === "string" && /^[A-Za-z0-9_-]{12}$/.test(o.id) ? { id: o.id, name: cleanDisplay(o.name, 80) || o.id, path: cleanDisplay(o.path, 240) } : null;
  }).filter((f): f is TaskFolder => f !== null);
  const tasks = (Array.isArray(p.tasks) ? p.tasks : []).slice(0, 10).map((t) => {
    const o = obj(t);
    if (!o || typeof o.id !== "string" || !TASK_ID_RE.test(o.id) || !TASK_STATES.has(o.state as TaskState)) return null;
    return {
      id: o.id,
      tool: typeof o.tool === "string" && ID_RE.test(o.tool) ? o.tool : "?",
      folder: cleanDisplay(o.folder, 80),
      state: o.state as TaskState,
      started: num(o.started) ?? 0,
      ended: num(o.ended),
      text: cleanDisplay(o.text, 80),
      reason: typeof o.reason === "string" ? o.reason.slice(0, 40) : null,
    };
  }).filter((t): t is TaskListItem => t !== null);
  const maxMin = typeof p.maxMin === "number" && Number.isSafeInteger(p.maxMin) && p.maxMin > 0 && p.maxMin <= 240 ? p.maxMin : 30;
  return { at, on: p.on === true, tools, folders, tt: typeof p.tt === "string" && /^[A-Za-z0-9_-]{22}$/.test(p.tt) ? p.tt : null, maxMin, tasks };
}

export function parseTaskAck(payload: unknown): TaskAck | null {
  const p = obj(payload);
  if (!p || p.kind !== "task_ack" || typeof p.nonce !== "string" || !NONCE_RE.test(p.nonce)) return null;
  if (p.state !== "started" && p.state !== "refused") return null;
  return { nonce: p.nonce, state: p.state, reason: typeof p.reason === "string" ? p.reason.slice(0, 40) : "", task: typeof p.task === "string" && TASK_ID_RE.test(p.task) ? p.task : null };
}

/** Asks the computer what a task may run (tools, folders) and for a fresh task token. */
export function taskInfoPayload(phone: string, now: number, lang: "pt" | "en"): Record<string, unknown> {
  return { v: 6, kind: "task_info", phone, at: now, nonce: randomNonce(), lang };
}

/**
 * A task, signed by this phone (MAC), and the challenge its passkey must sign over the tool, the
 * folder and this very text (the caller adds the assertion as `wa`).
 */
export async function taskPayload(
  signer: Signer,
  room: string,
  tool: string,
  folder: string,
  tt: string | null,
  text: string,
  now: number,
): Promise<{ payload: Record<string, unknown>; nonce: string; challenge: Uint8Array<ArrayBuffer> } | { error: "empty" | "too_long" | "no_token" }> {
  const clean = text.replace(/\r\n?/g, "\n").replace(HIDDEN, "").trim();
  if (!clean) return { error: "empty" };
  if (utf8Length(clean) > REPLY_MAX_BYTES) return { error: "too_long" };
  if (!tt) return { error: "no_token" };
  const nonce = randomNonce();
  const f = { phone: signer.phone, tool, folder, nonce, ts: now, tt, text: clean };
  return { payload: { v: 6, kind: "task", ...f, mac: await phoneMac(signer.macKey, await taskMacText(room, f)) }, nonce, challenge: await taskChallenge(room, f) };
}

/** "Parar": signed by this phone (no passkey: stopping only narrows). */
export async function stopPayload(signer: Signer, room: string, task: string, now: number): Promise<Record<string, unknown>> {
  const f = { phone: signer.phone, task, nonce: randomNonce(), ts: now };
  return { v: 6, kind: "task_stop", ...f, mac: await phoneMac(signer.macKey, stopMacText(room, f)) };
}

/** A pending approval, checked: the input shown must hash to the hash the decision will carry. */
export async function parseApproval(payload: unknown, now: number): Promise<ApprovalView | null> {
  const p = obj(payload);
  if (!p || p.kind !== "approval") return null;
  const { id, session, tool, input, hash, nonce } = p;
  const at = num(p.at);
  const expires = num(p.expires);
  if (typeof id !== "string" || !REQ_RE.test(id) || typeof session !== "string" || !ID_RE.test(session)) return null;
  if (typeof tool !== "string" || !TOOL_RE.test(tool) || typeof hash !== "string" || !HASH_RE.test(hash)) return null;
  if (typeof nonce !== "string" || !NONCE_RE.test(nonce)) return null;
  if (typeof input !== "string" || at === null || expires === null) return null;
  if (at > now + MAX_FUTURE_MS || expires <= now) return null;
  const full = p.full === true;
  // The hash is recomputed over the string received: an allow can only cover what is displayed.
  const verified = full && (await sha256Text(input)) === hash;
  return { id, session, tool, input, full, hash, nonce, verified, at, expires: Math.min(expires, at + APPROVAL_MAX_MS, now + APPROVAL_MAX_MS) };
}

/** Whether the phone may approve this card at all (the passkey and the user's reading come on top). */
export function allowable(a: ApprovalView, view: InputView | null, now: number): boolean {
  return a.verified && now < a.expires && !!view && !view.hidden;
}

export function parseApprovalDone(payload: unknown): ApprovalDone | null {
  const p = obj(payload);
  if (!p || p.kind !== "approval_done" || typeof p.id !== "string" || !REQ_RE.test(p.id)) return null;
  const outcome = p.outcome;
  if (outcome !== "allow" && outcome !== "deny" && outcome !== "timeout" && outcome !== "answered") return null;
  return { id: p.id, outcome };
}

/** The computer's answer to this phone's enrollment. */
export function parseEnrolled(payload: unknown): EnrollResult | null {
  const p = obj(payload);
  if (!p || p.kind !== "enrolled" || typeof p.phone !== "string" || !PHONE_RE.test(p.phone)) return null;
  const fp = typeof p.fp === "string" && /^[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(p.fp) ? p.fp : null;
  return { phone: p.phone, ok: p.ok === true, fp, reason: typeof p.reason === "string" ? p.reason.slice(0, 40) : "" };
}

export function parseReplyAck(payload: unknown): ReplyAck | null {
  const p = obj(payload);
  if (!p || p.kind !== "reply_ack" || typeof p.nonce !== "string" || !NONCE_RE.test(p.nonce)) return null;
  const state = p.state;
  if (state !== "queued" && state !== "sent" && state !== "delivered" && state !== "refused") return null;
  const how = p.how === "now" || p.how === "turn_end" ? p.how : null;
  return { nonce: p.nonce, state, reason: typeof p.reason === "string" ? p.reason.slice(0, 40) : "", how };
}

const utf8Length = (s: string) => new TextEncoder().encode(s).length;

/** This phone's signing identity for one computer. */
export type Signer = { phone: string; macKey: CryptoKey };

/**
 * The reply frame's payload, signed by this phone (MAC), and the challenge its passkey must sign
 * (the caller adds that assertion as `wa`: nothing reaches the computer without the person's
 * biometric or PIN over this very text), or why it cannot go. `rt`: the reply token from the
 * session's latest history frame.
 */
export async function replyPayload(
  signer: Signer,
  room: string,
  session: string,
  rt: string | null,
  text: string,
  now: number,
): Promise<{ payload: Record<string, unknown>; nonce: string; challenge: Uint8Array<ArrayBuffer> } | { error: "empty" | "too_long" | "no_token" }> {
  const clean = text.replace(/\r\n?/g, "\n").replace(HIDDEN, "").trim();
  if (!clean) return { error: "empty" };
  if (utf8Length(clean) > REPLY_MAX_BYTES) return { error: "too_long" };
  if (!rt) return { error: "no_token" };
  const nonce = randomNonce();
  const f = { phone: signer.phone, session, nonce, ts: now, rt, text: clean };
  return {
    payload: { v: 5, kind: "reply", ...f, mac: await phoneMac(signer.macKey, await replyMacText(room, f)) },
    nonce,
    challenge: await replyChallenge(room, f),
  };
}

/** Asks the computer for one session's last messages (sent when its conversation is opened, and again while it stays open). */
export function openPayload(session: string, now: number): Record<string, unknown> {
  return { v: 4, kind: "open", session, at: now, nonce: randomNonce() };
}

/** The challenge this phone's passkey signs for an allow of `a` on `room`. */
export function allowChallenge(a: ApprovalView, room: string): Promise<Uint8Array<ArrayBuffer>> {
  return approveChallenge({ id: a.id, tool: a.tool, hash: a.hash, room, nonce: a.nonce });
}

/**
 * The signed decision for one approval. An allow needs the input verified, the card not expired and
 * the passkey assertion over allowChallenge(); a deny is always possible.
 */
export async function decisionPayload(
  signer: Signer,
  room: string,
  a: ApprovalView,
  decision: "allow" | "deny",
  now: number,
  wa?: Assertion,
): Promise<Record<string, unknown> | null> {
  if (decision === "allow" && (!a.verified || now >= a.expires || !wa)) return null;
  const fields: DecisionFields = { phone: signer.phone, id: a.id, session: a.session, tool: a.tool, hash: a.hash, decision, nonce: randomNonce(), ts: now };
  return { v: 4, kind: "decision", ...fields, mac: await phoneMac(signer.macKey, decisionMacText(room, fields)), ...(decision === "allow" ? { wa } : {}) };
}

/** Newest-wins guard for history frames, per session: a replayed or reordered frame is ignored. */
export function newerHistory(current: HistoryView | undefined, next: HistoryView, now: number): boolean {
  if (next.at > now + MAX_FUTURE_MS) return false;
  return !current || next.at > current.at;
}

/**
 * New status keys from the computer (a phone was revoked there), or null: only from a frame sealed
 * to this phone alone (never the shared-key status, which a revoked phone still reads), well formed,
 * fresh, and of a newer generation than `held`.
 */
export function parseRekey(payload: unknown, sealed: boolean, held: number, now: number): { readToken: string; key: string; epoch: number } | null {
  const p = obj(payload);
  if (!p || p.kind !== "rekey" || !sealed) return null;
  const at = num(p.at);
  if (at === null || Math.abs(now - at) > 10 * 60 * 1000) return null;
  const { readToken, key, epoch } = p;
  if (typeof readToken !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(readToken) || typeof key !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(key)) return null;
  if (typeof epoch !== "number" || !Number.isSafeInteger(epoch) || epoch <= held) return null;
  return { readToken, key, epoch };
}

// --- v7: confirmations on the phone (a change asked on the computer, with the code it shows) ------

/** What the computer asks to turn on (plain data, rendered by the phone in its own words). */
export type ConfirmWhat =
  | { kind: "settings"; on: string[]; timeoutS: number | null; taskMaxMin: number | null; folders: string[] }
  | { kind: "admit"; phone: { id: string; name: string; model: string | null; place: string | null } };
export type ConfirmView = { id: string; nonce: string; what: ConfirmWhat; cap: string; at: number; expires: number; left: number };
export type ConfirmDone = { id: string; outcome: string };
export type ConfirmResult = { id: string; reason: string; left: number };

const ON_IDS = new Set(["approvals", "replies", "history", "permissive", "tasks"]);

/** A canonical JSON (keys sorted), as the computer hashes `what` into `cap`. */
function canonical(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v ?? null);
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o).filter((k) => o[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`).join(",")}}`;
}

/**
 * A confirmation request, checked: `cap` must be the hash of exactly the `what` shown (the phone
 * signs `cap`, so it can only confirm what it displays), every field plain and bounded.
 */
export async function parseConfirm(payload: unknown, now: number): Promise<ConfirmView | null> {
  const p = obj(payload);
  if (!p || p.kind !== "confirm" || typeof p.id !== "string" || !REQ_RE.test(p.id) || typeof p.nonce !== "string" || !REQ_RE.test(p.nonce)) return null;
  if (typeof p.cap !== "string" || !HASH_RE.test(p.cap)) return null;
  const at = num(p.at);
  const expires = num(p.expires);
  if (at === null || expires === null || at > now + MAX_FUTURE_MS || expires <= now) return null;
  const w = obj(p.what);
  let what: ConfirmWhat | null = null;
  if (w?.kind === "settings" && Array.isArray(w.on) && Array.isArray(w.folders)) {
    const on = w.on.filter((x): x is string => typeof x === "string" && ON_IDS.has(x));
    // A folder is shown exactly as the computer sent it (the hash covers those bytes), so one with
    // hidden or direction-changing characters is refused rather than shown as something else.
    const folders = w.folders.filter((x): x is string => typeof x === "string" && x.length <= 1024 && cleanDisplay(x, 1024) === x);
    if (on.length !== w.on.length || folders.length !== w.folders.length || folders.length > 12) return null;
    const int = (v: unknown) => (v === null ? null : typeof v === "number" && Number.isSafeInteger(v) && v > 0 && v < 10_000 ? v : undefined);
    const timeoutS = int(w.timeoutS);
    const taskMaxMin = int(w.taskMaxMin);
    if (timeoutS === undefined || taskMaxMin === undefined) return null;
    what = { kind: "settings", on, timeoutS, taskMaxMin, folders: w.folders as string[] };
  } else if (w?.kind === "admit") {
    const ph = obj(w.phone);
    // Shown as sent (the hash covers it): plain and short, or refused.
    const plain = (v: string) => v.length <= 120 && cleanDisplay(v, 120) === v;
    if (!ph || typeof ph.id !== "string" || !PHONE_RE.test(ph.id) || typeof ph.name !== "string" || !plain(ph.name)) return null;
    const opt = (v: unknown) => (v === null ? null : typeof v === "string" && plain(v) ? v : undefined);
    const model = opt(ph.model);
    const place = opt(ph.place);
    if (model === undefined || place === undefined) return null;
    what = { kind: "admit", phone: { id: ph.id, name: ph.name, model, place } };
  }
  if (!what) return null;
  // The hash is recomputed over what is shown: the phone signs this very request.
  if ((await sha256Text(canonical(what))) !== p.cap) return null;
  const left = typeof p.left === "number" && Number.isSafeInteger(p.left) ? Math.max(0, Math.min(3, p.left)) : 3;
  return { id: p.id, nonce: p.nonce, what, cap: p.cap, at, expires: Math.min(expires, now + APPROVAL_MAX_MS), left };
}

export function parseConfirmDone(payload: unknown): ConfirmDone | null {
  const p = obj(payload);
  if (!p || p.kind !== "confirm_done" || typeof p.id !== "string" || !REQ_RE.test(p.id) || typeof p.outcome !== "string") return null;
  return { id: p.id, outcome: p.outcome.slice(0, 20) };
}

export function parseConfirmResult(payload: unknown): ConfirmResult | null {
  const p = obj(payload);
  if (!p || p.kind !== "confirm_result" || typeof p.id !== "string" || !REQ_RE.test(p.id)) return null;
  return { id: p.id, reason: typeof p.reason === "string" ? p.reason.slice(0, 20) : "", left: typeof p.left === "number" ? Math.max(0, Math.min(3, p.left)) : 0 };
}

const enc7 = new TextEncoder();
async function hmacB64(macKey: CryptoKey, text: string): Promise<string> {
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", macKey, enc7.encode(text)));
  return btoa(String.fromCharCode(...sig)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The challenge this phone's passkey signs to confirm `c` with the code proof (plugin confirm.js). */
export async function confirmChallenge(room: string, phone: string, c: ConfirmView, proof: string): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", enc7.encode(["miblo-confirm-wa-v7", room, phone, c.id, c.cap, c.nonce, proof].join("|"))));
}

/**
 * The answer to a confirmation: "confirm" with the code the person typed (only its proof travels,
 * an HMAC under this phone's MAC key; the caller adds the passkey assertion over confirmChallenge
 * as `wa`), or "deny" (MAC only).
 */
export async function confirmPayload(signer: Signer, room: string, c: ConfirmView, verdict: "confirm" | "deny", code: string, now: number, nonce = randomNonce()): Promise<{ payload: Record<string, unknown>; proof: string }> {
  const proof = verdict === "confirm" ? await hmacB64(signer.macKey, ["miblo-confirm-code-v7", room, signer.phone, c.id, c.nonce, code].join("|")) : "";
  const fields = { phone: signer.phone, id: c.id, cap: c.cap, nonce, ts: now };
  const mac = await hmacB64(signer.macKey, ["miblo-confirm-v7", room, signer.phone, c.id, c.cap, verdict, nonce, String(now), proof].join("|"));
  return { payload: { v: 7, kind: verdict === "confirm" ? "confirm_answer" : "confirm_deny", ...fields, ...(verdict === "confirm" ? { proof } : {}), mac }, proof };
}
