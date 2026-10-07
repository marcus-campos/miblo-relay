// What the chat view shows, decided apart from React (tested in Node): the messages as bubbles,
// runs of tool calls as compact cards (a run of reads becomes "Leu 3 arquivos"), and a time line
// between messages far apart. Nothing here touches the relay or its crypto.
import type { HistoryMsg, ToolInfo } from "./plus";
import type { PhoneStrings } from "./strings";

export type ToolCardView = {
  key: string;
  /** One line: "Editou src/x.ts", "Rodou: npm test", "Leu 3 arquivos". */
  line: string;
  kind: ToolInfo["kind"];
  add: number | null;
  del: number | null;
  err: boolean;
  /** What opening the card shows: the files of a merged run, the command, the diff, the output. */
  paths: string[];
  cmd: string | null;
  diff: ToolInfo["diff"];
  out: string | null;
};

export type ChatItem =
  | { k: "sep"; key: string; label: string }
  | { k: "msg"; key: string; m: HistoryMsg; mine: boolean }
  | { k: "tools"; key: string; cards: ToolCardView[] };

/** Messages this far apart get a time line between them. */
export const GAP_MS = 15 * 60 * 1000;
const short = (s: string, n: number) => (Array.from(s).length > n ? Array.from(s).slice(0, n - 1).join("") + "…" : s);
const lastPart = (p: string) => p.split(/[\\/]/).filter(Boolean).slice(-2).join("/") || p;

/** A tool card from one message (v6 details when the computer sent them, else its one-line text). */
export function toolCard(m: HistoryMsg, t: PhoneStrings): ToolCardView {
  const tool = m.tool;
  const base = { key: m.id, add: tool?.add ?? null, del: tool?.del ?? null, err: !!tool?.err, paths: tool?.path ? [tool.path] : [], cmd: tool?.cmd ?? null, diff: tool?.diff ?? [], out: tool?.out ?? null };
  if (!tool) return { ...base, kind: "other", line: short(m.text, 120) };
  const where = tool.path ? lastPart(tool.path) : "";
  const c = t.chat;
  let line: string;
  switch (tool.kind) {
    case "edit":
      line = c.edited(where || tool.name);
      break;
    case "write":
      line = c.wrote(where || tool.name);
      break;
    case "run":
      line = c.ran(short((tool.cmd ?? "").split("\n")[0], 80));
      break;
    case "read":
      line = c.read(where || tool.name);
      break;
    case "search":
      line = c.searched(short(tool.cmd ?? where ?? "", 60));
      break;
    case "web":
      line = c.web(short(tool.cmd ?? "", 60));
      break;
    case "agent":
      line = c.agent(short(tool.cmd ?? "", 60));
      break;
    case "todo":
      line = c.todo;
      break;
    default:
      line = c.used(tool.name);
  }
  return { ...base, kind: tool.kind, line };
}

/** A run of tool calls as cards: consecutive reads (or searches) become one card. */
export function toolCards(msgs: HistoryMsg[], t: PhoneStrings): ToolCardView[] {
  const out: ToolCardView[] = [];
  for (const m of msgs) {
    const card = toolCard(m, t);
    const prev = out[out.length - 1];
    if (prev && (card.kind === "read" || card.kind === "search") && prev.kind === card.kind && !card.err && !prev.err) {
      const paths = [...prev.paths, ...(card.kind === "read" ? card.paths : card.cmd ? [card.cmd] : [])];
      const n = paths.length;
      out[out.length - 1] = { ...prev, paths, line: card.kind === "read" ? t.chat.readN(n) : t.chat.searchedN(n), cmd: null };
      continue;
    }
    if (card.kind === "search" && card.cmd) card.paths = [card.cmd];
    out.push(card);
  }
  return out;
}

function dayLabel(at: number, now: number, lang: "pt" | "en", t: PhoneStrings): string {
  const d = new Date(at);
  const today = new Date(now);
  const time = d.toLocaleTimeString(lang === "pt" ? "pt-BR" : "en", { hour: "2-digit", minute: "2-digit" });
  const sameDay = (a: Date, b: Date) => a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
  if (sameDay(d, today)) return `${t.chat.today} ${time}`;
  const y = new Date(now - 86_400_000);
  if (sameDay(d, y)) return `${t.chat.yesterday} ${time}`;
  return `${d.toLocaleDateString(lang === "pt" ? "pt-BR" : "en", { day: "2-digit", month: "2-digit" })} ${time}`;
}

/** The chat's items, oldest first. */
export function chatItems(msgs: HistoryMsg[], now: number, lang: "pt" | "en", t: PhoneStrings): ChatItem[] {
  const out: ChatItem[] = [];
  let lastAt: number | null = null;
  let run: HistoryMsg[] = [];
  const flush = () => {
    if (!run.length) return;
    out.push({ k: "tools", key: `tools-${run[0].id}`, cards: toolCards(run, t) });
    run = [];
  };
  for (const m of msgs) {
    if (m.at !== null && (lastAt === null || m.at - lastAt >= GAP_MS)) {
      flush();
      out.push({ k: "sep", key: `sep-${m.id}`, label: dayLabel(m.at, now, lang, t) });
    }
    if (m.at !== null) lastAt = m.at;
    if (m.role === "tool") {
      run.push(m);
      continue;
    }
    flush();
    out.push({ k: "msg", key: m.id, m, mine: m.role === "user" || m.role === "phone" });
  }
  flush();
  return out;
}

/** Long texts and outputs fold: at most this many characters before "Ver tudo". */
export const FOLD_CHARS = 1400;
export const FOLD_LINES = 24;
export function folds(text: string): boolean {
  return text.length > FOLD_CHARS || text.split("\n").length > FOLD_LINES;
}
