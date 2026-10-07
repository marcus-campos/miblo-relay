// A strict Markdown parser for the AI's messages in the phone's chat view (protocol v6, "History for
// the chat view"). It produces plain data (blocks and inline runs) that ChatMarkdown renders as
// React elements only: no HTML is ever parsed or produced, so raw HTML in a message stays visible
// text, images are never loaded (an image becomes "[imagem: alt]"), and links keep only http(s)
// addresses, shown with their domain and opened only after the person confirms the whole address.
// Supported: headings, paragraphs (line breaks kept), bullet and numbered lists (nested by
// indentation), quotes, fenced code blocks, tables (GitHub style), rules, **bold**, *italic*,
// ~~strikethrough~~, `code`, [links](https://…) and bare https:// addresses.

export type Inline =
  | { t: "text"; v: string }
  | { t: "b" | "i" | "s"; c: Inline[] }
  | { t: "code"; v: string }
  | { t: "link"; href: string; domain: string; c: Inline[]; bare: boolean }
  | { t: "img"; alt: string }
  | { t: "br" };

export type Block =
  | { t: "p"; c: Inline[] }
  | { t: "h"; level: 1 | 2 | 3 | 4; c: Inline[] }
  | { t: "ul"; items: Block[][] }
  | { t: "ol"; start: number; items: Block[][] }
  | { t: "quote"; c: Block[] }
  | { t: "code"; lang: string; v: string }
  | { t: "table"; head: Inline[][]; rows: Inline[][][]; align: ("l" | "c" | "r" | null)[] }
  | { t: "hr" };

const MAX_DEPTH = 6;
const MAX_BLOCKS = 400;

/** An address the phone may open: http(s) only, no credentials, rebuilt from the parsed URL. */
export function safeLink(raw: string): { href: string; domain: string } | null {
  const v = raw.trim();
  if (!/^https?:\/\//i.test(v)) return null;
  try {
    const u = new URL(v);
    if ((u.protocol !== "http:" && u.protocol !== "https:") || u.username || u.password || !u.hostname) return null;
    // The hostname as the URL parser gives it: an international domain shows as its punycode (xn--…),
    // so a look-alike cannot pass for a familiar name.
    return { href: u.href, domain: u.hostname };
  } catch {
    return null;
  }
}

// --- inline ---------------------------------------------------------------------------------------

const BARE_URL = /^https?:\/\/[^\s<>"'`]+/i;

function pushText(out: Inline[], v: string) {
  if (!v) return;
  const last = out[out.length - 1];
  if (last && last.t === "text") last.v += v;
  else out.push({ t: "text", v });
}

/** The closing delimiter `close` after `from` (not escaped, not right after an opening space). */
function findClose(s: string, from: number, close: string): number {
  for (let j = from; j <= s.length - close.length; j++) {
    if (s[j] === "\\") {
      j++;
      continue;
    }
    if (s.startsWith(close, j) && j > from && !/\s/.test(s[j - 1])) return j;
  }
  return -1;
}

/** `[label](url)` at `i`: -> { label, url, end } or null. */
function bracketLink(s: string, i: number): { label: string; url: string; end: number } | null {
  let depth = 0;
  let j = i;
  for (; j < s.length; j++) {
    if (s[j] === "\\") {
      j++;
      continue;
    }
    if (s[j] === "[") depth++;
    else if (s[j] === "]") {
      depth--;
      if (depth === 0) break;
    } else if (s[j] === "\n" && s[j + 1] === "\n") return null;
  }
  if (depth !== 0 || s[j + 1] !== "(") return null;
  const close = s.indexOf(")", j + 2);
  if (close < 0 || close - j > 2100) return null;
  const inside = s.slice(j + 2, close).trim();
  // [label](url "title"): the title is dropped.
  const url = inside.split(/\s+/)[0] ?? "";
  return { label: s.slice(i + 1, j), url, end: close + 1 };
}

export function parseInline(s: string, depth = 0): Inline[] {
  const out: Inline[] = [];
  if (depth > MAX_DEPTH) {
    pushText(out, s);
    return out;
  }
  let i = 0;
  while (i < s.length) {
    const ch = s[i];
    const rest = s.slice(i);
    if (ch === "\\" && i + 1 < s.length && /[\\`*_~[\]()#+\-.!|>]/.test(s[i + 1])) {
      pushText(out, s[i + 1]);
      i += 2;
      continue;
    }
    if (ch === "\n") {
      out.push({ t: "br" });
      i++;
      continue;
    }
    if (ch === "`") {
      const run = /^`+/.exec(rest)![0];
      const end = s.indexOf(run, i + run.length);
      if (end > 0) {
        out.push({ t: "code", v: s.slice(i + run.length, end).replace(/^ ([\s\S]*) $/, "$1") });
        i = end + run.length;
        continue;
      }
      pushText(out, run);
      i += run.length;
      continue;
    }
    if (ch === "!" && s[i + 1] === "[") {
      const l = bracketLink(s, i + 1);
      if (l) {
        // Never loaded: an image is its description only.
        out.push({ t: "img", alt: l.label.slice(0, 120) });
        i = l.end;
        continue;
      }
    }
    if (ch === "[") {
      const l = bracketLink(s, i);
      if (l) {
        const ok = safeLink(l.url);
        const label = parseInline(l.label, depth + 1);
        if (ok) out.push({ t: "link", ...ok, c: label, bare: false });
        else {
          // Not an address the phone opens: its text stays, plainly.
          for (const x of label) {
            if (x.t === "text") pushText(out, x.v);
            else out.push(x);
          }
          pushText(out, ` (${l.url.slice(0, 200)})`);
        }
        i = l.end;
        continue;
      }
    }
    if ((ch === "h" || ch === "H") && (i === 0 || /[\s(<]/.test(s[i - 1]))) {
      const m = BARE_URL.exec(rest);
      if (m) {
        let url = m[0];
        const trail = /[.,;:!?)\]]+$/.exec(url);
        if (trail) url = url.slice(0, -trail[0].length);
        const ok = safeLink(url);
        if (ok) {
          out.push({ t: "link", ...ok, c: [{ t: "text", v: url }], bare: true });
          i += url.length;
          continue;
        }
      }
    }
    if ((ch === "*" || ch === "_") && s[i + 1] === ch && s[i + 2] && !/\s/.test(s[i + 2])) {
      const end = findClose(s, i + 2, ch + ch);
      if (end > 0) {
        out.push({ t: "b", c: parseInline(s.slice(i + 2, end), depth + 1) });
        i = end + 2;
        continue;
      }
    }
    if (ch === "~" && s[i + 1] === "~" && s[i + 2] && !/\s/.test(s[i + 2])) {
      const end = findClose(s, i + 2, "~~");
      if (end > 0) {
        out.push({ t: "s", c: parseInline(s.slice(i + 2, end), depth + 1) });
        i = end + 2;
        continue;
      }
    }
    if ((ch === "*" || ch === "_") && s[i + 1] && !/\s/.test(s[i + 1]) && (ch === "*" || i === 0 || !/\w/.test(s[i - 1]))) {
      const end = findClose(s, i + 1, ch);
      if (end > 0 && (ch === "*" || !/\w/.test(s[end + 1] ?? ""))) {
        out.push({ t: "i", c: parseInline(s.slice(i + 1, end), depth + 1) });
        i = end + 1;
        continue;
      }
    }
    // Plain text up to the next character that may start something.
    const next = rest.slice(1).search(/[\\\n`![*_~hH]/);
    const take = next < 0 ? rest.length : next + 1;
    pushText(out, rest.slice(0, take));
    i += take;
  }
  return out;
}

// --- blocks ---------------------------------------------------------------------------------------

const FENCE = /^ {0,3}(`{3,}|~{3,})\s*([\w+#.-]*)[^\n]*$/;
const HEADING = /^ {0,3}(#{1,6})\s+(.*?)\s*#*\s*$/;
const HR = /^ {0,3}((\*\s*){3,}|(-\s*){3,}|(_\s*){3,})$/;
const LIST = /^(\s*)([-*+]|(\d{1,9})[.)])\s+(.*)$/;
const QUOTE = /^ {0,3}>\s?(.*)$/;
const TABLE_SEP = /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/;

const cells = (line: string): string[] => {
  let l = line.trim();
  if (l.startsWith("|")) l = l.slice(1);
  if (l.endsWith("|") && !l.endsWith("\\|")) l = l.slice(0, -1);
  const out: string[] = [];
  let cur = "";
  for (let i = 0; i < l.length; i++) {
    if (l[i] === "\\" && l[i + 1] === "|") {
      cur += "|";
      i++;
    } else if (l[i] === "|") {
      out.push(cur.trim());
      cur = "";
    } else cur += l[i];
  }
  out.push(cur.trim());
  return out.slice(0, 12);
};

const startsBlock = (line: string, next: string | undefined) =>
  FENCE.test(line) || HEADING.test(line) || HR.test(line) || LIST.test(line) || QUOTE.test(line) || (line.includes("|") && next !== undefined && TABLE_SEP.test(next));

export function parseMarkdown(text: string, depth = 0): Block[] {
  const lines = String(text ?? "").replace(/\r\n?/g, "\n").split("\n");
  const out: Block[] = [];
  let i = 0;
  while (i < lines.length && out.length < MAX_BLOCKS) {
    const line = lines[i];
    if (!line.trim()) {
      i++;
      continue;
    }
    const fence = FENCE.exec(line);
    if (fence) {
      const mark = fence[1];
      const body: string[] = [];
      i++;
      while (i < lines.length && !new RegExp(`^ {0,3}${mark[0] === "`" ? "`" : "~"}{${mark.length},}\\s*$`).test(lines[i])) body.push(lines[i++]);
      i++;
      out.push({ t: "code", lang: fence[2].slice(0, 20), v: body.join("\n") });
      continue;
    }
    const h = HEADING.exec(line);
    if (h) {
      out.push({ t: "h", level: Math.min(4, h[1].length) as 1 | 2 | 3 | 4, c: parseInline(h[2], depth) });
      i++;
      continue;
    }
    if (HR.test(line)) {
      out.push({ t: "hr" });
      i++;
      continue;
    }
    if (QUOTE.test(line)) {
      const body: string[] = [];
      while (i < lines.length && lines[i].trim() && QUOTE.test(lines[i])) body.push(QUOTE.exec(lines[i++])![1]);
      out.push({ t: "quote", c: depth < MAX_DEPTH ? parseMarkdown(body.join("\n"), depth + 1) : [{ t: "p", c: [{ t: "text", v: body.join("\n") }] }] });
      continue;
    }
    if (line.includes("|") && i + 1 < lines.length && TABLE_SEP.test(lines[i + 1])) {
      const head = cells(line);
      const align = cells(lines[i + 1]).map((c) => (c.startsWith(":") && c.endsWith(":") ? "c" : c.endsWith(":") ? "r" : c.startsWith(":") ? "l" : null));
      i += 2;
      const rows: Inline[][][] = [];
      while (i < lines.length && lines[i].trim() && lines[i].includes("|") && rows.length < 100) rows.push(cells(lines[i++]).map((c) => parseInline(c, depth)));
      out.push({ t: "table", head: head.map((c) => parseInline(c, depth)), rows, align });
      continue;
    }
    const li = LIST.exec(line);
    if (li) {
      const ordered = li[3] !== undefined;
      const indent = li[1].length;
      const items: string[][] = [];
      while (i < lines.length) {
        const m = LIST.exec(lines[i]);
        if (m && m[1].length <= indent + 1 && (m[3] !== undefined) === ordered) {
          items.push([m[4]]);
          i++;
          continue;
        }
        // Continuation: an indented line (or a nested list) belongs to the item; a blank line
        // followed by an indented one too.
        if (items.length && lines[i].trim() && (/^\s{2,}/.test(lines[i]) || (!startsBlock(lines[i], lines[i + 1]) && !LIST.test(lines[i])))) {
          items[items.length - 1].push(lines[i].replace(/^\s{1,4}/, ""));
          i++;
          continue;
        }
        if (!lines[i].trim() && i + 1 < lines.length && /^\s{2,}\S/.test(lines[i + 1]) && items.length) {
          items[items.length - 1].push("");
          i++;
          continue;
        }
        break;
      }
      const blocks = items.slice(0, 200).map((it) => (depth < MAX_DEPTH ? parseMarkdown(it.join("\n"), depth + 1) : [{ t: "p" as const, c: [{ t: "text" as const, v: it.join("\n") }] }]));
      out.push(ordered ? { t: "ol", start: Math.min(Number(li[3]), 1e6), items: blocks } : { t: "ul", items: blocks });
      continue;
    }
    // A paragraph, up to a blank line or the start of another block.
    const body: string[] = [line];
    i++;
    while (i < lines.length && lines[i].trim() && !startsBlock(lines[i], lines[i + 1])) body.push(lines[i++]);
    out.push({ t: "p", c: parseInline(body.join("\n"), depth) });
  }
  return out;
}

/** The plain text of some inline runs (for labels and tests). */
export function plainText(c: Inline[]): string {
  return c.map((x) => (x.t === "text" || x.t === "code" ? x.v : x.t === "br" ? "\n" : x.t === "img" ? `[${x.alt}]` : plainText(x.c))).join("");
}
