"use client";

// The conversation as a chat (protocol v6, "History for the chat view"): the person's messages and
// the AI's as bubbles, the AI's Markdown rendered by a strict renderer (chat-markdown.ts: React
// elements only, never HTML; images never loaded; links only http(s), shown with their domain and
// opened after the whole address is confirmed), tool calls as compact cards that open on tap, long
// texts and outputs folded, a time line between messages far apart, "working…" while the session
// works, and the view kept at the newest message (scroll-anchor.ts).
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode, type RefObject } from "react";
import type { Locale } from "@/lib/i18n";
import { Icon } from "./AppParts";
import { chatItems, folds, type ToolCardView } from "./chat-model";
import { parseMarkdown, type Block, type Inline } from "./chat-markdown";
import type { HistoryView } from "./plus";
import { ScrollAnchor } from "./scroll-anchor";
import type { PhoneStrings } from "./strings";
import styles from "./phone.module.css";

// --- Markdown ---------------------------------------------------------------------------------------

function LinkView({ href, domain, bare, children, t }: { href: string; domain: string; bare: boolean; children: ReactNode; t: PhoneStrings }) {
  return (
    <>
      <a
        href={href}
        target="_blank"
        rel="noopener noreferrer nofollow"
        className={styles.mdLink}
        onClick={(e) => {
          // The whole address first: a link's text may name another place than it goes to.
          e.preventDefault();
          if (window.confirm(t.chat.openLink(href))) window.open(href, "_blank", "noopener,noreferrer");
        }}
      >
        {children}
      </a>
      {!bare && <span className={styles.mdDomain}> ({domain})</span>}
    </>
  );
}

function Inlines({ c, t }: { c: Inline[]; t: PhoneStrings }) {
  return (
    <>
      {c.map((x, i) => {
        switch (x.t) {
          case "text":
            return <span key={i}>{x.v}</span>;
          case "br":
            return <br key={i} />;
          case "code":
            return (
              <code key={i} className={styles.mdCode}>
                {x.v}
              </code>
            );
          case "b":
            return (
              <strong key={i}>
                <Inlines c={x.c} t={t} />
              </strong>
            );
          case "i":
            return (
              <em key={i}>
                <Inlines c={x.c} t={t} />
              </em>
            );
          case "s":
            return (
              <del key={i}>
                <Inlines c={x.c} t={t} />
              </del>
            );
          case "img":
            return (
              <span key={i} className={styles.mdImg}>
                {t.chat.image(x.alt)}
              </span>
            );
          case "link":
            return (
              <LinkView key={i} href={x.href} domain={x.domain} bare={x.bare} t={t}>
                <Inlines c={x.c} t={t} />
              </LinkView>
            );
        }
      })}
    </>
  );
}

function CopyButton({ text, t }: { text: string; t: PhoneStrings }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className={styles.copyButton}
      onClick={() => {
        void navigator.clipboard?.writeText(text).then(
          () => {
            setDone(true);
            window.setTimeout(() => setDone(false), 1500);
          },
          () => {},
        );
      }}
    >
      <Icon name={done ? "check" : "copy"} size={14} />
      {done ? t.chat.copied : t.chat.copy}
    </button>
  );
}

/** Long content folds behind "Ver tudo". */
function Fold({ long, t, children }: { long: boolean; t: PhoneStrings; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  if (!long) return <>{children}</>;
  return (
    <div className={styles.fold} data-open={open ? "true" : undefined}>
      <div className={styles.foldBody}>{children}</div>
      <button type="button" className={styles.foldButton} onClick={() => setOpen((v) => !v)} aria-expanded={open}>
        {open ? t.chat.less : t.chat.more}
      </button>
    </div>
  );
}

function CodeBlock({ lang, v, t }: { lang: string; v: string; t: PhoneStrings }) {
  return (
    <div className={styles.mdPre}>
      <div className={styles.mdPreHead}>
        <span>{lang || "code"}</span>
        <CopyButton text={v} t={t} />
      </div>
      <Fold long={folds(v)} t={t}>
        <pre>
          <code>{v}</code>
        </pre>
      </Fold>
    </div>
  );
}

function Blocks({ blocks, t }: { blocks: Block[]; t: PhoneStrings }) {
  return (
    <>
      {blocks.map((b, i) => {
        switch (b.t) {
          case "p":
            return (
              <p key={i}>
                <Inlines c={b.c} t={t} />
              </p>
            );
          case "h": {
            const H = (`h${Math.min(6, b.level + 2)}` as "h3" | "h4" | "h5" | "h6");
            return (
              <H key={i} className={styles.mdH} data-level={b.level}>
                <Inlines c={b.c} t={t} />
              </H>
            );
          }
          case "ul":
            return (
              <ul key={i}>
                {b.items.map((it, j) => (
                  <li key={j}>
                    <Blocks blocks={it} t={t} />
                  </li>
                ))}
              </ul>
            );
          case "ol":
            return (
              <ol key={i} start={b.start}>
                {b.items.map((it, j) => (
                  <li key={j}>
                    <Blocks blocks={it} t={t} />
                  </li>
                ))}
              </ol>
            );
          case "quote":
            return (
              <blockquote key={i}>
                <Blocks blocks={b.c} t={t} />
              </blockquote>
            );
          case "code":
            return <CodeBlock key={i} lang={b.lang} v={b.v} t={t} />;
          case "hr":
            return <hr key={i} />;
          case "table":
            return (
              <div key={i} className={styles.mdTable}>
                <table>
                  <thead>
                    <tr>
                      {b.head.map((c, j) => (
                        <th key={j} style={{ textAlign: b.align[j] === "c" ? "center" : b.align[j] === "r" ? "right" : "left" }}>
                          <Inlines c={c} t={t} />
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {b.rows.map((r, j) => (
                      <tr key={j}>
                        {r.map((c, k) => (
                          <td key={k} style={{ textAlign: b.align[k] === "c" ? "center" : b.align[k] === "r" ? "right" : "left" }}>
                            <Inlines c={c} t={t} />
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            );
        }
      })}
    </>
  );
}

export function ChatMarkdown({ text, t }: { text: string; t: PhoneStrings }) {
  const blocks = useMemo(() => parseMarkdown(text), [text]);
  return (
    <div className={styles.md}>
      <Blocks blocks={blocks} t={t} />
    </div>
  );
}

// --- tool cards ---------------------------------------------------------------------------------------

const KIND_ICON: Record<ToolCardView["kind"], string> = { edit: "✎", write: "＋", read: "◱", run: "›_", search: "⌕", web: "◎", agent: "◇", todo: "☑", other: "•" };

function ToolCard({ c, t }: { c: ToolCardView; t: PhoneStrings }) {
  const hasBody = c.paths.length > 1 || !!c.cmd || c.diff.length > 0 || !!c.out || (c.paths.length === 1 && c.kind !== "read");
  const head = (
    <>
      <span className={styles.toolIcon} aria-hidden="true">
        {KIND_ICON[c.kind]}
      </span>
      <span className={styles.toolLine}>{c.line}</span>
      {(c.add !== null || c.del !== null) && (
        <span className={styles.toolStats}>
          {c.add !== null && <span data-sign="+">+{c.add}</span>}
          {c.del !== null && c.del > 0 && <span data-sign="-">−{c.del}</span>}
        </span>
      )}
      {c.err && <span className={styles.toolErr}>{t.chat.failed}</span>}
    </>
  );
  if (!hasBody) return <div className={styles.toolCard}>{head}</div>;
  return (
    <details className={styles.toolCard} data-err={c.err ? "true" : undefined}>
      <summary>{head}</summary>
      <div className={styles.toolBody}>
        {c.paths.length > 0 && (
          <ul className={styles.toolPaths}>
            {c.paths.map((p, i) => (
              <li key={i}>{p}</li>
            ))}
          </ul>
        )}
        {c.cmd && <pre className={styles.toolPre}>{c.cmd}</pre>}
        {c.diff.length > 0 && (
          <>
            <p className={styles.toolLabel}>{t.chat.changes}</p>
            <pre className={styles.toolPre}>
              {c.diff.map((d, i) => (
                <span key={i} className={styles.diffLine} data-sign={d.sign}>
                  {d.sign} {d.text}
                  {"\n"}
                </span>
              ))}
            </pre>
          </>
        )}
        {c.out && (
          <>
            <p className={styles.toolLabel}>{t.chat.output}</p>
            <Fold long={folds(c.out)} t={t}>
              <pre className={styles.toolPre}>{c.out}</pre>
            </Fold>
          </>
        )}
      </div>
    </details>
  );
}

// --- the list ------------------------------------------------------------------------------------------

export function ChatMessages({ history, t, lang, now, listRef }: { history: HistoryView; t: PhoneStrings; lang: Locale; now: number; listRef: RefObject<HTMLOListElement | null> }) {
  const items = useMemo(() => chatItems(history.msgs, now, lang === "en" ? "en" : "pt", t), [history.msgs, now, lang, t]);
  const time = (at: number | null) => (at ? new Date(at).toLocaleTimeString(lang === "pt" ? "pt-BR" : "en", { hour: "2-digit", minute: "2-digit" }) : "");
  return (
    <ol className={styles.chatList} ref={listRef} data-testid="chat-list">
      {items.map((it) =>
        it.k === "sep" ? (
          <li key={it.key} className={styles.chatSep}>
            {it.label}
          </li>
        ) : it.k === "tools" ? (
          <li key={it.key} className={styles.toolRun}>
            {it.cards.map((c) => (
              <ToolCard key={c.key} c={c} t={t} />
            ))}
          </li>
        ) : (
          <li key={it.key} className={styles.bubble} data-mine={it.mine ? "true" : undefined} data-role={it.m.role}>
            {it.m.md ? (
              <ChatMarkdown text={it.m.text} t={t} />
            ) : (
              <Fold long={folds(it.m.text)} t={t}>
                <p className={styles.plain}>{it.m.text}</p>
              </Fold>
            )}
            <span className={styles.bubbleMeta}>
              {it.m.role === "phone" ? `${t.plus.roles.phone} · ` : ""}
              {time(it.m.at)}
            </span>
          </li>
        ),
      )}
      {history.state === "working" && (
        <li className={styles.typing} aria-live="polite">
          <span className={styles.typingDots} aria-hidden="true">
            <i />
            <i />
            <i />
          </span>
          {t.chat.working}
        </li>
      )}
    </ol>
  );
}

// --- keeping the newest message in view ------------------------------------------------------------------

/**
 * The window follows the end of the conversation while pinned (scroll-anchor.ts). `ids`: the
 * messages shown (the history keeps only the last 50, so a new one can leave the count unchanged:
 * every id ever seen here is counted); `listRef`: the list, whose growth (late history, a code
 * block laid out) is watched. -> the pill's state and the jump.
 */
export function useScrollAnchor(ids: string[], listRef: RefObject<HTMLElement | null>, key: string) {
  const seen = useRef<{ key: string; ids: Set<string> }>({ key, ids: new Set() });
  const [count, setCount] = useState(0);
  useEffect(() => {
    if (seen.current.key !== key) seen.current = { key, ids: new Set() };
    for (const id of ids) seen.current.ids.add(id);
    setCount(seen.current.ids.size);
  }, [ids, key]);
  const [pill, setPill] = useState({ pinned: true, unseen: 0 });
  const anchor = useRef<ScrollAnchor | null>(null);
  const sync = useCallback(() => {
    const a = anchor.current;
    if (a) setPill((p) => (p.pinned === a.pinned && p.unseen === a.unseen ? p : { pinned: a.pinned, unseen: a.unseen }));
  }, []);

  // One anchor per conversation; it starts pinned to the end.
  useEffect(() => {
    const a = new ScrollAnchor({
      metrics: () => ({ scrollTop: window.scrollY, scrollHeight: document.documentElement.scrollHeight, viewport: window.innerHeight }),
      scrollTo: (top, smooth) => window.scrollTo({ top, behavior: smooth ? "smooth" : "auto" }),
    });
    anchor.current = a;
    const input = () => a.userInput();
    const keys = (e: KeyboardEvent) => {
      if (["ArrowUp", "ArrowDown", "PageUp", "PageDown", "Home", "End", " "].includes(e.key)) a.userInput();
    };
    const scroll = () => {
      if (a.onScroll()) sync();
    };
    window.addEventListener("wheel", input, { passive: true });
    window.addEventListener("touchstart", input, { passive: true });
    window.addEventListener("touchmove", input, { passive: true });
    window.addEventListener("keydown", keys);
    window.addEventListener("scroll", scroll, { passive: true });
    return () => {
      window.removeEventListener("wheel", input);
      window.removeEventListener("touchstart", input);
      window.removeEventListener("touchmove", input);
      window.removeEventListener("keydown", keys);
      window.removeEventListener("scroll", scroll);
      anchor.current = null;
    };
  }, [key, sync]);

  // New messages (or the history arriving late).
  useEffect(() => {
    anchor.current?.onContent(count);
    sync();
  }, [count, key, sync]);

  // The list growing without new messages (layout, fonts, a fold opened at the end).
  useEffect(() => {
    const el = listRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    let last = el.getBoundingClientRect().height;
    const ro = new ResizeObserver(() => {
      const h = el.getBoundingClientRect().height;
      if (h > last && anchor.current?.pinned) anchor.current.onContent(count);
      last = h;
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [listRef, count, key]);

  const jump = useCallback(() => {
    anchor.current?.jump();
    sync();
  }, [sync]);
  return { pinned: pill.pinned, unseen: pill.unseen, jump };
}
