"use client";

// 1.24: above a session's reply field, what a reply will do before it is sent ("Entra agora." /
// "Entra quando a sessão terminar a vez." / "Esta IA não recebe respostas parada: entra na próxima
// vez.") and, once sent, what the computer said happened to it (na fila, enviada, entregue, or why
// not, in plain words). Only for computers that send `replyHow` (1.24 and later); older ones keep
// the composer's v6 lines (PlusViews.tsx).
import type { Locale } from "@/lib/i18n";
import type { ReplyAck, ReplyHow } from "./plus";
import { ackLine, whenText } from "./reply-model";
import styles from "./phone.module.css";

export function SessionReplyCard({
  lang,
  when,
  ack,
  sentHow,
  note,
}: {
  lang: Locale;
  /** What a reply would do now. */
  when: "now" | "turnEnd" | "nextTime";
  /** The computer's answer to the last reply sent from here, if any. */
  ack: ReplyAck | null;
  /** The `replyHow` when that reply was sent. */
  sentHow: ReplyHow | null;
  /** The phone's own line about the last send (sending, cancelled, offline...), until the computer answers. */
  note: string | null;
}) {
  const line = ack ? ackLine(ack, sentHow, lang) : null;
  return (
    <div className={styles.replyCard} data-testid="reply-card">
      {line ? (
        <p className={styles.replyAck} data-kind={line.kind} data-state={ack?.state} role="status" data-testid="reply-ack">
          <span className={styles.replyDot} aria-hidden="true" />
          {line.text}
        </p>
      ) : (
        note && (
          <p className={styles.composerStatus} role="status">
            {note}
          </p>
        )
      )}
      {/* A reply waiting in the queue already says when it goes in; the next one would wait too. */}
      {ack?.state !== "queued" && (
        <p className={styles.replyWhen} data-when={when} data-testid="reply-when">
          {whenText(when, lang)}
        </p>
      )}
    </div>
  );
}
