"use client";

// "Nova tarefa" (protocol v6): start a new headless AI run on the computer from the phone, in a
// folder allowed there, and follow it as a conversation. The sheet shows exactly what will run
// (the AI, its mode, the folder's path, the text) before the phone's passkey is asked; the computer
// checks all of it again (lib/plus/tasks.js in the plugin).
import { useMemo, useState } from "react";
import { Icon, Tech } from "./AppParts";
import type { TaskInfo, TaskListItem } from "./plus";
import type { PhoneStrings } from "./strings";
import styles from "./phone.module.css";

export type TaskSendResult = "ok" | "empty" | "too_long" | "no_token" | "cancelled" | "offline" | { refused: string };

export function TaskSheet({
  t,
  info,
  online,
  canSign,
  onClose,
  onSend,
  onOpenTask,
}: {
  t: PhoneStrings;
  /** null: still asking the computer. */
  info: TaskInfo | null;
  online: boolean;
  /** This phone has a passkey and the computer accepted it. */
  canSign: boolean;
  onClose: () => void;
  onSend: (tool: string, folder: string, text: string) => Promise<TaskSendResult>;
  onOpenTask: (id: string) => void;
}) {
  const [tool, setTool] = useState("");
  const [folder, setFolder] = useState("");
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<{ text: string; bad?: boolean } | null>(null);
  // The first choices until the person picks (the computer's list may change between answers).
  const chosenTool = useMemo(() => info?.tools.find((x) => x.id === tool) ?? info?.tools[0] ?? null, [info, tool]);
  const chosenFolder = useMemo(() => info?.folders.find((x) => x.id === folder) ?? info?.folders[0] ?? null, [info, folder]);

  const send = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chosenTool || !chosenFolder) return;
    setBusy(true);
    setNote({ text: t.task.sending });
    const r = await onSend(chosenTool.id, chosenFolder.id, text);
    setBusy(false);
    if (r === "ok") {
      setText("");
      setNote({ text: t.task.started });
    } else if (typeof r === "object") setNote({ text: t.task.refused(t.task.reasons[r.refused] ?? r.refused), bad: true });
    else
      setNote({
        text: r === "empty" ? t.task.empty : r === "too_long" ? t.task.tooLong : r === "no_token" ? t.task.noToken : r === "cancelled" ? t.task.cancelled : t.task.offline,
        bad: true,
      });
  };

  return (
    <section className={styles.taskSheet} aria-labelledby="task-title" data-testid="task-sheet">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 id="task-title" className="text-[1.0625rem] font-bold">
            {t.task.title}
          </h2>
          <p className="mt-1 text-[0.95rem] text-ink-2">{t.task.lead}</p>
        </div>
        <button type="button" className={styles.iconButton} onClick={onClose} aria-label={t.close}>
          <Icon name="close" size={20} />
        </button>
      </div>
      {!info ? (
        <p className="text-ink-2">{t.task.loading}</p>
      ) : !info.on ? (
        <div>
          <p className="font-bold">{t.task.off}</p>
          <p className="mt-1 text-[0.95rem] text-ink-2">{t.task.offHow}</p>
          <Tech t={t} commands={t.task.offTech} />
        </div>
      ) : !info.tools.length ? (
        <p className="font-bold">{t.task.noTools}</p>
      ) : !info.folders.length ? (
        <div>
          <p className="font-bold">{t.task.noFolders}</p>
          <Tech t={t} commands={[t.task.offTech[0]]} />
        </div>
      ) : (
        <form onSubmit={send} className="grid gap-3">
          <div>
            <label className={styles.fieldLabel} htmlFor="task-tool">
              {t.task.tool}
            </label>
            <select id="task-tool" className={styles.select} value={chosenTool?.id ?? ""} onChange={(e) => setTool(e.target.value)}>
              {info.tools.map((x) => (
                <option key={x.id} value={x.id}>
                  {x.name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className={styles.fieldLabel} htmlFor="task-folder">
              {t.task.folder}
            </label>
            <select id="task-folder" className={styles.select} value={chosenFolder?.id ?? ""} onChange={(e) => setFolder(e.target.value)}>
              {info.folders.map((x) => (
                <option key={x.id} value={x.id}>
                  {x.name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className={styles.fieldLabel} htmlFor="task-text">
              {t.task.prompt}
            </label>
            <textarea id="task-text" className={styles.taskArea} value={text} maxLength={4000} onChange={(e) => setText(e.target.value)} placeholder={t.task.placeholder} />
          </div>
          {chosenTool && chosenFolder && (
            // Exactly what the computer will run, before the passkey is asked.
            <div className={styles.willRun} data-testid="task-will-run">
              <p className="font-bold">{t.task.willRun(chosenTool.name, chosenFolder.path)}</p>
              <p className="mt-1 text-ink-2">{chosenTool.mode}</p>
              <p className="mt-1 text-ink-2">{t.task.limit(info.maxMin)}</p>
            </div>
          )}
          {note && (
            <p role="status" className={note.bad ? "font-bold text-amber-ink" : "text-ink-2"}>
              {note.text}
            </p>
          )}
          <button type="submit" className="btn btn-primary w-full" disabled={busy || !online || !canSign || !text.trim()} aria-busy={busy}>
            {t.task.send}
          </button>
          <p className="text-[0.875rem] text-ink-2">{canSign ? t.task.passkey : t.chat.noPasskey}</p>
        </form>
      )}
      {info && info.tasks.length > 0 && <TaskList t={t} tasks={info.tasks} onOpen={onOpenTask} />}
    </section>
  );
}

export function TaskList({ t, tasks, onOpen }: { t: PhoneStrings; tasks: TaskListItem[]; onOpen: (id: string) => void }) {
  return (
    <div>
      <h3 className="text-[0.95rem] font-bold">{t.task.recent}</h3>
      <ul className={`${styles.taskRows} mt-2`}>
        {[...tasks].reverse().map((x) => (
          <li key={x.id}>
            <button type="button" className={styles.taskRow} data-state={x.state} onClick={() => onOpen(x.id)}>
              <span className={styles.dot} aria-hidden="true" />
              <span className="min-w-0 flex-1">
                <span className="block truncate font-bold">{x.text || x.id}</span>
                <span className="block truncate text-[0.8125rem] text-ink-2">
                  {[t.task.states[x.state], x.tool, x.folder].filter(Boolean).join(" · ")}
                </span>
              </span>
              <Icon name="chevron" size={18} />
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
