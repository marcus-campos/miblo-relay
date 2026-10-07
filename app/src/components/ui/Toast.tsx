"use client";

import { useSyncExternalStore } from "react";
import { ToneIcon, type AlertTone } from "./Alert";

// Short-lived confirmations ("Passkey adicionada", "Link copiado"). Call toast() from any client
// component; the one <Toaster /> in the root layout shows them above any sticky bottom bar.
// For anything the person must act on, use an inline <Alert> instead: toasts disappear.

export type ToastItem = { id: number; tone: AlertTone; text: string };

type Listener = () => void;

/** A tiny store, exported for tests. */
export function createToastStore(defaultMs = 4000) {
  let items: ToastItem[] = [];
  let next = 1;
  const listeners = new Set<Listener>();
  const timers = new Map<number, ReturnType<typeof setTimeout>>();
  const emit = () => listeners.forEach((l) => l());
  const dismiss = (id: number) => {
    const t = timers.get(id);
    if (t) clearTimeout(t);
    timers.delete(id);
    const before = items.length;
    items = items.filter((i) => i.id !== id);
    if (items.length !== before) emit();
  };
  const show = (text: string, tone: AlertTone = "success", ms = defaultMs) => {
    const id = next++;
    // At most three at once: the oldest goes first.
    items = [...items, { id, tone, text }].slice(-3);
    timers.set(id, setTimeout(() => dismiss(id), ms));
    emit();
    return id;
  };
  return {
    show,
    dismiss,
    get: () => items,
    subscribe: (l: Listener) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
  };
}

const store = createToastStore();
const empty: ToastItem[] = [];

/** Shows a toast. Errors stay longer, since they usually need reading. */
export function toast(text: string, tone: AlertTone = "success") {
  return store.show(text, tone, tone === "error" ? 7000 : 4000);
}

export function Toaster({ closeLabel = "Fechar" }: { closeLabel?: string }) {
  const items = useSyncExternalStore(store.subscribe, store.get, () => empty);
  return (
    <div
      aria-live="polite"
      className="pointer-events-none fixed inset-x-0 z-[60] flex flex-col items-center gap-2 px-4"
      style={{ bottom: "calc(6rem + env(safe-area-inset-bottom))" }}
    >
      {items.map((t) => (
        <div
          key={t.id}
          role={t.tone === "error" ? "alert" : "status"}
          className="pointer-events-auto flex w-full max-w-md items-center gap-3 rounded-xl border border-line bg-surface px-4 py-3 text-ink shadow-xl"
        >
          <ToneIcon tone={t.tone} />
          <p className="min-w-0 flex-1 font-bold leading-snug">{t.text}</p>
          <button type="button" onClick={() => store.dismiss(t.id)} className="-mr-2 grid min-h-11 min-w-11 place-items-center rounded-md text-ink-2 hover:text-ink" aria-label={closeLabel}>
            <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
              <path d="M3 3l10 10M13 3L3 13" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
            </svg>
          </button>
        </div>
      ))}
    </div>
  );
}
