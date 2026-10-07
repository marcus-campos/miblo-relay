// UI-only decisions of the phone app, kept apart from React so they can be tested in Node:
// which tab shows what, how a tool request is named for people, the approval countdown, which
// install and notification help fits this phone. Nothing here touches the relay or its crypto.
import type { ApprovalView } from "./plus";
import type { MibloView, SessionView } from "./snapshot";

/** The bottom tabs: what needs you now, the person's Miblo, settings. */
export type AppTab = "now" | "miblo" | "settings";
export const APP_TABS: readonly AppTab[] = ["now", "miblo", "settings"];

/** What a tool request does, in words a non-developer understands. */
export type ToolKind = "command" | "edit" | "read" | "web" | "other";

const COMMAND = new Set(["bash", "shell", "powershell", "run_shell_command", "exec_command", "local_shell", "exec"]);
const EDIT = new Set(["write", "edit", "multiedit", "notebookedit", "write_file", "replace", "apply_patch", "edit_file", "create_file"]);
const READ = new Set(["read", "read_file", "read_many_files", "glob", "grep", "ls", "list_directory", "search_file_content"]);
const WEB = new Set(["webfetch", "websearch", "web_fetch", "google_web_search"]);

export function toolKind(tool: string): ToolKind {
  const t = tool.trim().toLowerCase();
  if (COMMAND.has(t)) return "command";
  if (EDIT.has(t)) return "edit";
  if (READ.has(t)) return "read";
  if (WEB.has(t)) return "web";
  return "other";
}

/** An approval's time left: whole seconds, the share of its window still left (0..1), and whether it is urgent. */
export function countdown(a: Pick<ApprovalView, "at" | "expires">, now: number): { left: number; fraction: number; urgent: boolean } {
  const total = Math.max(1, a.expires - a.at);
  const remaining = Math.max(0, a.expires - now);
  const left = Math.ceil(remaining / 1000);
  return { left, fraction: Math.min(1, remaining / total), urgent: left <= 10 };
}

/** Approvals still waiting for an answer (not expired, none given). */
export function pendingApprovals(approvals: readonly ApprovalView[], outcomes: Readonly<Record<string, string>>, now: number): ApprovalView[] {
  return approvals.filter((a) => a.expires > now && !outcomes[a.id]);
}

/**
 * The number on the "Agora" tab for one computer: the sessions that need the person, or the
 * approvals waiting, whichever is larger (an approval is usually what makes its session wait).
 */
export function attentionCount(sessions: readonly Pick<SessionView, "kind">[] | undefined, pending: number): number {
  const needs = sessions?.filter((s) => s.kind === "needs").length ?? 0;
  return Math.max(needs, pending);
}

/** Which Miblo the compact card shows: one asking for attention, else one online, else the first. */
export function featuredMiblo(miblos: readonly MibloView[]): number {
  const alert = miblos.findIndex((m) => m.online && m.screen === "alert");
  if (alert >= 0) return alert;
  const online = miblos.findIndex((m) => m.online);
  return online >= 0 ? online : 0;
}

export type DeviceKind = { ios: boolean; android: boolean; standalone: boolean };

export function deviceKind(ua: string, ios: boolean, standalone: boolean): DeviceKind {
  return { ios, android: /Android/i.test(ua), standalone };
}

/**
 * How to put the app on the home screen here: already installed, the browser's own install
 * prompt (Android/Chrome), the iPhone share sheet, Android's menu, or a generic hint.
 */
export type InstallHint = "installed" | "prompt" | "ios" | "android" | "other";
export function installHint(d: DeviceKind, canPrompt: boolean): InstallHint {
  if (d.standalone) return "installed";
  if (canPrompt) return "prompt";
  if (d.ios) return "ios";
  if (d.android) return "android";
  return "other";
}

/** Where to unblock notifications once the person (or the browser) said no. */
export type NotifyHelp = "ios" | "android-app" | "android" | "other";
export function notifyHelp(d: DeviceKind): NotifyHelp {
  if (d.ios) return "ios";
  if (d.android) return d.standalone ? "android-app" : "android";
  return "other";
}

/** "agora" / "há 5 min" from a compact elapsed text (snapshot.elapsed). */
export function agoText(ms: number, lang: "pt" | "en", elapsedText: string): string {
  if (ms < 60_000) return lang === "pt" ? "agora" : "now";
  return lang === "pt" ? `há ${elapsedText}` : `${elapsedText} ago`;
}
