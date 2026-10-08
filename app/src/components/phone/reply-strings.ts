// Copy of the 1.24 reply states on the phone (SessionReplyCard.tsx): what a reply will do before it
// is sent, what happened to it after, and every refusal in plain words. docs/phone-relay-protocol.md
// "1.24: replies in every AI tool" has the table.
import type { Locale } from "@/lib/i18n";

/** The AI tools by the id the computer uses (`harness`). */
const TOOLS: Record<string, string> = {
  claude: "Claude Code",
  codex: "Codex",
  opencode: "OpenCode",
  copilot: "Copilot CLI",
  gemini: "Gemini CLI",
  cursor: "Cursor",
};

export function toolName(harness: string | null | undefined, lang: Locale): string {
  return (harness && TOOLS[harness]) || (lang === "en" ? "this AI" : "esta IA");
}

const pt = {
  // Before sending: what the reply will do.
  whenNow: "Entra agora.",
  whenTurnEnd: "Entra quando a sessão terminar a vez.",
  whenNextTime: "Esta IA não recebe respostas parada: entra na próxima vez.",
  // Why the field is off (the computer would refuse a reply).
  idleUnsupported: (tool: string) => `Sessão parada: o ${tool} não aceita mensagens de fora enquanto está parado.`,
  autoMode: "Esta sessão roda em modo automático; respostas só em sessões que pedem permissão.",
  oldSession: "Respostas valem para sessões abertas depois da atualização.",
  unsupported: "Esta IA não recebe respostas pelo celular.",
  // After sending.
  queued: "Na fila: entra quando a sessão terminar a vez.",
  sent: "Enviada.",
  delivered: "Entregue.",
  deliveredNow: "Entregue: entrou na hora.",
  deliveredTurnEnd: "Entregue: entrou no fim da vez.",
  refused: (why: string) => `Não entregue: ${why}`,
  reasons: {
    unsupported: "esta IA não recebe respostas pelo celular.",
    idle_unsupported: "a sessão está parada e esta IA não aceita mensagens de fora assim.",
    old_session: "a sessão foi aberta antes da atualização. Respostas valem para sessões abertas depois dela.",
    expired: "ficou uma hora na fila e a sessão não pegou.",
    session_ended: "a sessão terminou antes de pegar a resposta.",
    deliver_failed: "a IA não aceitou a resposta. Tente de novo.",
    busy: "já há respostas demais esperando (ou outra tarefa rodando). Tente daqui a pouco.",
    rate_limited: "limite de tarefas por hora. Tente mais tarde.",
    folder_changed: "a pasta da tarefa mudou no computador.",
    unknown_tool: "o Claude Code não foi encontrado no computador.",
    stopped: "a tarefa foi parada antes.",
    unknown_mode: "esta sessão roda em modo automático; respostas só em sessões que pedem permissão.",
    permissive_session: "esta sessão roda em modo automático; respostas só em sessões que pedem permissão.",
    off: "as respostas estão desligadas no computador.",
    too_long: "texto longo demais.",
    stale: "o relógio do celular e o do computador não batem. Confira a hora do celular.",
    bad_token: "a conversa mudou no computador. Feche e abra de novo.",
    unknown_session: "a sessão não está mais no computador.",
    no_channel: "a sessão não está com o canal do Miblo.",
    not_claude: "este computador só responde no Claude Code (atualize o Miblo nele).",
    unknown_phone: "este celular não é reconhecido por este computador.",
    bad_mac: "este celular não é reconhecido por este computador.",
    malformed: "o computador não entendeu a mensagem. Atualize o app.",
    passkey: "o computador não aceitou o Face ID, a digital ou o PIN deste celular.",
  } as Record<string, string>,
  other: (code: string) => `o computador recusou (${code}).`,
};

export type ReplyStrings = typeof pt;

const en: ReplyStrings = {
  whenNow: "Goes in now.",
  whenTurnEnd: "Goes in when the session finishes its turn.",
  whenNextTime: "This AI takes no replies while idle: it goes in next time.",
  idleUnsupported: (tool: string) => `Idle: ${tool} cannot take outside messages while idle.`,
  autoMode: "This session runs in auto mode; replies only go to sessions that ask first.",
  oldSession: "Replies work in sessions started after the update.",
  unsupported: "This AI takes no replies from the phone.",
  queued: "Queued: goes in when the session finishes its turn.",
  sent: "Sent.",
  delivered: "Delivered.",
  deliveredNow: "Delivered: it went in right away.",
  deliveredTurnEnd: "Delivered: it went in at the end of the turn.",
  refused: (why: string) => `Not delivered: ${why}`,
  reasons: {
    unsupported: "this AI takes no replies from the phone.",
    idle_unsupported: "the session is idle and this AI cannot take outside messages like that.",
    old_session: "the session was started before the update. Replies work in sessions started after it.",
    expired: "it waited an hour and the session never took it.",
    session_ended: "the session ended before it took the reply.",
    deliver_failed: "the AI did not take the reply. Try again.",
    busy: "too many replies are waiting already (or another task is running). Try again shortly.",
    rate_limited: "the hourly task limit was reached. Try again later.",
    folder_changed: "the task's folder changed on the computer.",
    unknown_tool: "Claude Code was not found on the computer.",
    stopped: "the task was stopped first.",
    unknown_mode: "this session runs in auto mode; replies only go to sessions that ask first.",
    permissive_session: "this session runs in auto mode; replies only go to sessions that ask first.",
    off: "replies are off on the computer.",
    too_long: "the text is too long.",
    stale: "the phone's clock and the computer's disagree. Check the phone's time.",
    bad_token: "the conversation changed on the computer. Close it and open it again.",
    unknown_session: "the session is no longer on the computer.",
    no_channel: "the session is not running with Miblo's channel.",
    not_claude: "this computer takes replies in Claude Code only (update Miblo there).",
    unknown_phone: "the computer does not know this phone.",
    bad_mac: "the computer does not know this phone.",
    malformed: "the computer did not understand the message. Update the app.",
    passkey: "the computer did not accept this phone's Face ID, fingerprint or PIN.",
  },
  other: (code: string) => `the computer refused it (${code}).`,
};

export function replyStrings(lang: Locale): ReplyStrings {
  return lang === "en" ? en : pt;
}
