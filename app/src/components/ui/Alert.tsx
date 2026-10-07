// Inline feedback: one look for every "it worked", "check this" and "it failed" on the site.
// Errors are announced at once (role="alert"); the others politely (role="status").

export type AlertTone = "info" | "success" | "warning" | "error";

const toneClass: Record<AlertTone, string> = {
  info: "border-blue-ink/40 bg-blue/10",
  success: "border-green-ink/40 bg-green/10",
  warning: "border-amber-ink/40 bg-amber/10",
  error: "border-red-ink/50 bg-red/10",
};

const iconClass: Record<AlertTone, string> = {
  info: "text-blue-ink",
  success: "text-green-ink",
  warning: "text-amber-ink",
  error: "text-red-ink",
};

export function alertRole(tone: AlertTone): "alert" | "status" {
  return tone === "error" ? "alert" : "status";
}

export function ToneIcon({ tone, className = "" }: { tone: AlertTone; className?: string }) {
  return (
    <svg width="22" height="22" viewBox="0 0 22 22" aria-hidden="true" className={`shrink-0 ${iconClass[tone]} ${className}`}>
      <circle cx="11" cy="11" r="9.5" fill="none" stroke="currentColor" strokeWidth="2" />
      {tone === "success" && <path d="M6.5 11.3l3 3 6-6.3" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />}
      {tone === "info" && (
        <>
          <path d="M11 10v5.5" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" />
          <circle cx="11" cy="6.8" r="1.3" fill="currentColor" />
        </>
      )}
      {(tone === "warning" || tone === "error") && (
        <>
          <path d="M11 6v6" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" />
          <circle cx="11" cy="15.4" r="1.3" fill="currentColor" />
        </>
      )}
    </svg>
  );
}

/**
 * A boxed message with an icon. `title` is the one-line summary, `children` the detail, and
 * `action` a button or link (for example "Pagar com Pix" under a refused card).
 * Give it an `id` and `tabIndex={-1}` when focus should move to it after a failed submit.
 */
export function Alert({
  tone = "info",
  title,
  children,
  action,
  id,
  tabIndex,
  className = "",
}: {
  tone?: AlertTone;
  title?: React.ReactNode;
  children?: React.ReactNode;
  action?: React.ReactNode;
  id?: string;
  tabIndex?: number;
  className?: string;
}) {
  return (
    <div id={id} tabIndex={tabIndex} role={alertRole(tone)} data-tone={tone} className={`flex gap-3 rounded-xl border-2 p-4 text-ink ${toneClass[tone]} ${className}`}>
      <ToneIcon tone={tone} className="mt-0.5" />
      <div className="min-w-0 flex-1">
        {title && <p className="font-bold">{title}</p>}
        {children && <div className={title ? "mt-1 text-[0.95rem]" : "text-[0.95rem]"}>{children}</div>}
        {action && <div className="mt-3 flex flex-wrap gap-3">{action}</div>}
      </div>
    </div>
  );
}
