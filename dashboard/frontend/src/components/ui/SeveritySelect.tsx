import { ChevronDown } from "lucide-react";
import { SEVERITY_ORDER, severityLabel } from "../../severity";
import type { Severity } from "../../types";
import { cn } from "../../lib/cn";
import { SeverityIcon } from "./SeverityIcon";

/**
 * A rule's severity: the default, or an override. Shows the effective severity with its icon;
 * the native select underneath keeps it keyboard- and screen-reader-friendly.
 */
export function SeveritySelect({ value, defaultSeverity, override, onChange, defaultNote, label }: {
  value: Severity;
  defaultSeverity: Severity;
  override: Severity | null;
  onChange: (severity: string) => void;
  /** Extra text on the default option, e.g. Palo Alto's own wording. */
  defaultNote?: string;
  label: string;
}) {
  return (
    <span className={cn(
      "relative inline-flex items-center gap-1.5 h-7 pl-2 pr-6 rounded-md border text-[12px] font-medium",
      override ? "border-accent/60 bg-accent-soft" : "border-line bg-surface",
    )}>
      <SeverityIcon severity={value} size={12} />
      <span className="text-fg">{severityLabel(value)}</span>
      <ChevronDown size={13} className="absolute right-1.5 text-fg-muted pointer-events-none" aria-hidden="true" />
      <select
        aria-label={label}
        value={override ?? ""}
        onChange={(e) => onChange(e.target.value)}
        className="absolute inset-0 opacity-0 cursor-pointer w-full min-h-0 h-full"
      >
        <option value="">{severityLabel(defaultSeverity)} (default{defaultNote ? ` · ${defaultNote}` : ""})</option>
        {SEVERITY_ORDER.filter((s) => s !== defaultSeverity).map((s) => (
          <option key={s} value={s}>{severityLabel(s)}</option>
        ))}
      </select>
    </span>
  );
}
