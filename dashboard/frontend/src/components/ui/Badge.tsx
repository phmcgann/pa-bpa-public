import type { ReactNode } from "react";
import { cn } from "../../lib/cn";
import { SEVERITY_META } from "../../severity";
import type { Severity } from "../../types";
import { SeverityIcon } from "./SeverityIcon";

type Tone = "neutral" | "accent" | "critical" | "warning" | "low" | "info" | "good" | "outline";

const TONES: Record<Tone, string> = {
  neutral: "bg-surface-3 text-fg-2",
  accent: "bg-accent-soft text-accent-fg",
  critical: "bg-[color-mix(in_srgb,var(--sev-critical)_12%,transparent)] text-critical-fg",
  warning: "bg-[color-mix(in_srgb,var(--sev-warning)_14%,transparent)] text-warning-fg",
  low: "bg-[color-mix(in_srgb,var(--sev-low)_16%,transparent)] text-low-fg",
  info: "bg-surface-3 text-info-fg",
  good: "bg-[color-mix(in_srgb,var(--good)_12%,transparent)] text-good-fg",
  outline: "border border-line-strong text-fg-2",
};

export function Badge({ tone = "neutral", children, className, title }: {
  tone?: Tone; children: ReactNode; className?: string; title?: string;
}) {
  return (
    <span
      title={title}
      className={cn(
        "badge inline-flex items-center gap-1 h-5 px-1.5 rounded-md text-[11px] font-medium whitespace-nowrap leading-none",
        TONES[tone], className,
      )}
    >
      {children}
    </span>
  );
}

const SEV_TONE: Record<Severity, Tone> = { CRITICAL: "critical", WARNING: "warning", LOW: "low", INFORMATIONAL: "info" };

/** Severity as icon + label on a soft tint — never color alone. */
export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <Badge tone={SEV_TONE[severity]} className={cn("sev-badge", className)}>
      <SeverityIcon severity={severity} size={12} />
      {SEVERITY_META[severity].label}
    </Badge>
  );
}
