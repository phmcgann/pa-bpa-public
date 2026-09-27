import { Info, TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "../../lib/cn";

export function Callout({ tone = "info", title, children, className }: {
  tone?: "info" | "warning"; title?: ReactNode; children: ReactNode; className?: string;
}) {
  const Icon = tone === "warning" ? TriangleAlert : Info;
  return (
    <div className={cn(
      "flex gap-3 rounded-[var(--radius-card)] border px-4 py-3 text-[13px] leading-5",
      tone === "warning"
        ? "border-[color-mix(in_srgb,var(--sev-low)_45%,var(--border))] bg-[color-mix(in_srgb,var(--sev-low)_8%,var(--surface))]"
        : "border-line bg-surface",
      className,
    )}>
      <Icon size={16} className={cn("shrink-0 mt-0.5", tone === "warning" ? "text-low-fg" : "text-fg-muted")} aria-hidden="true" />
      <div className="text-fg-2 min-w-0">
        {title && <span className="font-semibold text-fg">{title} </span>}
        {children}
      </div>
    </div>
  );
}
