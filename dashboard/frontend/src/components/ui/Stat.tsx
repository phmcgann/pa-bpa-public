import type { ReactNode } from "react";
import { cn } from "../../lib/cn";

/** A single headline number with a label (KPI tile). Clickable when `onClick` is given. */
export function Stat({ label, value, sub, icon, onClick, active, className }: {
  label: ReactNode; value: ReactNode; sub?: ReactNode; icon?: ReactNode;
  onClick?: () => void; active?: boolean; className?: string;
}) {
  const body = (
    <>
      <div className="flex items-center gap-1.5 text-[12px] font-medium text-fg-muted">
        {icon}
        {label}
      </div>
      <div className="tab-num text-[26px] font-semibold leading-8 mt-1.5 text-fg tracking-tight">{value}</div>
      {sub && <div className="text-[12px] text-fg-muted mt-0.5 tab-num">{sub}</div>}
    </>
  );
  const base = "text-left bg-surface border rounded-[var(--radius-card)] shadow-card px-4 py-3.5 min-w-0";
  if (!onClick) return <div className={cn(base, "border-line", className)}>{body}</div>;
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        base, "transition-colors cursor-pointer",
        active ? "border-fg ring-1 ring-fg" : "border-line hover:border-line-strong",
        className,
      )}
    >
      {body}
    </button>
  );
}
