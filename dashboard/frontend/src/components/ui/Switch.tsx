import { cn } from "../../lib/cn";

/** On/off switch (role="switch"); pass `label` for the accessible name when there's no visible one. */
export function Switch({ checked, onChange, label, disabled, className }: {
  checked: boolean; onChange: (value: boolean) => void; label?: string; disabled?: boolean; className?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={(e) => { e.stopPropagation(); onChange(!checked); }}
      className={cn(
        "relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border transition-colors duration-150",
        "disabled:opacity-50 disabled:pointer-events-none",
        checked ? "bg-accent border-transparent" : "bg-surface-3 border-line-strong",
        className,
      )}
    >
      <span
        aria-hidden="true"
        className={cn(
          "inline-block size-3.5 rounded-full bg-white shadow-sm transition-transform duration-150",
          checked ? "translate-x-[18px]" : "translate-x-[2px]",
        )}
      />
    </button>
  );
}
