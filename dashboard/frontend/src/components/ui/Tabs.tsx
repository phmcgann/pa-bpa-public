import { ChevronLeft, ChevronRight } from "lucide-react";
import { useCallback, useEffect, useRef, useState, type KeyboardEvent } from "react";
import { cn } from "../../lib/cn";

export interface TabDef { id: string; label: string; count?: number }

/**
 * Underline tabs with arrow-key navigation (WAI-ARIA tabs pattern). The strip scrolls sideways on
 * narrow screens; the baseline is an inset shadow and the active underline sits inside the strip,
 * so nothing overflows vertically (which would show a stray vertical scrollbar on Windows).
 * When tabs are cut off, that edge fades out and gets an arrow button that scrolls the rest into view.
 */
export function Tabs({ tabs, value, onChange, className }: {
  tabs: TabDef[]; value: string; onChange: (id: string) => void; className?: string;
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const strip = useRef<HTMLDivElement>(null);
  const [edges, setEdges] = useState({ left: false, right: false });
  const measure = useCallback(() => {
    const el = strip.current;
    if (!el) return;
    const left = el.scrollLeft > 1;
    const right = el.scrollLeft + el.clientWidth < el.scrollWidth - 1;
    setEdges((e) => (e.left === left && e.right === right ? e : { left, right }));
  }, []);
  useEffect(() => {
    const el = strip.current;
    if (!el) return;
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [measure, tabs.length]);
  useEffect(() => {
    // Keep the selected tab visible, e.g. after a KPI tile switches to Findings.
    // Scrolls the strip only, never the page.
    const el = strip.current;
    const tab = refs.current[tabs.findIndex((t) => t.id === value)];
    if (!el || !tab) return;
    const pad = 56;
    if (tab.offsetLeft - pad < el.scrollLeft) el.scrollTo({ left: tab.offsetLeft - pad, behavior: "smooth" });
    else if (tab.offsetLeft + tab.offsetWidth + pad > el.scrollLeft + el.clientWidth) {
      el.scrollTo({ left: tab.offsetLeft + tab.offsetWidth + pad - el.clientWidth, behavior: "smooth" });
    }
  }, [value, tabs]);
  function page(dir: 1 | -1) {
    const el = strip.current;
    if (el) el.scrollBy({ left: dir * el.clientWidth * 0.7, behavior: "smooth" });
  }
  function onKey(e: KeyboardEvent, i: number) {
    const dir = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
    if (!dir) return;
    e.preventDefault();
    const next = (i + dir + tabs.length) % tabs.length;
    refs.current[next]?.focus();
    onChange(tabs[next].id);
  }
  const fade = "linear-gradient(to right, transparent, #000 56px, #000 calc(100% - 56px), transparent)";
  const mask = edges.left && edges.right ? fade
    : edges.left ? "linear-gradient(to right, transparent, #000 56px)"
    : edges.right ? "linear-gradient(to left, transparent, #000 56px)" : undefined;
  return (
    <div className={cn("relative no-print", className)}>
      <div
        ref={strip}
        role="tablist"
        onScroll={measure}
        style={{ maskImage: mask, WebkitMaskImage: mask }}
        className={cn(
          "flex gap-1 shadow-[inset_0_-1px_0_var(--border)] overflow-x-auto overflow-y-hidden",
          "[scrollbar-width:none] [&::-webkit-scrollbar]:hidden",
        )}
      >
        {tabs.map((t, i) => {
          const selected = t.id === value;
          return (
            <button
              key={t.id}
              ref={(el) => { refs.current[i] = el; }}
              role="tab"
              id={`tab-${t.id}`}
              aria-selected={selected}
              aria-controls={`panel-${t.id}`}
              tabIndex={selected ? 0 : -1}
              onClick={() => onChange(t.id)}
              onKeyDown={(e) => onKey(e, i)}
              className={cn(
                "relative h-10 px-3 text-[13px] font-medium whitespace-nowrap bg-transparent border-0 rounded-none",
                "transition-colors",
                selected ? "text-fg" : "text-fg-muted hover:text-fg",
              )}
            >
              <span className="inline-flex items-center gap-1.5">
                {t.label}
                {t.count !== undefined && (
                  <span className={cn(
                    "tab-num text-[11px] px-1.5 rounded-full leading-[18px]",
                    selected ? "bg-fg text-surface" : "bg-surface-3 text-fg-muted",
                  )}>
                    {t.count}
                  </span>
                )}
              </span>
              <span
                aria-hidden="true"
                className={cn("absolute left-2 right-2 bottom-0 h-0.5 rounded-full", selected ? "bg-brand" : "bg-transparent")}
              />
            </button>
          );
        })}
      </div>
      {edges.left && <ScrollButton side="left" onClick={() => page(-1)} />}
      {edges.right && <ScrollButton side="right" onClick={() => page(1)} />}
    </div>
  );
}

function ScrollButton({ side, onClick }: { side: "left" | "right"; onClick: () => void }) {
  const Icon = side === "left" ? ChevronLeft : ChevronRight;
  return (
    <button
      type="button"
      tabIndex={-1}
      aria-label={side === "left" ? "Show earlier tabs" : "Show more tabs"}
      onClick={onClick}
      className={cn(
        "absolute top-1.5 size-7 grid place-items-center rounded-full border border-line-strong bg-surface",
        "text-fg-2 hover:text-fg shadow-card p-0",
        side === "left" ? "left-0" : "right-0",
      )}
    >
      <Icon size={15} />
    </button>
  );
}
