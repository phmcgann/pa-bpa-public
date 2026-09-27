import { useCallback, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useScmCatalog } from "../lib/useScmCatalog";
import { cn } from "../lib/cn";

/**
 * "= SCM 95, 96" — the Palo Alto SCM checks a core rule matches. Hovering or focusing shows each
 * check's name and Palo Alto's description, so the numbers mean something without leaving the page.
 */
export function ScmCheckRefs({ ids, className }: { ids: number[]; className?: string }) {
  const catalog = useScmCatalog();
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const anchor = useRef<HTMLSpanElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  const timer = useRef<number | undefined>(undefined);

  const show = useCallback(() => { window.clearTimeout(timer.current); timer.current = window.setTimeout(() => setOpen(true), 120); }, []);
  const hide = useCallback(() => { window.clearTimeout(timer.current); timer.current = window.setTimeout(() => setOpen(false), 100); }, []);

  useLayoutEffect(() => {
    if (!open) return;
    const a = anchor.current?.getBoundingClientRect();
    if (!a) return;
    const w = panel.current?.offsetWidth ?? 360;
    const h = panel.current?.offsetHeight ?? 0;
    const left = Math.max(8, Math.min(a.left, window.innerWidth - w - 8));
    let top = a.bottom + 6;
    if (h && top + h > window.innerHeight - 8 && a.top - h - 6 > 8) top = a.top - h - 6;
    setPos({ top, left });
  }, [open]);

  if (ids.length === 0) return null;
  const label = ids.length > 4 ? `SCM ${ids[0]}–${ids[ids.length - 1]}` : `SCM ${ids.join(", ")}`;

  return (
    <>
      <span
        ref={anchor}
        tabIndex={0}
        onMouseEnter={show}
        onMouseLeave={hide}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
        onKeyDown={(e) => { if (e.key === "Escape") setOpen(false); }}
        aria-describedby={open ? "scm-refs-tip" : undefined}
        className={cn(
          "text-[11px] text-fg-muted underline decoration-dotted underline-offset-2 cursor-help rounded-sm",
          "focus-visible:outline-2 focus-visible:outline-accent",
          className,
        )}
      >
        = {label}
      </span>
      {open && createPortal(
        <div
          ref={panel}
          id="scm-refs-tip"
          role="tooltip"
          onMouseEnter={show}
          onMouseLeave={hide}
          style={{ position: "fixed", top: pos?.top ?? -9999, left: pos?.left ?? -9999, zIndex: 50 }}
          className="animate-in w-[360px] max-w-[calc(100vw-16px)] max-h-[60vh] overflow-y-auto bg-surface border border-line rounded-xl shadow-pop p-3 text-[12px] leading-5 no-print"
        >
          <div className="text-[11px] font-semibold tracking-[0.08em] uppercase text-fg-muted mb-1.5">
            Palo Alto SCM checks for the same setting
          </div>
          <ul className="m-0 p-0 list-none flex flex-col gap-2">
            {ids.map((id) => {
              const c = catalog?.get(id);
              return (
                <li key={id}>
                  <div className="text-fg font-medium">
                    <span className="tab-num text-fg-2 mr-1.5">SCM {id}</span>
                    {c ? c.name : catalog ? "Not in the catalogue" : "Loading…"}
                  </div>
                  {c?.description && <div className="text-fg-muted line-clamp-3">{c.description}</div>}
                </li>
              );
            })}
          </ul>
        </div>,
        document.body,
      )}
    </>
  );
}
