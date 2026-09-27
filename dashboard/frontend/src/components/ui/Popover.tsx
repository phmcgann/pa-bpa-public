import { useCallback, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { cn } from "../../lib/cn";

/**
 * Anchored floating panel. Rendered in a portal with fixed positioning so scrolling tables and
 * cards can't clip it. Closes on outside click, Escape, or `close()` from the render prop.
 */
export function Popover({ trigger, children, align = "start", width, className }: {
  trigger: (props: { open: boolean; toggle: () => void; ref: (el: HTMLElement | null) => void }) => ReactNode;
  children: (close: () => void) => ReactNode;
  align?: "start" | "end";
  width?: number;
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const anchorRef = useRef<HTMLElement | null>(null);
  const panelRef = useRef<HTMLDivElement | null>(null);

  const close = useCallback(() => setOpen(false), []);
  const toggle = useCallback(() => setOpen((o) => !o), []);
  const setAnchor = useCallback((el: HTMLElement | null) => { anchorRef.current = el; }, []);

  const place = useCallback(() => {
    const a = anchorRef.current?.getBoundingClientRect();
    if (!a) return;
    const w = panelRef.current?.offsetWidth ?? width ?? 240;
    const h = panelRef.current?.offsetHeight ?? 0;
    let left = align === "end" ? a.right - w : a.left;
    left = Math.max(8, Math.min(left, window.innerWidth - w - 8));
    let top = a.bottom + 6;
    if (h && top + h > window.innerHeight - 8) {
      // Flip above the anchor when it fits there; otherwise slide up as far as needed to stay on screen.
      top = a.top - h - 6 > 8 ? a.top - h - 6 : Math.max(8, window.innerHeight - h - 8);
    }
    setPos({ top, left });
  }, [align, width]);

  useLayoutEffect(() => { if (open) place(); }, [open, place]);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node;
      if (panelRef.current?.contains(t) || anchorRef.current?.contains(t)) return;
      setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") { setOpen(false); anchorRef.current?.focus(); } };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    window.addEventListener("resize", place);
    window.addEventListener("scroll", place, true);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
      window.removeEventListener("resize", place);
      window.removeEventListener("scroll", place, true);
    };
  }, [open, place]);

  return (
    <>
      {trigger({ open, toggle, ref: setAnchor })}
      {open && createPortal(
        <div
          ref={panelRef}
          role="dialog"
          onClick={(e) => e.stopPropagation()}
          style={{ position: "fixed", top: pos?.top ?? -9999, left: pos?.left ?? -9999, width, zIndex: 50 }}
          className={cn("animate-in bg-surface border border-line rounded-xl shadow-pop p-1.5 text-[13px]", className)}
        >
          {children(close)}
        </div>,
        document.body,
      )}
    </>
  );
}

/** A row inside a Popover used as a menu. */
export function MenuItem({ children, onSelect, active, danger, icon }: {
  children: ReactNode; onSelect: () => void; active?: boolean; danger?: boolean; icon?: ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        "w-full flex items-center gap-2 text-left px-2.5 h-8 rounded-md text-[13px] border-0 bg-transparent",
        "hover:bg-surface-3 focus-visible:bg-surface-3",
        active && "bg-surface-2 font-medium",
        danger ? "text-critical-fg" : "text-fg",
      )}
    >
      {icon && <span className="text-fg-muted shrink-0 flex">{icon}</span>}
      <span className="truncate">{children}</span>
    </button>
  );
}
