import { ChevronRight } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { cn } from "../../lib/cn";

/**
 * A collapsible group with a title row. `openFor` opens it whenever that value changes to a
 * non-empty one (e.g. the active search/filter), and closes it again when it goes back to empty —
 * but the user can still collapse or expand it in between.
 */
export function Disclosure({ title, meta, children, defaultOpen = false, openFor }: {
  title: ReactNode; meta?: ReactNode; children: ReactNode; defaultOpen?: boolean; openFor?: string;
}) {
  const [open, setOpen] = useState(defaultOpen || !!openFor);
  useEffect(() => {
    if (openFor !== undefined) setOpen(openFor ? true : defaultOpen);
  }, [openFor, defaultOpen]);
  return (
    <div className="border-t border-divider first:border-t-0">
      <button
        type="button"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-2 py-3 text-left bg-transparent border-0 group"
      >
        <ChevronRight
          size={15}
          className={cn("text-fg-muted transition-transform duration-150 shrink-0", open && "rotate-90")}
          aria-hidden="true"
        />
        <span className="text-[13px] font-semibold text-fg group-hover:text-fg">{title}</span>
        {meta && <span className="ml-auto text-[12px] text-fg-muted tab-num">{meta}</span>}
      </button>
      {open && <div className="pb-2 pl-6">{children}</div>}
    </div>
  );
}
