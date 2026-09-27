import type { ReactNode } from "react";
import { cn } from "../../lib/cn";

/**
 * The one container on every page. `reportSection` marks it as a top-level section of the
 * printed report (starts on its own page); `id` makes it linkable.
 */
export function Card({ title, description, actions, children, className, bodyClassName, reportSection, id, flush }: {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
  className?: string;
  bodyClassName?: string;
  reportSection?: boolean;
  id?: string;
  /** Body without padding — for tables that run edge to edge. */
  flush?: boolean;
}) {
  return (
    <section
      id={id}
      className={cn(
        "bg-surface border border-line rounded-[var(--radius-card)] shadow-card min-w-0",
        reportSection && "report-section",
        className,
      )}
    >
      {(title || actions) && (
        <header className="flex items-start justify-between gap-4 px-5 pt-4 pb-3">
          <div className="min-w-0">
            {title && <h2 className="text-[15px] font-semibold leading-6 m-0">{title}</h2>}
            {description && <p className="text-[13px] text-fg-muted mt-0.5 mb-0 max-w-3xl leading-5">{description}</p>}
          </div>
          {actions && <div className="flex items-center gap-2 shrink-0 no-print">{actions}</div>}
        </header>
      )}
      <div className={cn("card-body", flush ? "pb-1" : "px-5 pb-5", !title && !actions && !flush && "pt-5", bodyClassName)}>
        {children}
      </div>
    </section>
  );
}

/** A labelled group inside a card (what used to be the small h3 subheadings). */
export function CardSection({ title, description, children, className }: {
  title: ReactNode; description?: ReactNode; children: ReactNode; className?: string;
}) {
  return (
    <div className={cn("card-section mt-6 first:mt-0", className)}>
      <h3 className="text-[13px] font-semibold text-fg m-0">{title}</h3>
      {description && <p className="text-[12px] text-fg-muted mt-0.5 mb-2 max-w-3xl leading-5">{description}</p>}
      <div className={description ? "" : "mt-2"}>{children}</div>
    </div>
  );
}
