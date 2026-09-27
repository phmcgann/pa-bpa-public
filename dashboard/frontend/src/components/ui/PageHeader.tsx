import type { ReactNode } from "react";

/** Title row at the top of every page: optional breadcrumb, title, description, actions. */
export function PageHeader({ breadcrumb, title, description, actions, meta }: {
  breadcrumb?: ReactNode; title: ReactNode; description?: ReactNode; actions?: ReactNode; meta?: ReactNode;
}) {
  return (
    <div className="mb-6">
      {breadcrumb && <div className="text-[13px] text-fg-muted mb-2 no-print">{breadcrumb}</div>}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-[24px] leading-8 font-semibold tracking-tight m-0 break-words">{title}</h1>
          {description && <p className="text-[14px] text-fg-muted mt-1 mb-0 max-w-2xl">{description}</p>}
          {meta}
        </div>
        {actions && <div className="flex items-center gap-2 shrink-0 no-print">{actions}</div>}
      </div>
    </div>
  );
}

export function EmptyState({ icon, title, children, action }: {
  icon?: ReactNode; title: ReactNode; children?: ReactNode; action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center text-center py-14 px-6">
      {icon && <div className="text-fg-faint mb-3">{icon}</div>}
      <div className="text-[15px] font-semibold text-fg">{title}</div>
      {children && <p className="text-[13px] text-fg-muted mt-1 mb-0 max-w-md">{children}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
