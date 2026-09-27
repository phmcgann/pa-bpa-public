import type { ReactNode } from "react";
import { Card } from "./ui/Card";

/**
 * A top-level report section: a Card that starts a new page when printed.
 * `bare` skips the scroll wrapper, for content that brings its own edge-to-edge table.
 * (`group` is accepted for older call sites and no longer shown.)
 */
export function SectionCard({ title, children, note, className, actions, id, bare }: {
  title: string; children: ReactNode; note?: string; className?: string; group?: string; actions?: ReactNode; id?: string;
  bare?: boolean;
}) {
  return (
    <Card title={title} description={note} actions={actions} className={className} reportSection id={id}>
      {bare ? children : <div className="table-scroll">{children}</div>}
    </Card>
  );
}
