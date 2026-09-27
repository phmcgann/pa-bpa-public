import { CircleDot, Info, OctagonX, TriangleAlert } from "lucide-react";
import { SEVERITY_META } from "../../severity";
import type { Severity } from "../../types";

const ICONS = { CRITICAL: OctagonX, WARNING: TriangleAlert, LOW: CircleDot, INFORMATIONAL: Info } as const;

/** Severity shape + color; always paired with a label somewhere nearby, never color alone. */
export function SeverityIcon({ severity, size = 14, className }: { severity: Severity; size?: number; className?: string }) {
  const Icon = ICONS[severity];
  return <Icon size={size} strokeWidth={2.25} color={SEVERITY_META[severity].color} aria-hidden="true" className={className} />;
}
