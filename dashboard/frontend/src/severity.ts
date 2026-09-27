import type { Severity } from "./types";

export const SEVERITY_ORDER: Severity[] = ["CRITICAL", "WARNING", "LOW", "INFORMATIONAL"];

/**
 * `color` is the fill (marks, dots, bars); `text` is the same hue stepped for legible text.
 * `icon` is a text glyph for places that can't render an SVG icon (print cover, native options).
 * Informational is neutral gray: it's "for the record", not "good".
 */
export const SEVERITY_META: Record<Severity, { label: string; icon: string; color: string; text: string }> = {
  CRITICAL: { label: "Critical", icon: "✖", color: "var(--sev-critical)", text: "var(--sev-critical-text)" },
  WARNING: { label: "Warning", icon: "▲", color: "var(--sev-warning)", text: "var(--sev-warning-text)" },
  LOW: { label: "Low", icon: "●", color: "var(--sev-low)", text: "var(--sev-low-text)" },
  INFORMATIONAL: { label: "Informational", icon: "○", color: "var(--sev-info)", text: "var(--sev-info-text)" },
};

/** Display label for a severity code ("INFORMATIONAL" -> "Informational"). */
export function severityLabel(sev: Severity): string {
  return SEVERITY_META[sev].label;
}
