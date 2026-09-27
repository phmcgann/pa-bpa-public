import type { Finding, Severity } from "./types";
import { brand } from "@brand";

export type ProgramFilter = "ALL" | "core" | "scm";

/** Everything that narrows the findings list, held by the page so printing can say what it prints. */
export interface FindingsView {
  severity: Severity | "ALL";
  category: string;
  program: ProgramFilter;
  query: string;
  showDismissed: boolean;
  showDisabledRule: boolean;
}

export const DEFAULT_VIEW: FindingsView = {
  severity: "ALL", category: "ALL", program: "ALL", query: "", showDismissed: false, showDisabledRule: false,
};

const PROGRAM_LABEL = { core: `${brand.ruleSet} only`, scm: "Palo Alto SCM only" };
const SEVERITY_LABEL: Record<Severity, string> = {
  CRITICAL: "Critical", WARNING: "Warning", LOW: "Low", INFORMATIONAL: "Informational",
};

export function filterFindings(findings: Finding[], v: FindingsView): Finding[] {
  const q = v.query.trim().toLowerCase();
  return findings.filter((f) => {
    if (!v.showDismissed && f.dismissed) return false;
    if (!v.showDisabledRule && f.rule_disabled) return false;
    if (v.severity !== "ALL" && f.severity !== v.severity) return false;
    if (v.category !== "ALL" && f.category !== v.category) return false;
    if (v.program !== "ALL" && f.program !== v.program) return false;
    if (q && ![f.title, f.message, f.recommendation, f.category].some((x) => x.toLowerCase().includes(q))) return false;
    return true;
  });
}

/** The filters that narrow the list, in words ("Critical", "Category: VPN"); empty when showing everything. */
export function describeView(v: FindingsView): string[] {
  return [
    v.severity !== "ALL" && `${SEVERITY_LABEL[v.severity]} only`,
    v.category !== "ALL" && `Category: ${v.category}`,
    v.program !== "ALL" && PROGRAM_LABEL[v.program],
    v.query.trim() && `Search: "${v.query.trim()}"`,
  ].filter((x): x is string => !!x);
}

/** Findings a default view lists: everything but dismissed ones and ones on disabled rules. */
export function listedByDefault(findings: Finding[]): number {
  return findings.filter((f) => !f.dismissed && !f.rule_disabled).length;
}
