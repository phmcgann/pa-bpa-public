import { EyeOff, RotateCcw, Search, X } from "lucide-react";
import { useMemo } from "react";
import { CliButton } from "./CliPanel";
import { NoteButton, NoteRef } from "./Notes";
import { BASIS_LABEL } from "../ruleBasis";
import { describeView, filterFindings, listedByDefault, type FindingsView, type ProgramFilter } from "../findingsView";
import type { Finding, Severity } from "../types";
import { Badge, SeverityBadge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { cn } from "../lib/cn";
import { ScmCheckRefs } from "./ScmCheckRefs";
import { brand } from "@brand";

const SEVERITY_RANK: Record<Severity, number> = { CRITICAL: 0, WARNING: 1, LOW: 2, INFORMATIONAL: 3 };

export function SourceBadge({ finding }: { finding: Finding }) {
  if (finding.program === "scm") {
    return (
      <Badge tone="neutral" title={finding.source_ref ?? undefined}>PAN SCM {finding.scm_check_ids[0]}</Badge>
    );
  }
  const basis = finding.source_type === "scm" ? null : BASIS_LABEL[finding.source_type];
  return (
    <div className="flex flex-col items-start gap-1">
      <Badge tone="accent" title={finding.source_ref ?? undefined}>
        <span className="whitespace-nowrap">{brand.ruleSet}</span>
        {basis && <span className="whitespace-nowrap">· {basis}</span>}
      </Badge>
      <ScmCheckRefs ids={finding.scm_check_ids} />
    </div>
  );
}

export function FindingsTable({ findings, view, onViewChange, onDismiss, onUndismiss }: {
  findings: Finding[];
  view: FindingsView;
  onViewChange: (view: FindingsView) => void;
  onDismiss: (key: string, reason?: string) => void;
  onUndismiss: (key: string) => void;
}) {
  const { severity: severityFilter, category: categoryFilter, program: programFilter, query, showDismissed,
    showDisabledRule } = view;
  const set = (patch: Partial<FindingsView>) => onViewChange({ ...view, ...patch });
  const hasScm = findings.some((f) => f.program === "scm");
  const coreTitles = useMemo(
    () => new Map(findings.filter((f) => f.program === "core").map((f) => [f.rule_id, f.title])),
    [findings]
  );

  const categories = useMemo(
    () => Array.from(new Set(findings.map((f) => f.category))).sort(),
    [findings]
  );

  const rows = filterFindings(findings, view)
    .sort((a, b) => {
      const sevDiff = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
      if (sevDiff !== 0) return sevDiff;
      const catDiff = a.category.localeCompare(b.category);
      if (catDiff !== 0) return catDiff;
      return a.message.localeCompare(b.message);
    });

  const dupCount = rows.filter((f) => f.not_scored_reason === "duplicate").length;
  const narrowedBy = describeView(view);
  const filtered = narrowedBy.length > 0;
  const total = listedByDefault(findings);

  return (
    <div>
      <div className="no-print flex flex-wrap items-center gap-2 mb-4">
        <div className="relative">
          <Search size={15} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-fg-faint pointer-events-none" aria-hidden="true" />
          <input
            type="search"
            value={query}
            onChange={(e) => set({ query: e.target.value })}
            placeholder="Search findings…"
            aria-label="Search findings"
            className="w-56 pl-8"
          />
        </div>
        <select value={severityFilter} onChange={(e) => set({ severity: e.target.value as Severity | "ALL" })} aria-label="Severity">
          <option value="ALL">All severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="WARNING">Warning</option>
          <option value="LOW">Low</option>
          <option value="INFORMATIONAL">Informational</option>
        </select>
        <select value={categoryFilter} onChange={(e) => set({ category: e.target.value })} aria-label="Category">
          <option value="ALL">All categories</option>
          {categories.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        {hasScm && (
          <select value={programFilter} onChange={(e) => set({ program: e.target.value as ProgramFilter })} aria-label="Source">
            <option value="ALL">{brand.ruleSet} + Palo Alto SCM</option>
            <option value="core">{brand.ruleSet} only</option>
            <option value="scm">Palo Alto SCM only</option>
          </select>
        )}
        {filtered && (
          <Button
            variant="ghost"
            onClick={() => set({ severity: "ALL", category: "ALL", program: "ALL", query: "" })}
          >
            <X size={14} />Clear
          </Button>
        )}
        <div className="flex items-center gap-4 ml-auto text-[13px] text-fg-2">
          <label className="inline-flex items-center gap-1.5 cursor-pointer">
            <input type="checkbox" checked={showDismissed} onChange={(e) => set({ showDismissed: e.target.checked })} />
            Dismissed
          </label>
          <label className="inline-flex items-center gap-1.5 cursor-pointer">
            <input type="checkbox" checked={showDisabledRule} onChange={(e) => set({ showDisabledRule: e.target.checked })} />
            On disabled rules
          </label>
          <span className="text-fg-muted tab-num">{rows.length} shown</span>
        </div>
      </div>

      {filtered && (
        <div className="print-only print-filter-note mb-3">
          <strong>Filtered view:</strong> {narrowedBy.join(" · ")}. Showing {rows.length} of {total} findings;
          the rest are left out of this report.
        </div>
      )}
      {dupCount > 0 && (
        <p className="print-only text-[11px] text-fg-muted m-0 mb-2">
          {dupCount} Palo Alto SCM finding{dupCount === 1 ? "" : "s"} that repeat a {brand.ruleSet} finding are listed in the
          Palo Alto SCM section instead.
        </p>
      )}
      <div className="table-scroll -mx-5">
        <table className="findings-table min-w-[860px]">
          <thead>
            <tr>
              <th className="pl-5 w-[118px]">Severity</th>
              <th>Finding</th>
              <th className="w-[140px]">Category</th>
              <th>Recommendation</th>
              <th className="w-[130px]">Source</th>
              <th className="w-[210px] pr-5 no-print" aria-label="Actions" />
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => (
              <tr
                key={f.finding_key}
                className={cn(
                  f.dismissed || f.rule_disabled ? "opacity-50" : f.not_scored_reason ? "opacity-75" : undefined,
                  f.not_scored_reason === "duplicate" && "print-dup",
                )}
              >
                <td className="pl-5">
                  <div className="flex flex-col items-start gap-1">
                    <SeverityBadge severity={f.severity} />
                    {f.severity_overridden && (
                      <span className="text-[11px] text-fg-muted" title={`Recategorized in Settings — default is ${f.default_severity}`}>Recategorized</span>
                    )}
                  </div>
                </td>
                <td className="min-w-[260px]">
                  <div className="font-medium text-fg leading-5">
                    {f.title}<NoteRef kind="finding" targetKey={f.finding_key} />
                  </div>
                  <div className="text-[12px] text-fg-2 leading-5 mt-0.5 break-words">{f.message}</div>
                  {f.not_scored_reason === "duplicate" && (
                    <div className="text-[11px] text-fg-muted mt-1">
                      Not scored twice — already covered by {brand.ruleSet}: {f.duplicate_of?.map((id) => coreTitles.get(id) ?? id).join("; ")}
                    </div>
                  )}
                  {f.not_scored_reason === "scm_excluded" && (
                    <div className="text-[11px] text-fg-muted mt-1">Not scored — Palo Alto SCM findings are excluded from the score in Settings</div>
                  )}
                  {f.rule_disabled && <div className="text-[11px] text-fg-muted mt-1">Excluded from the score — the rule is disabled in the config</div>}
                </td>
                <td className="text-[12px] text-fg-2">{f.category}</td>
                <td className="text-[12px] text-fg-2 leading-5 min-w-[240px]">{f.recommendation}</td>
                <td><SourceBadge finding={f} /></td>
                <td className="pr-5 text-right no-print">
                  <div className="inline-flex items-center gap-1">
                  <NoteButton kind="finding" targetKey={f.finding_key} label={`${f.title.replace(/\.$/, "")} — ${f.message}`.slice(0, 500)} />
                  {f.cli && !f.dismissed && !f.rule_disabled && (
                    <CliButton entries={[f.cli]} title={f.title} />
                  )}
                  {f.rule_disabled ? null : f.dismissed ? (
                    <Button size="sm" variant="ghost" onClick={() => onUndismiss(f.finding_key)}><RotateCcw size={13} />Restore</Button>
                  ) : (
                    <Button size="sm" variant="ghost" onClick={() => onDismiss(f.finding_key)} title="Accept this finding: hide it and exclude it from the score">
                      <EyeOff size={13} />Dismiss
                    </Button>
                  )}
                  </div>
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={6} className="text-center text-fg-muted py-10">No findings match these filters.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
