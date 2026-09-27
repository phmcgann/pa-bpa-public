import { ArrowDownRight, ArrowRight, ArrowUpRight } from "lucide-react";
import type { AssessmentDetail, CompareResult, Severity } from "../types";
import { SEVERITY_META } from "../severity";
import { SeverityBadge } from "./ui/Badge";
import { SeverityIcon } from "./ui/SeverityIcon";
import { brand } from "@brand";

const SOURCE: Record<string, string> = {
  tsf_upload: "tech support file",
  panorama_export: "Panorama export",
  file_upload: "configuration export",
  live: "live connection",
};

function day(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" });
}

function countsSentence(counts: Record<Severity, number>): string {
  const parts = (["CRITICAL", "WARNING", "LOW", "INFORMATIONAL"] as Severity[])
    .filter((s) => counts[s] > 0)
    .map((s) => `${counts[s]} ${SEVERITY_META[s].label.toLowerCase()}${s === "WARNING" && counts[s] !== 1 ? "s" : ""}`);
  if (parts.length <= 1) return parts.join("");
  return `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
}

/**
 * One page for a non-technical reader: the verdict, the trend since the last run, the top risks in
 * plain language, and the three pieces of work that would reduce risk the most.
 */
export function ExecutiveSummary({ assessment, changes, onOpenPlan }: {
  assessment: AssessmentDetail;
  changes: CompareResult | null;
  onOpenPlan: () => void;
}) {
  const { summary, data } = assessment;
  const plan = assessment.remediation ?? [];
  const info = data.system_info;
  const name = assessment.hostname || info.hostname || "this firewall";
  const pct = (p: number) => (summary.score ? Math.round((p / summary.score) * 100) : 0);
  const top = plan.slice(0, 5);
  const next = plan.slice(0, 3);
  const nextPoints = next.reduce((n, i) => n + i.points, 0);
  const device = [info.available && info.model, info.available && info.sw_version && `PAN-OS ${info.sw_version}`]
    .filter(Boolean).join(", ");

  return (
    <div className="exec-summary flex flex-col gap-6">
      <section className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center gap-3">
          <span className="text-[13px] font-semibold tracking-[0.08em] uppercase text-fg-muted">Overall risk</span>
          <SeverityBadge severity={summary.risk_label} className="text-[13px] h-6 px-2" />
          <span className="text-[13px] text-fg-muted tab-num">{summary.score} points</span>
        </div>
        <p className="text-[17px] leading-7 text-fg m-0 max-w-3xl">
          {summary.total === 0
            ? <>The assessment of <strong>{name}</strong>{device && ` (${device})`} found no issues.</>
            : <>The assessment of <strong>{name}</strong>{device && ` (${device})`} found {summary.total} issue
                {summary.total === 1 ? "" : "s"}: {countsSentence(summary.severity_counts)}.</>}
          {summary.floor_applied && " Overall risk is rated by the most severe issue found, not only the point total."}
        </p>
        <p className="text-[14px] text-fg-2 m-0 flex items-start gap-1.5">
          {changes ? (
            <>
              {changes.score_delta < 0 ? <ArrowDownRight size={16} className="shrink-0 mt-0.5 text-good-fg" aria-hidden="true" />
                : changes.score_delta > 0 ? <ArrowUpRight size={16} className="shrink-0 mt-0.5 text-critical-fg" aria-hidden="true" />
                : <ArrowRight size={16} className="shrink-0 mt-0.5" aria-hidden="true" />}
              <span className="min-w-0">
                Since the previous assessment on {day(changes.base.uploaded_at)}, the risk score{" "}
                {changes.score_delta === 0 ? "is unchanged" : `went ${changes.score_delta < 0 ? "down" : "up"} ${Math.abs(changes.score_delta)} points`}{" "}
                ({changes.base.summary.score} → {changes.target.summary.score}): {changes.new.length} new issue
                {changes.new.length === 1 ? "" : "s"}, {changes.resolved.length} resolved.
              </span>
            </>
          ) : (
            <span>This is the first assessment of this firewall in the dashboard, so there's no trend yet.</span>
          )}
        </p>
      </section>

      {top.length > 0 && (
        <section>
          <h3 className="text-[13px] font-semibold tracking-[0.08em] uppercase text-fg-muted m-0 mb-3">Top risks</h3>
          <ol className="list-none m-0 p-0 flex flex-col gap-3">
            {top.map((item) => (
              <li key={item.key} className="flex gap-3">
                <SeverityIcon severity={item.severity} size={16} className="mt-0.5 shrink-0" />
                <div className="min-w-0">
                  <p className="text-[14px] text-fg m-0 leading-5">{item.risk}</p>
                  <p className="text-[12px] text-fg-muted m-0 mt-0.5 tab-num">
                    {item.finding_count} issue{item.finding_count === 1 ? "" : "s"} · {pct(item.points)}% of the risk score
                  </p>
                </div>
              </li>
            ))}
          </ol>
        </section>
      )}

      {next.length > 0 && (
        <section>
          <h3 className="text-[13px] font-semibold tracking-[0.08em] uppercase text-fg-muted m-0 mb-3">Recommended next steps</h3>
          <ol className="list-none m-0 p-0 flex flex-col gap-2">
            {next.map((item) => (
              <li key={item.key} className="flex gap-3 items-baseline">
                <span className="shrink-0 w-6 h-6 rounded-full bg-accent-soft text-accent-fg text-[12px] font-semibold tab-num flex items-center justify-center">
                  {item.order}
                </span>
                <span className="text-[14px] text-fg">
                  <strong className="font-semibold">{item.title}</strong>
                  <span className="text-fg-muted tab-num"> — removes {pct(item.points)}% of the risk score</span>
                </span>
              </li>
            ))}
          </ol>
          <p className="text-[14px] text-fg-2 mt-3 mb-0">
            Together these remove about {pct(nextPoints)}% of the risk score.{" "}
            {plan.length > next.length && <>The full remediation plan has {plan.length} work items.</>}{" "}
            <button type="button" onClick={onOpenPlan} className="no-print text-accent-fg hover:underline bg-transparent border-0 p-0">
              Open the remediation plan
            </button>
          </p>
        </section>
      )}

      <p className="text-[12px] text-fg-muted m-0 border-t border-divider pt-3">
        Based on a {SOURCE[assessment.source] ?? "configuration"} ({assessment.filename}) from {day(assessment.uploaded_at)},
        checked against the {brand.ruleSet} rules
        {assessment.scm.run?.status === "completed" && " and Palo Alto Networks' Strata Cloud Manager BPA"}.
        Issues dismissed as accepted risk aren't counted.
      </p>
    </div>
  );
}
