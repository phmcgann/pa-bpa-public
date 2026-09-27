import { ArrowRight, ArrowDown, ArrowUp } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { Badge, SeverityBadge } from "./ui/Badge";
import { Callout } from "./ui/Callout";
import { Card } from "./ui/Card";
import { Tabs } from "./ui/Tabs";
import { cn } from "../lib/cn";
import { SEVERITY_ORDER, severityLabel } from "../severity";
import type { CompareResult, CompareSide, Finding } from "../types";
import { brand } from "@brand";

function when(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

/** A signed point change: fewer points (better) reads green, more (worse) reads red. */
function Delta({ value, className }: { value: number; className?: string }) {
  if (value === 0) return <span className={cn("text-fg-muted tab-num", className)}>0</span>;
  const better = value < 0;
  return (
    <span className={cn("tab-num font-medium inline-flex items-center gap-0.5", better ? "text-good-fg" : "text-critical-fg", className)}>
      {better ? <ArrowDown size={13} aria-hidden="true" /> : <ArrowUp size={13} aria-hidden="true" />}
      {better ? "−" : "+"}{Math.abs(value)}
      <span className="sr-only">{better ? " points fewer" : " points more"}</span>
    </span>
  );
}

function SideCard({ side, label }: { side: CompareSide; label: string }) {
  const s = side.summary;
  return (
    <Card className="flex-1 min-w-0">
      <div className="text-[11px] font-semibold tracking-[0.08em] uppercase text-fg-muted">{label}</div>
      <Link to={`/assessments/${side.id}`} className="block mt-1 font-semibold text-fg hover:underline truncate">
        {side.hostname || side.filename}
      </Link>
      <div className="text-[12px] text-fg-muted truncate">{when(side.uploaded_at)} · {side.filename}</div>
      <div className="flex items-baseline gap-2 mt-3">
        <span className="text-[28px] font-semibold tab-num leading-none">{s.score}</span>
        <span className="text-fg-muted text-[13px]">points</span>
        <SeverityBadge severity={s.risk_label} className="ml-1" />
      </div>
      <div className="flex flex-wrap gap-x-3 gap-y-1 mt-3 text-[12px] text-fg-muted tab-num">
        {SEVERITY_ORDER.map((sev) => (
          <span key={sev}><strong className="text-fg font-semibold">{s.severity_counts[sev]}</strong> {severityLabel(sev)}</span>
        ))}
      </div>
      <div className="text-[12px] text-fg-muted mt-2 tab-num">
        {brand.ruleSet} {side.points_by_program.core} pts
        {side.scm_run ? ` · Palo Alto SCM ${side.points_by_program.scm} pts` : " · no Palo Alto SCM run"}
      </div>
    </Card>
  );
}

function Source({ f }: { f: Finding }) {
  return f.program === "scm"
    ? <Badge tone="neutral">PAN SCM {f.scm_check_ids[0]}</Badge>
    : <Badge tone="accent">{brand.ruleSet}</Badge>;
}

function FindingTable({ findings, empty }: { findings: Finding[]; empty: string }) {
  if (findings.length === 0) return <p className="text-[13px] text-fg-muted px-5 py-6 m-0">{empty}</p>;
  return (
    <div className="table-scroll">
      <table className="min-w-[760px] compare-findings-table">
        <thead><tr><th className="pl-5 w-[120px]">Severity</th><th>Finding</th><th className="w-[160px]">Category</th><th className="w-[140px]">Source</th></tr></thead>
        <tbody>
          {findings.map((f) => (
            <tr key={f.finding_key}>
              <td className="pl-5 align-top"><SeverityBadge severity={f.severity} /></td>
              <td className="align-top">
                <div className="font-medium text-fg leading-5">{f.title}</div>
                <div className="text-[12px] text-fg-muted leading-5">{f.message}</div>
              </td>
              <td className="align-top text-fg-2">{f.category}</td>
              <td className="align-top"><Source f={f} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Print-only heading for a list that shows as a tab on screen. */
function PrintListHeading({ children }: { children: string }) {
  return <h3 className="print-only text-[14px] font-semibold m-0 px-5 pt-4 pb-1">{children}</h3>;
}

/**
 * Two assessments side by side: the score change, which checks account for it, and every finding
 * that appeared, disappeared or changed. On screen the three finding lists are tabs; on paper they
 * print one after another.
 */
export function CompareView({ result: r }: { result: CompareResult }) {
  const [tab, setTab] = useState("new");
  const changedFindings = r.changed.map((c) => c.finding);
  const pane = (id: string) => (tab === id ? "" : "hidden print:block");
  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-col md:flex-row print:flex-row items-stretch gap-3 keep-together">
        <SideCard side={r.base} label="Earlier" />
        <div className="flex md:flex-col print:flex-col items-center justify-center gap-2 px-2 shrink-0">
          <ArrowRight size={18} className="text-fg-muted hidden md:block print:block" aria-hidden="true" />
          <div className="text-center">
            <Delta value={r.score_delta} className="text-[22px]" />
            <div className="text-[12px] text-fg-muted">points</div>
          </div>
        </div>
        <SideCard side={r.target} label="Later" />
      </div>

      {r.notes.length > 0 && (
        <Callout tone="warning" className="keep-together" title="Not everything here is a configuration change">
          <ul className="m-0 pl-4 flex flex-col gap-1">
            {r.notes.map((n) => <li key={n.kind + n.text}>{n.text}</li>)}
          </ul>
        </Callout>
      )}

      <Card flush reportSection title="What moved the score" description="Every check whose scored findings changed, largest point change first.">
        {r.by_rule.length === 0 ? (
          <p className="text-[13px] text-fg-muted px-5 py-6 m-0">No check's scored findings changed.</p>
        ) : (
          <div className="table-scroll">
            <table className="min-w-[760px] compare-rules-table">
              <thead>
                <tr>
                  <th className="pl-5">Check</th><th className="w-[140px]">Source</th>
                  <th className="w-[110px] text-right">Earlier</th><th className="w-[110px] text-right">Later</th>
                  <th className="w-[110px] text-right pr-5">Change</th>
                </tr>
              </thead>
              <tbody>
                {r.by_rule.map((x) => (
                  <tr key={x.rule_id}>
                    <td className="pl-5">
                      <div className="font-medium text-fg leading-5">{x.title}</div>
                      <div className="text-[12px] text-fg-muted leading-5">{x.category}</div>
                    </td>
                    <td>{x.program === "scm" ? <Badge tone="neutral">PAN SCM</Badge> : <Badge tone="accent">{brand.ruleSet}</Badge>}</td>
                    <td className="text-right tab-num text-fg-2">{x.base_count} · {x.base_points} pts</td>
                    <td className="text-right tab-num text-fg-2">{x.target_count} · {x.target_points} pts</td>
                    <td className="text-right pr-5"><Delta value={x.target_points - x.base_points} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card flush reportSection>
        <Tabs
          className="px-5"
          value={tab}
          onChange={setTab}
          tabs={[
            { id: "new", label: "New findings", count: r.new.length },
            { id: "resolved", label: "Resolved", count: r.resolved.length },
            { id: "changed", label: "Changed", count: r.changed.length },
          ]}
        />
        <div className={pane("new")}>
          <PrintListHeading>{`New findings (${r.new.length})`}</PrintListHeading>
          <FindingTable findings={r.new} empty="No findings appeared in the later assessment." />
        </div>
        <div className={pane("resolved")}>
          <PrintListHeading>{`Resolved findings (${r.resolved.length})`}</PrintListHeading>
          <FindingTable findings={r.resolved} empty="No findings were resolved." />
        </div>
        <div className={pane("changed")}>
          <PrintListHeading>{`Changed findings (${r.changed.length})`}</PrintListHeading>
          {r.changed.length === 0 ? <FindingTable findings={changedFindings} empty="No findings changed severity or scoring." /> : (
            <div className="table-scroll">
              <table className="min-w-[760px] compare-changed-table">
                <thead><tr><th className="pl-5">Finding</th><th className="w-[320px]">Change</th></tr></thead>
                <tbody>
                  {r.changed.map((c) => (
                    <tr key={c.finding.finding_key}>
                      <td className="pl-5 align-top">
                        <div className="font-medium text-fg leading-5">{c.finding.title}</div>
                        <div className="text-[12px] text-fg-muted leading-5">{c.finding.message}</div>
                      </td>
                      <td className="align-top">
                        <div className="flex items-center gap-2 flex-wrap">
                          <SeverityBadge severity={c.before.severity} />
                          {!c.before.counted && <span className="text-[12px] text-fg-muted">{c.before.dismissed ? "dismissed" : "not scored"}</span>}
                          <ArrowRight size={13} className="text-fg-muted" aria-hidden="true" />
                          <SeverityBadge severity={c.after.severity} />
                          {!c.after.counted && <span className="text-[12px] text-fg-muted">{c.after.dismissed ? "dismissed" : "not scored"}</span>}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}
