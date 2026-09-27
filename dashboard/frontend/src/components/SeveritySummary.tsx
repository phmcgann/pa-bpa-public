import { HelpCircle } from "lucide-react";
import { cn } from "../lib/cn";
import { Link } from "react-router-dom";
import { SEVERITY_META, SEVERITY_ORDER, severityLabel } from "../severity";
import type { Severity, Summary } from "../types";
import { SeverityBadge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { Popover } from "./ui/Popover";
import { SeverityIcon } from "./ui/SeverityIcon";
import { Stat } from "./ui/Stat";

function ScoringExplainer({ summary }: { summary: Summary }) {
  return (
    <div className="p-2 text-[13px] leading-5">
      <div className="font-semibold text-fg mb-1">How the score works</div>
      <p className="text-fg-2 m-0 mb-2">
        Score = Σ (active findings × severity weight). The overall risk is then floored at the worst active
        finding, so a single Critical finding can never read as a lower risk. Weights and thresholds are
        editable in <Link to="/settings">Settings</Link>.
      </p>
      {summary.floor_applied && (
        <p className="text-fg-2 m-0 mb-2">
          Points alone would read <strong>{severityLabel(summary.points_based_label)}</strong>; raised to{" "}
          <strong>{severityLabel(summary.risk_label)}</strong> by the severity floor.
        </p>
      )}
      <table className="text-[12px]">
        <thead><tr><th className="pl-0">Severity</th><th>Count</th><th>Weight</th><th className="text-right pr-0">Points</th></tr></thead>
        <tbody>
          {SEVERITY_ORDER.map((sev) => {
            const b = summary.score_breakdown[sev];
            return (
              <tr key={sev}>
                <td className="pl-0 py-1.5"><span className="inline-flex items-center gap-1.5"><SeverityIcon severity={sev} size={12} />{severityLabel(sev)}</span></td>
                <td className="py-1.5">{b.count}</td>
                <td className="py-1.5">× {b.weight}</td>
                <td className="py-1.5 text-right pr-0">{b.points}</td>
              </tr>
            );
          })}
          <tr><td colSpan={3} className="pl-0 py-1.5 font-semibold">Total</td><td className="py-1.5 text-right pr-0 font-semibold">{summary.score}</td></tr>
        </tbody>
      </table>
      <div className="text-[12px] text-fg-muted mt-2">
        Informational ≤ {summary.thresholds.informational_max} · Low ≤ {summary.thresholds.low_max} · Warning ≤{" "}
        {summary.thresholds.warning_max} · above that is Critical
      </div>
    </div>
  );
}

/** Overall risk plus one tile per severity; a tile filters the findings to that severity. */
export function SeveritySummary({ summary, activeSeverityFilter, onSeverityClick }: {
  summary: Summary;
  activeSeverityFilter?: Severity | "ALL";
  onSeverityClick?: (severity: Severity | "ALL") => void;
}) {
  const filtered = !!activeSeverityFilter && activeSeverityFilter !== "ALL";
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-3">
      <div
        className={cn(
          "col-span-2 md:col-span-3 xl:col-span-1 bg-surface border rounded-[var(--radius-card)] shadow-card px-4 py-3.5",
          filtered ? "border-line hover:border-line-strong cursor-pointer" : "border-line",
        )}
        onClick={filtered && onSeverityClick ? (e) => {
          // The help button inside opens its own popover.
          if (!(e.target as HTMLElement).closest("button")) onSeverityClick("ALL");
        } : undefined}
        title={filtered ? "Show all findings" : undefined}
      >
        <div className="flex items-center justify-between">
          <span className="text-[12px] font-medium text-fg-muted">Overall risk</span>
          <Popover
            align="end"
            width={340}
            trigger={({ toggle, ref, open }) => (
              <Button ref={ref as (el: HTMLButtonElement | null) => void} variant="ghost" size="sm" iconOnly
                aria-label="How the score works" aria-expanded={open} onClick={toggle} className="-mr-1.5 -mt-1">
                <HelpCircle size={15} />
              </Button>
            )}
          >
            {() => <ScoringExplainer summary={summary} />}
          </Popover>
        </div>
        <div className="flex items-baseline gap-2 mt-1.5">
          <span className="tab-num text-[26px] font-semibold leading-8 tracking-tight">{summary.score}</span>
          <span className="text-[12px] text-fg-muted">points</span>
        </div>
        <div className="flex items-center gap-2 mt-1">
          <SeverityBadge severity={summary.risk_label} />
          <span className="text-[12px] text-fg-muted tab-num">{summary.total} active findings</span>
        </div>
      </div>
      {SEVERITY_ORDER.map((sev) => {
        const b = summary.score_breakdown[sev];
        return (
          <Stat
            key={sev}
            label={SEVERITY_META[sev].label}
            icon={<SeverityIcon severity={sev} size={13} />}
            value={summary.severity_counts[sev]}
            sub={`× ${b.weight} pts = ${b.points}`}
            active={activeSeverityFilter === sev}
            onClick={onSeverityClick ? () => onSeverityClick(sev) : undefined}
          />
        );
      })}
    </div>
  );
}
