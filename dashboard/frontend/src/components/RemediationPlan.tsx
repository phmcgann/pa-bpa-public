import type { Finding, RemediationItem } from "../types";
import { CliButton } from "./CliPanel";
import { NoteButton, NoteRef } from "./Notes";
import { Badge, SeverityBadge } from "./ui/Badge";
import { SeverityIcon } from "./ui/SeverityIcon";
import { Callout } from "./ui/Callout";

/**
 * The scored findings grouped into work items, most urgent first. Each item shows what it resolves:
 * findings, and the risk points it would take off the score.
 */
export function RemediationPlan({ items, totalPoints, findings, cliUnavailable }: {
  items: RemediationItem[];
  totalPoints: number;
  findings: Finding[];
  /** Set when commands can't be offered (e.g. a Panorama-managed firewall): shown instead of Copy CLI. */
  cliUnavailable?: string | null;
}) {
  const byKey = new Map(findings.map((f) => [f.finding_key, f]));
  if (items.length === 0) {
    return <p className="text-[13px] text-fg-2 m-0">No scored findings, so there's nothing to remediate.</p>;
  }
  const issueCount = items.reduce((n, i) => n + i.finding_count, 0);
  const firstThree = items.slice(0, 3).reduce((n, i) => n + i.points, 0);
  const pct = (p: number) => (totalPoints ? Math.round((p / totalPoints) * 100) : 0);

  return (
    <div className="remediation-plan flex flex-col gap-4">
      <p className="text-[13px] text-fg-2 m-0 max-w-3xl">
        {items.length} work item{items.length === 1 ? "" : "s"} cover all {issueCount} scored findings, ordered by the
        most severe finding each resolves, then by the risk points it removes.
        {items.length > 3 && <> The first three remove {firstThree} of {totalPoints} points ({pct(firstThree)}%).</>}
      </p>
      {cliUnavailable && <Callout className="no-print max-w-3xl" title="No CLI commands for this firewall.">{cliUnavailable}</Callout>}
      <ol className="list-none m-0 p-0 flex flex-col">
        {items.map((item) => (
          <li key={item.key} className="keep-together border-t border-divider first:border-t-0 py-4 flex gap-4">
            <div className="shrink-0 w-8 h-8 rounded-full bg-surface-3 text-fg font-semibold tab-num flex items-center justify-center text-[14px]">
              {item.order}
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                <h3 className="text-[15px] font-semibold m-0">
                  {item.title}<NoteRef kind="remediation" targetKey={item.key} />
                </h3>
                <SeverityBadge severity={item.severity} />
                <span className="ml-auto inline-flex items-center gap-1">
                  <NoteButton kind="remediation" targetKey={item.key} label={item.title} />
                  <ItemCli item={item} byKey={byKey} />
                </span>
              </div>
              <p className="text-[13px] text-fg-2 mt-1 mb-2 max-w-3xl leading-5">{item.summary}</p>
              <p className="text-[12px] text-fg-muted m-0 mb-2 tab-num">
                Resolves {item.finding_count} finding{item.finding_count === 1 ? "" : "s"} · {item.points} of{" "}
                {totalPoints} risk points ({pct(item.points)}%)
              </p>
              <ul className="list-none m-0 p-0 grid gap-x-6 gap-y-1 text-[12px] sm:grid-cols-2 print:grid-cols-2">
                {item.checks.map((c) => (
                  <li key={c.rule_id} className="flex gap-1.5 min-w-0">
                    <SeverityIcon severity={c.severity} size={12} className="mt-0.5 shrink-0" />
                    <span className="text-fg-2 min-w-0">
                      {c.title}
                      {c.count > 1 && <span className="text-fg-muted tab-num"> ×{c.count}</span>}
                      {c.program === "scm" && <Badge tone="outline" className="ml-1.5">Palo Alto SCM</Badge>}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}

/** Every command for the item's findings, as one batch. */
function ItemCli({ item, byKey }: { item: RemediationItem; byKey: Map<string, Finding> }) {
  const entries = item.finding_keys.map((k) => byKey.get(k)?.cli).filter((c): c is NonNullable<typeof c> => !!c);
  if (entries.length === 0) return null;
  const rest = item.finding_count - entries.length;
  return (
    <span>
      <CliButton
        entries={entries}
        title={item.title}
        label={`Copy CLI (${entries.length} of ${item.finding_count})`}
        variant="secondary"
        extra={rest > 0 ? `Commands cover ${entries.length} of the ${item.finding_count} issues; the other ${rest} need a judgement call, so follow their recommendations.` : undefined}
      />
    </span>
  );
}
