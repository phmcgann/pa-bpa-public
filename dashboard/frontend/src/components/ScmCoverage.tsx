import { Check, Copy } from "lucide-react";
import { useState } from "react";
import type { ScmCoverage as Coverage, ScmCoverageStatus } from "../types";
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { brand } from "@brand";

const STATUS: Record<ScmCoverageStatus, { label: string; tone: "critical" | "warning" | "neutral" | "good" | "info"; help: string }> = {
  core_missed: { label: `${brand.ruleSetShort} missed it`, tone: "critical", help: `A linked ${brand.ruleSetShort} rule is on but found nothing that SCM flagged.` },
  object_mismatch: { label: "Different objects", tone: "warning", help: `A linked ${brand.ruleSetShort} rule fired, but not on every object SCM failed.` },
  no_rule: { label: `No ${brand.ruleSetShort} rule`, tone: "neutral", help: `No ${brand.ruleSetShort} rule covers this check yet.` },
  core_off: { label: `${brand.ruleSetShort} rule off`, tone: "info", help: `The linked ${brand.ruleSetShort} rule is turned off in Settings.` },
  by_design: { label: "Deliberate difference", tone: "info", help: `The ${brand.ruleSetShort} rule checked this and chose not to flag it, for the reason shown. Not a gap.` },
  not_applicable: { label: "Not applicable", tone: "neutral", help: "SCM failed only PAN-OS built-in profiles that nothing uses (they can't be edited and affect no traffic), HA settings on a firewall without HA, or disabled policy-based forwarding rules. These aren't gaps." },
  covered: { label: "Covered", tone: "good", help: `A ${brand.ruleSetShort} finding covers it, so SCM isn't scored twice.` },
};

/**
 * Which failed SCM checks the core rules also caught, from the stored SCM run. The gaps are what would
 * go unreported if SCM couldn't be run; the copied text (check numbers, titles and field names only)
 * is what's needed to close them.
 */
export function ScmCoverage({ coverage }: { coverage: Coverage }) {
  const [copied, setCopied] = useState(false);
  const gaps = coverage.checks.filter((c) => !["covered", "by_design", "not_applicable"].includes(c.status));
  const gapPoints = gaps.reduce((n, c) => n + c.points, 0);
  const deliberate = coverage.checks.filter((c) => c.status === "by_design");
  const notApplicable = coverage.checks.filter((c) => c.status === "not_applicable");
  const listed = [...gaps, ...deliberate, ...notApplicable];
  const s = coverage.summary;

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-3 justify-between">
        <p className="text-[13px] text-fg-2 m-0 max-w-3xl">
          Of the {coverage.checks.length} SCM checks that failed, the {brand.ruleSet} rules also caught {s.covered.checks}.{" "}
          {gaps.length > 0
            ? <>{gaps.length} would go unreported without SCM ({gapPoints} points).</>
            : "Nothing would go unreported without SCM."}
          {deliberate.length > 0 && (
            <> {deliberate.length} {deliberate.length === 1 ? "is a deliberate difference" : "are deliberate differences"} from SCM.</>
          )}
          {notApplicable.length > 0 && (
            <> {notApplicable.length} more fail only on built-in profiles nothing uses, HA settings on a firewall without HA, or disabled PBF rules, which aren't gaps.</>
          )}
        </p>
        {listed.length > 0 && (
          <Button
            size="sm"
            className="no-print"
            onClick={async () => {
              await navigator.clipboard.writeText(coverage.text);
              setCopied(true);
              setTimeout(() => setCopied(false), 1800);
            }}
            title="Check numbers, titles, statuses and field names only; no object names"
          >
            {copied ? <Check size={13} /> : <Copy size={13} />}{copied ? "Copied" : "Copy gap list"}
          </Button>
        )}
      </div>
      {listed.length > 0 && (
        <table className="scm-coverage-table">
          <thead>
            <tr><th>SCM check</th><th>Status</th><th>Linked {brand.ruleSetShort} rule</th><th className="text-right">Points</th></tr>
          </thead>
          <tbody>
            {listed.map((c) => (
              <tr key={c.check_id}>
                <td>
                  <div className="text-[12px] text-fg-muted tab-num">SCM {c.check_id} · {c.category}</div>
                  <div className="text-[13px] leading-5">{c.title}</div>
                  {!!c.not_applicable_objects && c.status !== "not_applicable" && (
                    <div className="text-[11px] text-fg-muted mt-0.5">
                      Plus {c.not_applicable_objects} unused built-in object{c.not_applicable_objects === 1 ? "" : "s"}, not counted
                    </div>
                  )}
                  {c.reason && <div className="text-[12px] text-fg-2 mt-0.5">Why: {c.reason}</div>}
                  {c.failed_fields.length > 0 && (
                    <div className="text-[11px] text-fg-muted mt-0.5 font-mono break-all">{c.failed_fields.join(", ")}</div>
                  )}
                </td>
                <td><Badge tone={STATUS[c.status].tone} title={STATUS[c.status].help}>{STATUS[c.status].label}</Badge></td>
                <td className="text-[12px]">
                  {c.core_rules.length === 0 ? <span className="text-fg-muted">—</span> : c.core_rules.map((r) => (
                    <div key={r.id}>{r.title}{!r.enabled && <span className="text-fg-muted"> (off)</span>}</div>
                  ))}
                </td>
                <td className="text-right tab-num">{c.points}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
