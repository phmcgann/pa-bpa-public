import { useMemo, useState } from "react";
import { Loader2, Play, RotateCw } from "lucide-react";
import { SeverityBadge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { Callout } from "./ui/Callout";
import { Stat } from "./ui/Stat";
import type { Finding, ScmStatus } from "../types";
import { brand } from "@brand";

interface CheckRow {
  id: number;
  title: string;
  severity: Finding["severity"];
  category: string;
  objects: string[];
  duplicateOf: string[];
  scored: boolean;
}

const SEVERITY_RANK: Record<Finding["severity"], number> = { CRITICAL: 0, WARNING: 1, LOW: 2, INFORMATIONAL: 3 };

/**
 * "Decryption profile 'a'", "Decryption profile 'b'" → kind "Decryption profile" over names a, b,
 * so a check failing on many objects of one kind reads as one short line.
 */
function FailingOn({ objects }: { objects: string[] }) {
  const parsed = objects.map((o) => /^(.+?) '(.+)'$/.exec(o));
  const kind = parsed[0]?.[1];
  const shared = kind && parsed.every((m) => m?.[1] === kind);
  const names = shared ? parsed.map((m) => m![2]) : objects;
  const shown = names.slice(0, 3).join(", ");
  const more = names.length > 3 ? ` +${names.length - 3} more` : "";
  return (
    <span title={objects.join("\n")}>
      {shared && <span className="text-fg-muted">{kind}{names.length > 1 ? "s" : ""} </span>}
      {shown}
      {more && <span className="text-fg-muted">{more}</span>}
    </span>
  );
}

/**
 * Palo Alto Strata Cloud Manager's own BPA, run on request against this assessment's config.
 * One row per failed check (aggregated across the objects it failed on), in Palo Alto's wording.
 */
export function ScmBpaSection({ scm, findings, onRun }: {
  scm: ScmStatus;
  findings: Finding[];
  onRun: () => Promise<void>;
}) {
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const coreTitles = useMemo(
    () => new Map(findings.filter((f) => f.program === "core").map((f) => [f.rule_id, f.title])),
    [findings]
  );
  const rows = useMemo(() => {
    const byCheck = new Map<number, CheckRow>();
    for (const f of findings) {
      if (f.program !== "scm" || f.dismissed) continue;
      const id = f.scm_check_ids[0];
      const row = byCheck.get(id) ?? {
        id, title: f.title, severity: f.severity, category: f.category, objects: [],
        duplicateOf: f.duplicate_of ?? [], scored: false,
      };
      row.objects.push(f.message.split(" — ")[0]);
      row.scored ||= !f.not_scored_reason && !f.rule_disabled;
      byCheck.set(id, row);
    }
    return [...byCheck.values()].sort(
      (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || a.id - b.id
    );
  }, [findings]);

  async function run() {
    const ok = window.confirm(
      "This sends the firewall configuration to Palo Alto Networks' Strata Cloud Manager for analysis. " +
      "Palo Alto deletes it after processing. Continue?"
    );
    if (!ok) return;
    setError(null);
    setRunning(true);
    try {
      await onRun();
    } catch (e) {
      setError(e instanceof Error ? e.message.replace(/^\d+ [^:]*: /, "") : String(e));
    } finally {
      setRunning(false);
    }
  }

  const canRun = scm.configured && scm.config_stored;
  const run_ = scm.run;
  const coreMatched = rows.filter((r) => r.duplicateOf.length > 0).length;

  return (
    <div>
      {!run_ || run_.status === "failed" ? (
        <p className="text-[13px] text-fg-2 leading-6 max-w-3xl mt-0 mb-4">
          Run Palo Alto's own Best Practice Assessment on this configuration through Strata Cloud Manager. It
          reports every check Palo Alto evaluates — GlobalProtect, HA, device settings, dynamic updates and
          more — in Palo Alto's wording, alongside the {brand.ruleSet} findings. Checks a {brand.ruleSet} rule already covers
          are listed but not scored twice.
        </p>
      ) : (
        <div className="grid grid-cols-2 lg:grid-cols-4 print:grid-cols-4 gap-3 mb-5">
          <Stat label="Checks evaluated" value={run_.checks_evaluated}
            sub={`${run_.results_evaluated.toLocaleString()} results — one per check per object it applies to`} />
          <Stat label="Checks failing" value={rows.length} sub={`${run_.failed.toLocaleString()} failing results across objects`} />
          <Stat label={`Also ${brand.ruleSet}`} value={coreMatched} sub={`covered by a ${brand.ruleSetShort} rule`} />
          <Stat label="Results passed" value={run_.passed}
            sub={(() => {
              const excluded = run_.results_evaluated - run_.failed - run_.passed;
              return excluded > 0 ? `${excluded.toLocaleString()} more excluded by Palo Alto as not applicable` : "of all results";
            })()} />
        </div>
      )}

      {run_?.status === "failed" && (
        <Callout tone="warning" className="mb-4" title="Last run failed.">{run_.error}</Callout>
      )}
      {/* The request error repeats the stored run's error when the run itself failed: show it once. */}
      {error && error !== run_?.error && (
        <Callout tone="warning" className="mb-4" title="Couldn't run the Palo Alto BPA.">{error}</Callout>
      )}

      <div className="no-print flex items-center gap-3 flex-wrap mb-5">
        <Button variant={run_ ? "secondary" : "primary"} disabled={!canRun || running} onClick={run}>
          {running ? <Loader2 size={15} className="animate-spin" /> : run_ ? <RotateCw size={15} /> : <Play size={15} />}
          {running ? "Running Palo Alto BPA… (about a minute)" : run_ ? "Run again" : "Run Palo Alto SCM BPA"}
        </Button>
        {run_ && (
          <span className="text-[12px] text-fg-muted">
            Last run {new Date(run_.ran_at + "Z").toLocaleString()}
          </span>
        )}
        {!scm.configured && (
          <span className="text-[12px] text-fg-muted">
            Not configured on the server — set SCM_CLIENT_ID, SCM_CLIENT_SECRET and SCM_TSG_ID.
          </span>
        )}
        {scm.configured && !scm.config_stored && (
          <span className="text-[12px] text-fg-muted">
            This assessment was uploaded before configs were kept — re-upload the file to run it.
          </span>
        )}
      </div>

      {run_?.status === "completed" && (
        <div className="table-scroll -mx-5">
          <table className="scm-table min-w-[860px]">
            <thead>
              <tr>
                <th className="pl-5 w-[76px]">Check</th>
                <th className="w-[118px]">Severity</th>
                <th>Palo Alto recommendation</th>
                <th className="w-[140px]">Category</th>
                <th>Failing on</th>
                <th className="w-[200px] pr-5">{brand.ruleSet}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} className={r.scored ? undefined : "opacity-70"}>
                  <td className="pl-5 font-medium tab-num text-fg-2">#{r.id}</td>
                  <td><SeverityBadge severity={r.severity} /></td>
                  <td className="font-medium text-fg leading-5 min-w-[240px]">{r.title}</td>
                  <td className="text-[12px] text-fg-2">{r.category}</td>
                  <td className="text-[12px] text-fg-2 leading-5"><FailingOn objects={r.objects} /></td>
                  <td className="pr-5 text-[12px] leading-5">
                    {r.duplicateOf.length ? (
                      <span className="text-fg-2">Also {brand.ruleSet}: {r.duplicateOf.map((id) => coreTitles.get(id) ?? id).join("; ")}</span>
                    ) : (
                      <span className="text-fg-muted">SCM only</span>
                    )}
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr><td colSpan={6} className="text-center text-fg-muted py-10">No failing checks.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
