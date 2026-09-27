import { useState } from "react";
import type { Advisory, AdvisoryReport } from "../types";
import { Badge } from "./ui/Badge";

const TONE = { CRITICAL: "critical", HIGH: "warning", MEDIUM: "low", LOW: "info", INFORMATIONAL: "info", NONE: "info" } as const;
const MINOR = new Set(["LOW", "INFORMATIONAL", "NONE"]);

function label(s: Advisory["severity"]): string {
  return s.charAt(0) + s.slice(1).toLowerCase();
}

function day(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

/**
 * Palo Alto Networks security advisories that list this firewall's exact PAN-OS version as affected.
 * Low-severity and informational ones are folded away on screen and summarised in print.
 */
export function AdvisoriesSection({ report }: { report: AdvisoryReport }) {
  const [showMinor, setShowMinor] = useState(false);
  if (!report.version || report.status !== "ok") {
    return <p className="text-[13px] text-fg-muted">{report.reason}</p>;
  }
  const major = report.matches.filter((a) => !MINOR.has(a.severity));
  const minor = report.matches.filter((a) => MINOR.has(a.severity));
  const rows = showMinor ? report.matches : major;

  return (
    <div className="flex flex-col gap-3">
      <p className="text-[13px] text-fg-2">
        PAN-OS <span className="font-medium">{report.version}</span> checked against {report.count} Palo Alto Networks
        security advisories{report.fetched_at && <>, updated {day(report.fetched_at)}</>}.{" "}
        {report.matches.length === 0
          ? "None of them lists this version as affected."
          : <>{report.matches.length} list this version as affected.</>}
      </p>
      {report.recommended && (
        <p className="text-[13px] text-fg-2">
          Earliest build in this release that no critical or high advisory affects:{" "}
          <span className="font-medium">PAN-OS {report.recommended}</span>.
        </p>
      )}
      {rows.length > 0 && (
        <table className="advisories-table">
          <thead>
            <tr><th>Severity</th><th>Advisory</th><th className="text-right">CVSS</th><th>Fix</th></tr>
          </thead>
          <tbody>
            {rows.map((a) => (
              <tr key={a.id}>
                <td><Badge tone={TONE[a.severity]} className="sev-badge">{label(a.severity)}</Badge></td>
                <td>
                  <a href={a.url} target="_blank" rel="noreferrer" className="font-medium text-accent-fg hover:underline">{a.id}</a>
                  <div className="text-[12px] text-fg-muted">{a.title}</div>
                </td>
                <td className="text-right tab-num">{a.score ?? "—"}</td>
                <td className="text-[12px]">{a.fix.replace(/^Upgrade to PAN-OS /, "")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {minor.length > 0 && (
        <>
          <button
            type="button"
            onClick={() => setShowMinor(!showMinor)}
            className="no-print self-start text-[12px] text-accent-fg hover:underline bg-transparent border-0 p-0"
          >
            {showMinor ? "Hide" : "Show"} {minor.length} low-severity and informational advisor{minor.length === 1 ? "y" : "ies"}
          </button>
          {!showMinor && (
            <p className="hidden print:block text-[12px] text-fg-muted">
              Plus {minor.length} low-severity and informational advisor{minor.length === 1 ? "y" : "ies"} not listed here.
            </p>
          )}
        </>
      )}
    </div>
  );
}
