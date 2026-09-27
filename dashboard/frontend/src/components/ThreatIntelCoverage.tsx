import { Check, X } from "lucide-react";
import type { ThreatIntelCoverage as Coverage } from "../types";

function Blocked({ rules }: { rules: string[] }) {
  if (rules.length === 0) {
    return <span className="inline-flex items-center gap-1 text-critical-fg font-medium"><X size={14} aria-hidden="true" />Not blocked</span>;
  }
  return (
    <span className="inline-flex items-start gap-1 text-good-fg">
      <Check size={14} className="mt-0.5 shrink-0" aria-hidden="true" />
      <span className="text-fg-2">{rules.join(", ")}</span>
    </span>
  );
}

/**
 * Palo Alto Networks' built-in threat-intelligence IP lists and QUIC: which enabled deny rules
 * block each, per Internet Gateway Best Practices step 1 (lists) and step 3 (QUIC).
 */
export function ThreatIntelCoverage({ coverage }: { coverage: Coverage }) {
  return (
    <div className="table-scroll -mx-5">
      <table className="min-w-[720px]">
        <thead>
          <tr>
            <th className="pl-5">Built-in list</th>
            <th>Inbound (list as source)</th>
            <th className="pr-5">Outbound (list as destination)</th>
          </tr>
        </thead>
        <tbody>
          {coverage.lists.map((l) => (
            <tr key={l.id}>
              <td className="pl-5">
                <div className="font-medium text-fg">{l.label.replace("Palo Alto Networks - ", "")}</div>
                <div className="text-[11px] text-fg-muted">
                  {l.id}
                  {l.disabled_rules.length > 0 && ` · disabled rule: ${l.disabled_rules.join(", ")}`}
                </div>
              </td>
              <td><Blocked rules={l.inbound} /></td>
              <td className="pr-5"><Blocked rules={l.outbound} /></td>
            </tr>
          ))}
          <tr>
            <td className="pl-5">
              <div className="font-medium text-fg">QUIC application</div>
              <div className="text-[11px] text-fg-muted">
                {coverage.quic.decryption_in_use ? "SSL decryption is in use" : "No decryption rules in use"}
                {coverage.quic.disabled_rules.length > 0 && ` · disabled rule: ${coverage.quic.disabled_rules.join(", ")}`}
              </div>
            </td>
            <td colSpan={2} className="pr-5"><Blocked rules={coverage.quic.rules} /></td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}
