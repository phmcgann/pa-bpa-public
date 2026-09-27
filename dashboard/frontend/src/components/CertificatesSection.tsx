import type { Certificate, Finding } from "../types";
import { cn } from "../lib/cn";
import { Badge } from "./ui/Badge";

const DAY = 86_400_000;

function expiry(c: Certificate): { date: string; note: string } | null {
  if (!c.not_after) return null;
  const t = new Date(c.not_after);
  const days = Math.round((t.getTime() - Date.now()) / DAY);
  return {
    date: t.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }),
    note: days < 0 ? `expired ${-days} day${days === -1 ? "" : "s"} ago` : `in ${days} day${days === 1 ? "" : "s"}`,
  };
}

/** Every certificate in the config, soonest expiry first, with where it's used. Red values have an open finding. */
export function CertificatesSection({ certs, findings }: { certs: Certificate[]; findings: Finding[] }) {
  const active = new Set(findings.filter((f) => !f.dismissed).map((f) => f.finding_key));
  const has = (rule: string, name: string) => active.has(`${rule}:${name}`);
  const sorted = [...certs].sort((a, b) => (a.not_after ?? "9").localeCompare(b.not_after ?? "9"));

  return (
    <table className="certs-table">
      <thead>
        <tr><th>Certificate</th><th>Expires</th><th>Key</th><th>Signature</th><th>Used by</th></tr>
      </thead>
      <tbody>
        {sorted.map((c) => {
          const exp = expiry(c);
          const expFlag = has("cert_expired", c.name) || has("cert_expiring_soon", c.name) || has("cert_expired_unused", c.name);
          return (
            <tr key={`${c.scope}:${c.name}`} className={c.used_by.length ? undefined : "opacity-60"}>
              <td>
                <div className="font-medium">{c.name}</div>
                {c.common_name && <div className="text-[12px] text-fg-muted">{c.common_name}</div>}
                <div className="flex flex-wrap gap-1 mt-1">
                  {c.ca && <Badge tone="neutral">CA</Badge>}
                  {c.self_signed && (
                    <Badge tone={has("cert_self_signed_service", c.name) ? "critical" : "neutral"}>Self-signed</Badge>
                  )}
                  {!c.has_private_key && <Badge tone="outline">No private key</Badge>}
                </div>
              </td>
              <td className={cn("tab-num", expFlag && "text-critical-fg font-medium")}>
                {exp ? <>{exp.date}<div className="text-[12px] font-normal">{exp.note}</div></> : <span className="text-fg-muted">—</span>}
              </td>
              <td className={cn(has("cert_weak_key", c.name) && "text-critical-fg font-medium")}>
                {c.key_algorithm ?? "—"}{c.key_bits ? ` ${c.key_bits}` : ""}
              </td>
              <td className={cn(has("cert_weak_signature", c.name) && "text-critical-fg font-medium")}>
                {c.signature_hash ?? "—"}
              </td>
              <td className="text-[12px]">
                {c.used_by.length === 0
                  ? <span className="text-fg-muted">Not used</span>
                  : c.used_by.map((u) => <div key={u}>{u}</div>)}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
