import type { MgmtExposureEntry, ReachResult, UnresolvedRule } from "../types";

const SERVICE_LABEL: Record<string, string> = {
  https: "HTTPS", http: "HTTP", ssh: "SSH", telnet: "Telnet", snmp: "SNMP",
};

function via(r: ReachResult): string {
  return r.via.endsWith("-default") ? r.via : `rule '${r.via}'`;
}

function unresolvedText(u: UnresolvedRule): string {
  const causes = u.causes
    .map((c) => `${c.field}${c.object ? ` '${c.object}'` : ""} — ${c.kind}`)
    .join("; ");
  return `'${u.rule}' (${causes})`;
}

function uncertainText(r: ReachResult): string {
  const rules = r.unresolved_rules.map(unresolvedText).join(", ");
  return r.lean === "open"
    ? `allowed by ${via(r)} unless an earlier rule blocks it first: ${rules}`
    : `stopped by ${via(r)} unless an earlier rule allows it first: ${rules}`;
}

function ZoneList({ results, render }: { results: ReachResult[]; render: (r: ReachResult) => string }) {
  if (results.length === 0) return <span style={{ color: "var(--text-muted)" }}>—</span>;
  return (
    <>
      {results.map((r) => (
        <div key={r.source_zone}>
          <strong style={{ fontWeight: 600 }}>{r.source_zone}</strong>
          <span style={{ color: "var(--text-secondary)" }}> — {render(r)}</span>
        </div>
      ))}
    </>
  );
}

type Verdict = { label: string; icon: string; color: string };

function verdict(entry: MgmtExposureEntry, results: ReachResult[]): Verdict {
  if (entry.zone === null) return { label: "Not in a zone", icon: "–", color: "var(--text-muted)" };
  if (entry.permitted_ips > 0) return { label: "Restricted (permitted IPs)", icon: "✓", color: "var(--good-text)" };
  if (results.some((r) => r.status === "open")) return { label: "Exposed", icon: "✖", color: "var(--sev-critical-text)" };
  if (results.some((r) => r.lean === "open")) return { label: "Possibly exposed", icon: "▲", color: "var(--sev-warning-text)" };
  if (results.some((r) => r.status === "uncertain")) return { label: "Uncertain", icon: "?", color: "var(--sev-low-text)" };
  return { label: "Restricted (policy)", icon: "✓", color: "var(--good-text)" };
}

export function MgmtReachability({ exposure }: { exposure: MgmtExposureEntry[] }) {
  const rows = exposure.flatMap((entry) =>
    Object.entries(entry.services).map(([svc, results]) => ({ entry, svc, results }))
  );
  if (rows.length === 0) {
    return (
      <p style={{ fontSize: 13, color: "var(--text-muted)", margin: 0 }}>
        No data interfaces have HTTPS, HTTP, SSH, Telnet, or SNMP management enabled.
      </p>
    );
  }
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Interface</th>
            <th>Service</th>
            <th>Verdict</th>
            <th>Open to any source</th>
            <th>Specific sources only</th>
            <th>Uncertain</th>
            <th>Blocked from</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(({ entry, svc, results }) => {
            const v = verdict(entry, results);
            const by = (s: ReachResult["status"]) => results.filter((r) => r.status === s);
            const mitigated = entry.permitted_ips > 0;
            return (
              <tr key={`${entry.interface}:${svc}`}>
                <td style={{ fontWeight: 500 }}>
                  {entry.interface}
                  <div style={{ fontSize: 11, color: "var(--text-muted)", fontWeight: 400 }}>
                    zone {entry.zone ?? "none"} · profile {entry.profile}
                    {entry.permitted_ips > 0 && ` · ${entry.permitted_ips} permitted IP(s)`}
                    {!entry.address_known && " · address unknown (DHCP/unresolved)"}
                  </div>
                </td>
                <td>{SERVICE_LABEL[svc] ?? svc}</td>
                <td style={{ whiteSpace: "nowrap", color: v.color, fontWeight: 500 }}>
                  <span aria-hidden="true">{v.icon}</span> {v.label}
                </td>
                <td style={{ fontSize: 12, opacity: mitigated ? 0.6 : 1 }}>
                  <ZoneList results={by("open")} render={(r) => via(r)} />
                </td>
                <td style={{ fontSize: 12 }}>
                  <ZoneList
                    results={by("restricted")}
                    render={(r) => `${r.specific_allows.map((n) => `'${n}'`).join(", ")}, rest stopped by ${via(r)}`}
                  />
                </td>
                <td style={{ fontSize: 12 }}>
                  <ZoneList results={by("uncertain")} render={uncertainText} />
                </td>
                <td style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                  {by("blocked").map((r) => r.source_zone).join(", ") || "—"}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
