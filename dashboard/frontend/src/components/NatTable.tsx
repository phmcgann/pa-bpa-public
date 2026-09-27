import type { Finding, NatRule } from "../types";
import { cn } from "../lib/cn";
import { NoteButton, NoteRef } from "./Notes";
import { Badge } from "./ui/Badge";
import { SeverityIcon } from "./ui/SeverityIcon";

function sourceTranslation(r: NatRule): string {
  const st = r.source_translation;
  if (!st) return "—";
  const to = st.interface ? `interface ${st.interface}` : st.translated.join(", ") || "—";
  const kind = { "dynamic-ip-and-port": "Dynamic IP and port", "dynamic-ip": "Dynamic IP", "static-ip": "Static IP" }[st.type] ?? st.type;
  return `${kind} → ${to}`;
}

function destinationTranslation(r: NatRule): string {
  const dt = r.destination_translation;
  if (!dt) return "—";
  return `${dt.type === "dynamic" ? "Dynamic → " : "→ "}${dt.address ?? "—"}${dt.port ? `:${dt.port}` : ""}`;
}

/** NAT rules in evaluation order, with the core-rule issues found on each. */
export function NatTable({ rules, findings }: { rules: NatRule[]; findings: Finding[] }) {
  const issues = (name: string) =>
    findings.filter((f) => f.rule_id.startsWith("nat_") && f.finding_key === `${f.rule_id}:${name}` && !f.dismissed);

  return (
    <table className="nat-table">
      <thead>
        <tr>
          <th>Rule</th><th>From → To</th><th>Source</th><th>Destination</th><th>Service</th>
          <th>Source translation</th><th>Destination translation</th><th>Issues</th>
        </tr>
      </thead>
      <tbody>
        {rules.map((r, i) => {
          const found = issues(r.name);
          return (
            <tr key={`${r.vsys ?? ""}:${r.name}`} className={cn("group", r.disabled && "opacity-55")}>
              <td className="font-medium">
                <span className="text-fg-muted font-normal tab-num mr-1.5">#{i + 1}</span>{r.name}
                <NoteRef kind="nat_rule" targetKey={`${r.vsys ?? ""}:${r.name}`} />
                <NoteButton kind="nat_rule" targetKey={`${r.vsys ?? ""}:${r.name}`} label={r.name} className="ml-1 -my-1 opacity-0 group-hover:opacity-100 focus-visible:opacity-100" iconOnly />
                {r.disabled && <Badge tone="outline" className="ml-2">Disabled</Badge>}
                {r.source_translation?.bidirectional && <Badge tone="neutral" className="ml-2">Bi-directional</Badge>}
              </td>
              <td className="text-fg-2">
                {r.from_zones.join(", ")} → {r.to_zones.join(", ")}
                {r.to_interface !== "any" && <div className="text-[12px] text-fg-muted">via {r.to_interface}</div>}
              </td>
              <td className="text-fg-2">{r.sources.join(", ")}</td>
              <td className="text-fg-2">{r.destinations.join(", ")}</td>
              <td className="text-fg-2">{r.service}</td>
              <td className="text-fg-2">{sourceTranslation(r)}</td>
              <td className="text-fg-2">{destinationTranslation(r)}</td>
              <td>
                {found.length === 0 ? (
                  <span className="text-good-fg text-[12px]">No issues</span>
                ) : (
                  <ul className="m-0 pl-0 list-none flex flex-col gap-1 text-[12px]">
                    {found.map((f) => (
                      <li key={f.finding_key} className="flex gap-1.5">
                        <SeverityIcon severity={f.severity} size={12} className="mt-0.5 shrink-0" />
                        <span className="text-fg-2">{f.title}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
