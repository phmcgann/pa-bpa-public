import type { Finding, RuleScope, SecurityRule } from "../types";
import { cn } from "../lib/cn";
import { NoteButton, NoteRef } from "./Notes";
import { Badge } from "./ui/Badge";
import { SeverityIcon } from "./ui/SeverityIcon";

function issuesForRule(rule: SecurityRule, findings: Finding[]): Finding[] {
  return findings.filter(
    (f) => f.rule_id.startsWith("security_rule_") && f.finding_key.endsWith(`:${rule.name}`) && !f.dismissed
  );
}

const ACTION_TONE: Record<string, "good" | "critical" | "neutral"> = {
  allow: "good",
  deny: "critical",
  drop: "critical",
  "reset-client": "critical",
  "reset-server": "critical",
  "reset-both": "critical",
};

const RULE_SCOPE_LABEL: Record<RuleScope, string> = {
  shared_pre: "Shared (pre)",
  device_group_pre: "Device group (pre)",
  device_group_post: "Device group (post)",
  shared_post: "Shared (post)",
};

export function RuleTable({ rules, findings }: { rules: SecurityRule[]; findings: Finding[] }) {
  const showScope = rules.some((r) => r.rule_scope);

  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Rule</th>
            {showScope && <th style={{ width: 140 }}>Scope</th>}
            <th style={{ width: 70 }}>Action</th>
            <th>From → To</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Application</th>
            <th>Profile</th>
            <th>Issues</th>
          </tr>
        </thead>
        <tbody>
          {rules.map((r) => {
            const issues = issuesForRule(r, findings);
            const profile = r.profile_group || Object.keys(r.indiv_profiles).join(", ") || "—";
            return (
              <tr key={r.name} className={cn("group", r.disabled === "yes" && "opacity-55")}>
                <td className="font-medium">
                  {r.name}
                  <NoteRef kind="security_rule" targetKey={`${r.rule_scope ?? ""}:${r.name}`} />
                  <NoteButton kind="security_rule" targetKey={`${r.rule_scope ?? ""}:${r.name}`} label={r.name}
                    className="ml-1 -my-1 opacity-0 group-hover:opacity-100 focus-visible:opacity-100" iconOnly />
                  {r.disabled === "yes" && (
                    <Badge tone="outline" className="ml-2" title="Disabled rules are excluded from the risk score, same as a dismissed finding">
                      Disabled
                    </Badge>
                  )}
                </td>
                {showScope && (
                  <td style={{ color: "var(--text-secondary)", fontSize: 12 }}>
                    {r.rule_scope ? RULE_SCOPE_LABEL[r.rule_scope] : "—"}
                    {r.scope_name && <div className="text-[12px] text-fg-muted">{r.scope_name}</div>}
                  </td>
                )}
                <td>
                  <Badge tone={ACTION_TONE[r.action] ?? "neutral"}>{r.action}</Badge>
                </td>
                <td style={{ color: "var(--text-secondary)" }}>{r.from_zones.join(", ")} → {r.to_zones.join(", ")}</td>
                <td style={{ color: "var(--text-secondary)" }}>{r.sources.join(", ").slice(0, 60)}</td>
                <td style={{ color: "var(--text-secondary)" }}>{r.destinations.join(", ").slice(0, 60)}</td>
                <td style={{ color: "var(--text-secondary)" }}>{r.applications.join(", ").slice(0, 50)}</td>
                <td style={{ color: "var(--text-secondary)" }}>{profile}</td>
                <td>
                  {issues.length === 0 ? (
                    <span className="text-good-fg text-[12px]">No issues</span>
                  ) : (
                    <ul className="m-0 pl-0 list-none flex flex-col gap-1 text-[12px]">
                      {issues.map((i) => (
                        <li key={i.finding_key} className="flex gap-1.5">
                          <SeverityIcon severity={i.severity} size={12} className="mt-0.5 shrink-0" />
                          <span className="text-fg-2">{i.title}</span>
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
    </div>
  );
}
