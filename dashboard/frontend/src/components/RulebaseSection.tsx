import { useState } from "react";
import type { DynamicGroupUse, RulebaseAnalysis, ShadowedRule } from "../types";
import { CardSection } from "./ui/Card";
import { Badge } from "./ui/Badge";

const KIND_LABELS: Record<string, string> = {
  addresses: "Address objects",
  address_groups: "Address groups",
  services: "Service objects",
  service_groups: "Service groups",
  application_groups: "Application groups",
  application_filters: "Application filters",
  external_lists: "External dynamic lists",
  custom_url_categories: "Custom URL categories",
  security_profiles: "Security profiles",
  profile_groups: "Security profile groups",
};

const EFFECT: Record<ShadowedRule["kind"], { label: string; tone: "critical" | "neutral" | "warning" }> = {
  block_allowed: { label: "Traffic it blocks is allowed", tone: "critical" },
  allow_blocked: { label: "Traffic it allows is blocked", tone: "warning" },
  redundant: { label: "Redundant", tone: "neutral" },
};

const LIST_LIMIT = 40;

function Names({ names }: { names: string[] }) {
  const [all, setAll] = useState(false);
  const shown = all ? names : names.slice(0, LIST_LIMIT);
  return (
    <>
      {shown.join(", ")}
      {names.length > LIST_LIMIT && (
        <>
          {!all && <span className="text-fg-muted"> and {names.length - LIST_LIMIT} more</span>}
          <button
            type="button"
            onClick={() => setAll(!all)}
            className="no-print ml-2 text-accent-fg hover:underline bg-transparent border-0 p-0 text-[12px]"
          >
            {all ? "Show fewer" : "Show all"}
          </button>
        </>
      )}
    </>
  );
}

/**
 * Rules an earlier rule makes unreachable, objects nothing uses, and objects that duplicate each other.
 */
export function RulebaseSection({ analysis, unused, unusedReason, viaDynamicGroup = [] }: {
  analysis: RulebaseAnalysis;
  unused: Record<string, string[]> | null;
  unusedReason?: string;
  viaDynamicGroup?: DynamicGroupUse[];
}) {
  const unusedKinds = Object.entries(unused ?? {}).filter(([, names]) => names.length > 0);

  return (
    <div>
      <CardSection
        title="Rules that never match"
        description="An earlier rule matches all of this rule's traffic, so the firewall never reaches it. Only certain, whole coverage by a single earlier rule is shown."
      >
        {!analysis.available ? (
          <p className="text-[13px] text-fg-muted m-0">{analysis.reason}</p>
        ) : analysis.shadowed.length === 0 ? (
          <p className="text-[13px] text-fg-2 m-0">No rule is fully covered by an earlier one.</p>
        ) : (
          <table className="rule-shadow-table">
            <thead>
              <tr><th>Rule</th><th>Covered by</th><th>Effect</th></tr>
            </thead>
            <tbody>
              {analysis.shadowed.map((s) => (
                <tr key={`${s.vsys}:${s.rule}`}>
                  <td>
                    <span className="text-fg-muted tab-num mr-1.5">#{s.position}</span>
                    <span className="font-medium">{s.rule}</span>
                    <span className="text-fg-muted text-[12px] ml-1.5">{s.action}</span>
                  </td>
                  <td>
                    <span className="text-fg-muted tab-num mr-1.5">#{s.by_position}</span>
                    {s.by}
                    <span className="text-fg-muted text-[12px] ml-1.5">{s.by_action}</span>
                  </td>
                  <td><Badge tone={EFFECT[s.kind].tone}>{EFFECT[s.kind].label}</Badge></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </CardSection>

      <CardSection
        title="Unused objects"
        description="Objects no rule, NAT policy, interface, profile or other object uses, directly or through a group that's in use."
      >
        {unused === null ? (
          <p className="text-[13px] text-fg-muted m-0">{unusedReason}</p>
        ) : unusedKinds.length === 0 ? (
          <p className="text-[13px] text-fg-2 m-0">Every object is used.</p>
        ) : (
          <table className="objects-table">
            <thead>
              <tr><th>Kind</th><th className="text-right">Unused</th><th>Objects</th></tr>
            </thead>
            <tbody>
              {unusedKinds.map(([kind, names]) => (
                <tr key={kind}>
                  <td className="font-medium">{KIND_LABELS[kind] ?? kind}</td>
                  <td className="text-right tab-num">{names.length}</td>
                  <td className="text-[12px]"><Names names={names} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {unused !== null && viaDynamicGroup.length > 0 && (
          <div className="mt-4">
            <p className="text-[12px] text-fg-2 mt-0 mb-2 max-w-3xl leading-5">
              <span className="font-semibold">Counted as used only through a dynamic address group.</span>{" "}
              These address objects aren't referenced anywhere else; they count as used because a dynamic group in
              use names one of their tags. The group's filter isn't evaluated, so an address with any one tag the
              filter mentions is counted, even when the filter needs several (for example 'web' and 'prod'). Check
              each group's filter: any address that isn't really a member is unused.
            </p>
            <table className="dag-table">
              <thead>
                <tr><th>Address object</th><th>Its tags the filter names</th><th>Dynamic group and filter</th></tr>
              </thead>
              <tbody>
                {viaDynamicGroup.map((a) => (
                  <tr key={a.name}>
                    <td className="font-medium">{a.name}</td>
                    <td>{a.tags.map((t) => `'${t}'`).join(", ")}</td>
                    <td>
                      {a.groups.map((g) => (
                        <div key={g.name}>{g.name} <span className="text-fg-muted">— {g.filter}</span></div>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardSection>

      {analysis.duplicates.length > 0 && (
        <CardSection title="Duplicate objects" description="Objects with the same value. Keep one and point rules and groups at it.">
          <table className="objects-table">
            <thead>
              <tr><th>Kind</th><th>Value</th><th>Objects</th></tr>
            </thead>
            <tbody>
              {analysis.duplicates.map((d) => (
                <tr key={`${d.kind}:${d.value}`}>
                  <td className="font-medium">{d.kind === "addresses" ? "Address" : "Service"}</td>
                  <td className="tab-num">{d.value}</td>
                  <td className="text-[12px]">{d.names.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardSection>
      )}
    </div>
  );
}
