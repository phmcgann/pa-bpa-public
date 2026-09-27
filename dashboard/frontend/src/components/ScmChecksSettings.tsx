import { useMemo, type ReactNode } from "react";
import type { RuleDef, ScmCatalog, ScmCheck } from "../types";
import { cn } from "../lib/cn";
import { Badge } from "./ui/Badge";
import { Disclosure } from "./ui/Disclosure";
import { SeveritySelect } from "./ui/SeveritySelect";
import { Switch } from "./ui/Switch";
import { brand } from "@brand";

/** One Palo Alto SCM check: enable, severity, and which core rule (if any) already covers it. */
function CheckRow({ check: c, coreTitle, onToggle, onSeverity }: {
  check: ScmCheck;
  coreTitle: Map<string, string>;
  onToggle: (check: ScmCheck, enabled: boolean) => void;
  onSeverity: (check: ScmCheck, severity: string) => void;
}) {
  const paloWording = c.severity !== (c.default_severity.charAt(0) + c.default_severity.slice(1).toLowerCase())
    ? `Palo Alto: ${c.severity}` : undefined;
  return (
    <div className={cn("flex gap-3 py-3 border-t border-divider first:border-t-0", !c.enabled && "opacity-55")}>
      <Switch checked={c.enabled} onChange={(v) => onToggle(c, v)} label={`Enable check #${c.id}`} className="mt-0.5" />
      <div className="min-w-0 flex-1">
        <div className="text-[13px] text-fg leading-5">
          <span className="font-semibold tab-num text-fg-2 mr-1.5">#{c.id}</span>{c.name}
        </div>
        <div className="flex items-center gap-2 flex-wrap mt-1.5">
          <Badge tone="neutral">{c.object_type_label}</Badge>
          {c.core_rules.length > 0
            ? <Badge tone="accent" title={c.core_rules.map((id) => coreTitle.get(id) ?? id).join("\n")}>Also {brand.ruleSet}</Badge>
            : <span className="text-[11px] text-fg-muted">SCM only</span>}
        </div>
        {c.default_off_reason && (
          <p className="text-[12px] text-accent-fg leading-5 mt-1.5 mb-0">{c.default_off_reason}</p>
        )}
        <p className="text-[12px] text-fg-muted leading-5 mt-1.5 mb-0 max-w-3xl">{c.description}</p>
      </div>
      <div className="shrink-0">
        <SeveritySelect
          label={`Severity for check #${c.id}`}
          value={c.effective_severity}
          defaultSeverity={c.default_severity}
          override={c.severity_override}
          defaultNote={paloWording}
          onChange={(s) => onSeverity(c, s)}
        />
      </div>
    </div>
  );
}

/** Palo Alto SCM BPA checks: whether they count toward the score, and per-check enable/severity. */
export function ScmChecksSettings({ catalog, coreRules, query, filter, toolbar, onIncludeInScore, onToggle, onSeverity }: {
  catalog: ScmCatalog;
  toolbar: ReactNode;
  coreRules: RuleDef[];
  query: string;
  filter: string;
  onIncludeInScore: (value: boolean) => void;
  onToggle: (check: ScmCheck, enabled: boolean) => void;
  onSeverity: (check: ScmCheck, severity: string) => void;
}) {
  const coreTitle = useMemo(() => new Map(coreRules.map((r) => [r.id, r.title])), [coreRules]);
  const q = query.trim().toLowerCase();
  const shown = catalog.checks.filter((c) => {
    if (filter === "enabled" && !c.enabled) return false;
    if (filter === "disabled" && c.enabled) return false;
    if (filter === "overridden" && !c.severity_override) return false;
    if (filter === "linked" && c.core_rules.length === 0) return false;
    return !q || [`#${c.id}`, String(c.id), c.name, c.description, c.category, c.object_type_label]
      .some((v) => v.toLowerCase().includes(q));
  });
  const categories = Array.from(new Set(shown.map((c) => c.category))).sort();
  const covered = catalog.checks.filter((c) => c.core_rules.length > 0).length;
  const filtering = !!q || filter !== "all";

  return (
    <div>
      <div className="flex items-start gap-3 rounded-lg border border-line bg-surface-2 px-4 py-3 mb-4">
        <Switch checked={catalog.include_in_score} onChange={onIncludeInScore} label="Count Palo Alto SCM findings in the risk score" className="mt-0.5" />
        <div className="text-[13px] leading-5">
          <div className="font-medium text-fg">Count Palo Alto SCM findings in the risk score</div>
          <div className="text-fg-muted">
            Checks a {brand.ruleSet} rule already flagged are never counted twice. Turn this off to show SCM results for
            reference only.
          </div>
        </div>
      </div>

      <div className="flex items-center gap-x-4 gap-y-1 flex-wrap text-[12px] text-fg-muted mb-2 tab-num">
        <span><strong className="text-fg font-semibold">{catalog.checks.length}</strong> checks</span>
        <span><strong className="text-fg font-semibold">{covered}</strong> also covered by {brand.ruleSet}</span>
        <span>Catalogue retrieved {catalog.retrieved}</span>
        <span className={catalog.configured ? "text-good-fg" : undefined}>
          {catalog.configured ? "SCM configured on this server" : "SCM not configured on this server"}
        </span>
      </div>

      {toolbar}

      {categories.map((cat) => {
        const checks = shown.filter((c) => c.category === cat);
        const off = checks.filter((c) => !c.enabled).length;
        return (
          <Disclosure
            key={cat}
            title={cat}
            openFor={filtering ? `${filter}|${query}` : ""}
            meta={`${checks.length} check${checks.length === 1 ? "" : "s"} · ${checks.filter((c) => c.core_rules.length).length} also ${brand.ruleSetShort}${off ? ` · ${off} off` : ""}`}
          >
            {checks.map((c) => (
              <CheckRow key={c.id} check={c} coreTitle={coreTitle} onToggle={onToggle} onSeverity={onSeverity} />
            ))}
          </Disclosure>
        );
      })}
      {shown.length === 0 && <p className="text-[13px] text-fg-muted py-6 text-center m-0">No checks match.</p>}
    </div>
  );
}
