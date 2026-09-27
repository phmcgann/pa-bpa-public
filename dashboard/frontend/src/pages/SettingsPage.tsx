import { AlertCircle, Check, Loader2, Search } from "lucide-react";
import { ScmCheckRefs } from "../components/ScmCheckRefs";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api } from "../api";
import { BASIS_LABEL } from "../ruleBasis";
import { ScmChecksSettings } from "../components/ScmChecksSettings";
import { Badge, SeverityBadge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { Disclosure } from "../components/ui/Disclosure";
import { PageHeader } from "../components/ui/PageHeader";
import { SeverityIcon } from "../components/ui/SeverityIcon";
import { SeveritySelect } from "../components/ui/SeveritySelect";
import { Switch } from "../components/ui/Switch";
import { cn } from "../lib/cn";
import { SEVERITY_ORDER, severityLabel } from "../severity";
import type { RuleDef, ScmCatalog, ScmCheck, Severity, ScoringSettings } from "../types";
import { DASHBOARD_SECTIONS, useSectionVisibility } from "../useSectionVisibility";
import { brand } from "@brand";

type SaveState = "idle" | "saving" | "saved" | "error";

/** Every change saves immediately; this tracks the in-flight writes for the header's status line. */
function useSaver() {
  const [state, setState] = useState<SaveState>("idle");
  const pending = useRef(0);
  const save = useCallback(async (p: Promise<unknown>) => {
    pending.current += 1;
    setState("saving");
    try {
      await p;
      pending.current -= 1;
      if (pending.current === 0) setState("saved");
    } catch {
      pending.current -= 1;
      setState("error");
    }
  }, []);
  return { state, save };
}

function SaveStatus({ state }: { state: SaveState }) {
  if (state === "idle") return <span className="text-[12px] text-fg-muted">Changes save automatically</span>;
  if (state === "saving") return <span className="inline-flex items-center gap-1.5 text-[12px] text-fg-muted"><Loader2 size={13} className="animate-spin" />Saving…</span>;
  if (state === "error") return <span className="inline-flex items-center gap-1.5 text-[12px] text-critical-fg"><AlertCircle size={13} />Couldn't save — reload and try again</span>;
  return <span className="inline-flex items-center gap-1.5 text-[12px] text-good-fg"><Check size={13} />All changes saved</span>;
}

const NAV = [
  { id: "display", label: "Dashboard sections" },
  { id: "scoring", label: "Risk scoring" },
  { id: "core", label: `${brand.ruleSet} rules` },
  { id: "scm", label: "Palo Alto SCM checks" },
];

/** Which assessment tab each display toggle lives on, so the toggles read in the order you see them. */
const SECTION_GROUPS: { tab: string; keys: string[] }[] = [
  { tab: "Executive summary", keys: ["summary"] },
  { tab: "Overview", keys: ["charts", "system", "licenses", "advisories", "ha"] },
  { tab: "Remediation plan", keys: ["remediation"] },
  { tab: "Findings", keys: ["findings"] },
  { tab: "Policy & decryption", keys: ["policy", "nat", "rulebase", "decryption"] },
  { tab: "Security profiles", keys: ["threat"] },
  { tab: "Network & access", keys: ["zones", "access", "dos", "vpn", "certificates"] },
  { tab: "GlobalProtect", keys: ["globalprotect"] },
  { tab: "Changes since last run", keys: ["changes"] },
  { tab: "Palo Alto SCM", keys: ["scm"] },
];

const FILTERS = [
  { value: "all", label: "All" },
  { value: "enabled", label: "Enabled" },
  { value: "disabled", label: "Disabled" },
  { value: "overridden", label: "Recategorized" },
  { value: "linked", label: `Linked ${brand.ruleSetShort} ↔ SCM` },
];

function Toolbar({ query, onQuery, filter, onFilter, placeholder }: {
  query: string; onQuery: (v: string) => void; filter: string; onFilter: (v: string) => void; placeholder: string;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2 mb-3">
      <div className="relative flex-1 min-w-[200px] max-w-sm">
        <Search size={15} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-fg-faint pointer-events-none" aria-hidden="true" />
        <input type="search" value={query} onChange={(e) => onQuery(e.target.value)} placeholder={placeholder} aria-label={placeholder} className="w-full pl-8" />
      </div>
      <div role="radiogroup" aria-label="Filter" className="inline-flex flex-wrap p-0.5 rounded-lg bg-surface-3 border border-line">
        {FILTERS.map((f) => (
          <button
            key={f.value}
            type="button"
            role="radio"
            aria-checked={filter === f.value}
            onClick={() => onFilter(f.value)}
            className={cn(
              "h-7 px-2.5 rounded-md text-[12px] font-medium border-0 transition-colors",
              filter === f.value ? "bg-surface text-fg shadow-card" : "bg-transparent text-fg-muted hover:text-fg",
            )}
          >
            {f.label}
          </button>
        ))}
      </div>
    </div>
  );
}

function RuleRow({ rule, onToggle, onThreshold, onSeverity }: {
  rule: RuleDef;
  onToggle: (id: string, enabled: boolean) => void;
  onThreshold: (id: string, key: string, value: number) => void;
  onSeverity: (id: string, severity: string) => void;
}) {
  const thresholdKeys = Object.keys(rule.default_thresholds);
  const effective = { ...rule.default_thresholds, ...(rule.threshold_overrides || {}) };
  return (
    <div className={cn("flex gap-3 py-3 border-t border-divider first:border-t-0", !rule.enabled && "opacity-55")}>
      <Switch checked={rule.enabled} onChange={(v) => onToggle(rule.id, v)} label={`Enable ${rule.title}`} className="mt-0.5" />
      <div className="min-w-0 flex-1">
        <div className="text-[13px] font-medium text-fg leading-5">{rule.title}</div>
        <div className="flex items-center gap-2 flex-wrap mt-1.5">
          <Badge tone="accent" title={rule.source_ref ?? undefined}>{brand.ruleSet} · {BASIS_LABEL[rule.source_type]}</Badge>
          <ScmCheckRefs ids={rule.scm_check_ids} />
        </div>
        {rule.default_off_reason && (
          <p className="text-[12px] text-accent-fg leading-5 mt-1.5 mb-0">{rule.default_off_reason}</p>
        )}
        <p className="text-[12px] text-fg-muted leading-5 mt-1.5 mb-0 max-w-3xl">{rule.description}</p>
        {rule.source_type !== "custom" && rule.source_ref && (
          <p className="text-[11px] text-fg-faint leading-4 mt-1 mb-0 max-w-3xl">{rule.source_ref}</p>
        )}
        {thresholdKeys.length > 0 && (
          <div className="flex gap-4 flex-wrap mt-2">
            {thresholdKeys.map((k) => (
              <label key={k} className="inline-flex items-center gap-2 text-[12px] text-fg-2">
                {k.replace(/_/g, " ")}
                <input
                  type="number"
                  value={effective[k]}
                  onChange={(e) => onThreshold(rule.id, k, Number(e.target.value))}
                  className="w-20 tab-num"
                />
              </label>
            ))}
          </div>
        )}
      </div>
      <div className="shrink-0">
        <SeveritySelect
          label={`Severity for ${rule.title}`}
          value={rule.effective_severity}
          defaultSeverity={rule.default_severity}
          override={rule.severity_override}
          onChange={(s) => onSeverity(rule.id, s)}
        />
      </div>
    </div>
  );
}

function NumberField({ value, onChange, label, suffix }: {
  value: number; onChange: (v: number) => void; label: string; suffix?: string;
}) {
  return (
    <span className="relative inline-flex items-center">
      <input
        type="number"
        min={0}
        value={value}
        aria-label={label}
        onChange={(e) => onChange(Number(e.target.value))}
        className={cn("w-full tab-num", suffix && "pr-9")}
      />
      {suffix && <span className="absolute right-2.5 text-[12px] text-fg-muted pointer-events-none">{suffix}</span>}
    </span>
  );
}

function ScoringSettingsBody({ scoring, onChange }: {
  scoring: ScoringSettings;
  onChange: (patch: Partial<Record<string, number>>) => void;
}) {
  const weightField: Record<Severity, string> = {
    CRITICAL: "weight_critical", WARNING: "weight_warning", LOW: "weight_low", INFORMATIONAL: "weight_informational",
  };
  const t = scoring.thresholds;
  function labelFor(score: number): Severity {
    if (score <= t.informational_max) return "INFORMATIONAL";
    if (score <= t.low_max) return "LOW";
    if (score <= t.warning_max) return "WARNING";
    return "CRITICAL";
  }
  // Risk bands, lowest first: each owns the scores up to its ceiling.
  const bands: { sev: Severity; from: number; ceiling: number | null; field?: string }[] = [
    { sev: "INFORMATIONAL", from: 0, ceiling: t.informational_max, field: "informational_max" },
    { sev: "LOW", from: t.informational_max + 1, ceiling: t.low_max, field: "low_max" },
    { sev: "WARNING", from: t.low_max + 1, ceiling: t.warning_max, field: "warning_max" },
    { sev: "CRITICAL", from: t.warning_max + 1, ceiling: null },
  ];
  const oneCritical = scoring.weights.CRITICAL;
  const fiveLow = scoring.weights.LOW * 5;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h3 className="text-[13px] font-semibold text-fg m-0">Points per finding</h3>
        <p className="text-[12px] text-fg-muted mt-0.5 mb-3">Each active finding adds its severity's weight to the assessment's score.</p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {SEVERITY_ORDER.map((sev) => (
            <div key={sev} className="rounded-lg border border-line bg-surface px-3.5 py-3">
              <div className="flex items-center gap-1.5 text-[12px] font-medium text-fg-2 mb-2">
                <SeverityIcon severity={sev} size={13} />{severityLabel(sev)}
              </div>
              <NumberField
                value={scoring.weights[sev]}
                label={`${severityLabel(sev)} weight`}
                suffix="pts"
                onChange={(v) => onChange({ [weightField[sev]]: v })}
              />
            </div>
          ))}
        </div>
      </div>

      <div>
        <h3 className="text-[13px] font-semibold text-fg m-0">Overall risk from the score</h3>
        <p className="text-[12px] text-fg-muted mt-0.5 mb-3">
          The total score falls into one of these bands. The overall risk is never lower than the worst active finding.
        </p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-[2px] rounded-lg overflow-hidden border border-line bg-line">
          {bands.map((b) => (
            <div key={b.sev} className="bg-surface px-3.5 py-3">
              <div className="h-1 rounded-full mb-3" style={{ background: `var(--sev-${b.sev === "INFORMATIONAL" ? "info" : b.sev.toLowerCase()})` }} />
              <div className="flex items-center gap-1.5 text-[12px] font-medium text-fg-2">
                <SeverityIcon severity={b.sev} size={13} />{severityLabel(b.sev)}
              </div>
              <div className="text-[12px] text-fg-muted mt-1 tab-num">
                {b.ceiling === null ? `${b.from}+ pts` : b.from > b.ceiling ? "No scores (empty band)" : `${b.from}–${b.ceiling} pts`}
              </div>
              {b.field ? (
                <label className="flex items-center gap-2 mt-2 text-[12px] text-fg-2">
                  <span className="shrink-0">up to</span>
                  <NumberField value={b.ceiling!} label={`${severityLabel(b.sev)} ceiling`} onChange={(v) => onChange({ [b.field!]: v })} />
                </label>
              ) : (
                <div className="mt-2 h-8 flex items-center text-[12px] text-fg-muted">Everything above Warning</div>
              )}
            </div>
          ))}
        </div>
        <div className="flex items-center gap-x-4 gap-y-2 flex-wrap mt-3 text-[12px] text-fg-muted">
          <span className="inline-flex items-center gap-1.5">One Critical finding = {oneCritical} pts → <SeverityBadge severity={labelFor(oneCritical)} /></span>
          <span className="inline-flex items-center gap-1.5">Five Low findings = {fiveLow} pts → <SeverityBadge severity={labelFor(fiveLow)} /></span>
        </div>
      </div>
    </div>
  );
}

function Section({ id, title, description, children, actions }: {
  id: string; title: string; description?: ReactNode; children: ReactNode; actions?: ReactNode;
}) {
  return (
    <Card id={id} title={title} description={description} actions={actions} className="scroll-mt-6">
      {children}
    </Card>
  );
}

export function SettingsPage() {
  const [rules, setRules] = useState<RuleDef[]>([]);
  const [scoring, setScoring] = useState<ScoringSettings | null>(null);
  const [scmCatalog, setScmCatalog] = useState<ScmCatalog | null>(null);
  const [loading, setLoading] = useState(true);
  const [ruleQuery, setRuleQuery] = useState("");
  const [ruleFilter, setRuleFilter] = useState("all");
  const [scmQuery, setScmQuery] = useState("");
  const [scmFilter, setScmFilter] = useState("all");
  const { isVisible, setVisible } = useSectionVisibility();
  const { state: saveState, save } = useSaver();

  useEffect(() => {
    Promise.all([api.listRules(), api.getScoring(), api.getScmCatalog()]).then(([r, s, c]) => {
      setRules(r);
      setScoring(s);
      setScmCatalog(c);
      setLoading(false);
    });
  }, []);

  const q = ruleQuery.trim().toLowerCase();
  const shownRules = useMemo(() => rules.filter((r) => {
    if (ruleFilter === "enabled" && !r.enabled) return false;
    if (ruleFilter === "disabled" && r.enabled) return false;
    if (ruleFilter === "overridden" && !r.severity_override) return false;
    if (ruleFilter === "linked" && r.scm_check_ids.length === 0) return false;
    return !q || [r.title, r.description, r.category, r.source_ref ?? "", ...r.scm_check_ids.map((n) => `#${n}`)]
      .some((v) => v.toLowerCase().includes(q));
  }), [rules, ruleFilter, q]);
  const categories = useMemo(() => Array.from(new Set(shownRules.map((r) => r.category))), [shownRules]);
  const rulesFiltering = !!q || ruleFilter !== "all";

  function toggle(id: string, enabled: boolean) {
    setRules((prev) => prev.map((r) => (r.id === id ? { ...r, enabled } : r)));
    save(api.updateRule(id, { enabled }));
  }

  function setThreshold(id: string, key: string, value: number) {
    const rule = rules.find((r) => r.id === id);
    if (!rule) return;
    const overrides = { ...(rule.threshold_overrides || {}), [key]: value };
    setRules((prev) => prev.map((r) => (r.id === id ? { ...r, threshold_overrides: overrides } : r)));
    save(api.updateRule(id, { threshold_overrides: overrides }));
  }

  function setSeverity(id: string, severity: string) {
    const rule = rules.find((r) => r.id === id);
    if (!rule) return;
    const override = (severity || null) as Severity | null;
    const effective = override ?? rule.default_severity;
    setRules((prev) => prev.map((r) => (r.id === id ? { ...r, severity_override: override, effective_severity: effective } : r)));
    save(api.updateRule(id, { severity_override: severity }));
  }

  function patchScmCheck(id: number, patch: Partial<ScmCheck>) {
    setScmCatalog((prev) => prev && { ...prev, checks: prev.checks.map((c) => (c.id === id ? { ...c, ...patch } : c)) });
  }

  function toggleScm(check: ScmCheck, enabled: boolean) {
    patchScmCheck(check.id, { enabled });
    save(api.updateRule(check.rule_id, { enabled }));
  }

  function setScmSeverity(check: ScmCheck, severity: string) {
    const override = (severity || null) as Severity | null;
    patchScmCheck(check.id, { severity_override: override, effective_severity: override ?? check.default_severity });
    save(api.updateRule(check.rule_id, { severity_override: severity }));
  }

  function setScmIncludeInScore(value: boolean) {
    setScmCatalog((prev) => prev && { ...prev, include_in_score: value });
    save(api.updateScmSettings({ include_in_score: value }));
  }

  function updateScoring(patch: Partial<Record<string, number>>) {
    if (!scoring) return;
    const fieldToSeverity: Record<string, Severity> = {
      weight_critical: "CRITICAL", weight_warning: "WARNING", weight_low: "LOW", weight_informational: "INFORMATIONAL",
    };
    const next: ScoringSettings = { ...scoring, weights: { ...scoring.weights }, thresholds: { ...scoring.thresholds } };
    for (const [key, value] of Object.entries(patch)) {
      if (key in fieldToSeverity) next.weights[fieldToSeverity[key]] = value as number;
      else (next.thresholds as Record<string, number>)[key] = value as number;
    }
    setScoring(next);
    save(api.updateScoring(patch));
  }

  if (loading || !scoring) {
    return <div className="py-24 text-center text-fg-muted text-[13px]">Loading settings…</div>;
  }

  const enabledRules = rules.filter((r) => r.enabled).length;
  const overriddenRules = rules.filter((r) => r.severity_override).length;

  return (
    <div className="animate-in">
      <PageHeader
        title="Settings"
        description="What the assessment view shows, how findings are weighted into the overall risk, and which checks run."
        actions={<SaveStatus state={saveState} />}
      />

      <div className="grid grid-cols-1 xl:grid-cols-[200px_minmax(0,1fr)] gap-8 items-start">
        <nav aria-label="Settings sections" className="hidden xl:flex flex-col gap-0.5 sticky top-8">
          {NAV.map((n) => (
            <a key={n.id} href={`#${n.id}`} className="px-2.5 h-8 inline-flex items-center rounded-md text-[13px] text-fg-muted hover:text-fg hover:bg-surface-3 no-underline">
              {n.label}
            </a>
          ))}
        </nav>

        <div className="flex flex-col gap-5 min-w-0">
          <Section
            id="display"
            title="Dashboard sections"
            description="A display preference saved in this browser — hides a section from the assessment view and the printed report without changing what's analyzed or scored."
          >
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-4">
              {SECTION_GROUPS.map((g) => (
                <div key={g.tab}>
                  <div className="text-[11px] font-semibold tracking-[0.08em] uppercase text-fg-muted mb-1.5">{g.tab}</div>
                  {g.keys.map((key) => {
                    const s = DASHBOARD_SECTIONS.find((d) => d.key === key)!;
                    return (
                      <label key={key} className="flex items-center justify-between gap-3 py-1.5 text-[13px] text-fg cursor-pointer">
                        {s.label}
                        <Switch checked={isVisible(key)} onChange={(v) => setVisible(key, v)} label={`Show ${s.label}`} />
                      </label>
                    );
                  })}
                </div>
              ))}
            </div>
          </Section>

          <Section
            id="scoring"
            title="Risk scoring"
            description="Applies to every assessment immediately. Dismissed findings and findings on disabled rules never count."
          >
            <ScoringSettingsBody scoring={scoring} onChange={updateScoring} />
          </Section>

          <Section
            id="core"
            title={`${brand.ruleSet} rules`}
            description={
              <>
                {brand.company}'s own checks, run on every assessment — each labelled with what it's based on (CIS benchmark,
                Palo Alto documentation, or custom) and the matching Palo Alto SCM check where one exists. Changing a
                rule's severity recategorizes every finding it produces; turning a rule off removes it from findings and
                the score. To set aside a single occurrence instead, dismiss that finding on the assessment.
              </>
            }
          >
            <div className="flex items-center gap-x-4 gap-y-1 flex-wrap text-[12px] text-fg-muted mb-3 tab-num">
              <span><strong className="text-fg font-semibold">{rules.length}</strong> rules</span>
              <span><strong className="text-fg font-semibold">{enabledRules}</strong> enabled</span>
              <span><strong className="text-fg font-semibold">{rules.filter((r) => r.scm_check_ids.length).length}</strong> also a Palo Alto SCM check</span>
              {overriddenRules > 0 && <span><strong className="text-fg font-semibold">{overriddenRules}</strong> recategorized</span>}
            </div>
            <Toolbar query={ruleQuery} onQuery={setRuleQuery} filter={ruleFilter} onFilter={setRuleFilter} placeholder="Search rules…" />
            {categories.map((cat) => {
              const catRules = shownRules.filter((r) => r.category === cat);
              const off = catRules.filter((r) => !r.enabled).length;
              return (
                <Disclosure
                  key={cat}
                  title={cat}
                  openFor={rulesFiltering ? `${ruleFilter}|${ruleQuery}` : ""}
                  meta={`${catRules.length} rule${catRules.length === 1 ? "" : "s"}${off ? ` · ${off} off` : ""}`}
                >
                  {catRules.map((r) => (
                    <RuleRow key={r.id} rule={r} onToggle={toggle} onThreshold={setThreshold} onSeverity={setSeverity} />
                  ))}
                </Disclosure>
              );
            })}
            {shownRules.length === 0 && <p className="text-[13px] text-fg-muted py-6 text-center m-0">No rules match.</p>}
          </Section>

          {scmCatalog && (
            <Section
              id="scm"
              title="Palo Alto SCM checks"
              description={
                <>
                  Palo Alto's own Best Practice Assessment checks from Strata Cloud Manager, in Palo Alto's wording. They
                  run when you choose "Run Palo Alto SCM BPA" on an assessment. Turn checks off or change their severity
                  here the same way as {brand.ruleSet} rules.
                </>
              }
            >
              <ScmChecksSettings
                toolbar={<Toolbar query={scmQuery} onQuery={setScmQuery} filter={scmFilter} onFilter={setScmFilter} placeholder="Search checks by name or #…" />}
                catalog={scmCatalog}
                coreRules={rules}
                query={scmQuery}
                filter={scmFilter}
                onIncludeInScore={setScmIncludeInScore}
                onToggle={toggleScm}
                onSeverity={setScmSeverity}
              />
            </Section>
          )}
        </div>
      </div>
    </div>
  );
}
