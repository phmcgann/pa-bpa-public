import { ArrowRight, Cpu, FileText, Printer, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { flushSync } from "react-dom";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { Popover } from "../components/ui/Popover";
import { CategorySeverityChart } from "../components/CategorySeverityChart";
import { FindingsTable } from "../components/FindingsTable";
import { DEFAULT_VIEW, describeView, filterFindings, listedByDefault, type FindingsView } from "../findingsView";
import { GlobalProtectSection } from "../components/GlobalProtectSection";
import { ClientCombobox, SerialEdit } from "../components/IdentityFields";
import { MgmtPlaneSection } from "../components/MgmtPlaneSection";
import { HaConfigRows } from "../components/HaConfigRows";
import { AdvisoriesSection } from "../components/AdvisoriesSection";
import { CertificatesSection } from "../components/CertificatesSection";
import { CompareView } from "../components/CompareView";
import { ExecutiveSummary } from "../components/ExecutiveSummary";
import { VpnSection } from "../components/VpnSection";
import { DosSection } from "../components/DosSection";
import { MgmtReachability } from "../components/MgmtReachability";
import { PrintCover } from "../components/PrintCover";
import { NatTable } from "../components/NatTable";
import { NotesAppendix } from "../components/Notes";
import { NotesContext, flash, indexNotes, noteAnchor, noteRefAnchor, type NotesApi } from "../notes";
import { RemediationPlan } from "../components/RemediationPlan";
import { RuleTable } from "../components/RuleTable";
import { RulebaseSection } from "../components/RulebaseSection";
import { ScmBpaSection } from "../components/ScmBpaSection";
import { ScmCoverage } from "../components/ScmCoverage";
import { SectionCard } from "../components/SectionCard";
import { ThreatIntelCoverage } from "../components/ThreatIntelCoverage";
import { SeveritySummary } from "../components/SeveritySummary";
import { Badge, SeverityBadge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Callout } from "../components/ui/Callout";
import { Card, CardSection } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import { SeverityIcon } from "../components/ui/SeverityIcon";
import { Tabs } from "../components/ui/Tabs";
import { cn } from "../lib/cn";
import { brand } from "@brand";
import { usePrintFilename } from "../printFilename";

import type { AssessmentDetail, CompareResult, Finding, LicenseGate, Note, NoteKind, ProfileSettings, ReanalyzeResult, Severity, VulnerabilityException } from "../types";
import { useSectionVisibility } from "../useSectionVisibility";

function KV({ label, value, warn }: { label: string; value: ReactNode; warn?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-2 border-b border-divider last:border-b-0 text-[13px]">
      <span className="text-fg-muted">{label}</span>
      <span className={warn ? "font-medium text-critical-fg text-right" : "font-medium text-fg text-right tab-num"}>{value}</span>
    </div>
  );
}

function Unavailable({ reason }: { reason?: string }) {
  return <p className="text-[13px] text-fg-muted m-0 mt-2 leading-5">{reason}</p>;
}

function NotCaptured() {
  return (
    <p className="text-[13px] text-fg-muted m-0">
      Not captured for this assessment — re-upload the config to see this.
    </p>
  );
}

function InlineCloudGateNote({ gate }: { gate: LicenseGate | undefined }) {
  if (!gate) return null;
  const title = gate.status === "applies" ? "Inline Cloud Analysis checks included."
    : gate.status === "license_unknown" ? "Inline Cloud Analysis checks included, license unconfirmed."
    : "Inline Cloud Analysis checks skipped.";
  return (
    <Callout className="mb-4" title={title}>
      {gate.reason}
    </Callout>
  );
}

const SOURCE_LABEL: Record<string, string> = {
  file_upload: "Config export",
  panorama_export: "Panorama export",
  tsf_upload: "Tech support file",
  live: "Live device",
};

function SourceCallout({ assessment }: { assessment: AssessmentDetail }) {
  const { data } = assessment;
  if (assessment.source === "panorama_export") {
    return (
      <Callout title={`Resolved from a Panorama export — device group "${assessment.hostname || "unknown"}".`}>
        Rules are merged from shared and device-group pre/post-rulebases (see each rule's Scope); zones and
        NTP/login-banner settings come from the device group's template stack. This approximates Panorama's
        commit-time merge rather than replicating it. Admin accounts, PAN-OS version, licenses and HA state
        aren't derivable from a Panorama export and show as unavailable.
      </Callout>
    );
  }
  if (!data.panorama_managed) return null;
  if (assessment.source === "tsf_upload") {
    return (
      <Callout title="Panorama-managed firewall, assessed from a tech support file.">
        A tech support file carries PAN-OS's own merged, effective policy — so the sections below reflect the
        real pushed rules, zones and profiles, plus system info, licenses and HA state from the device.
      </Callout>
    );
  }
  return (
    <Callout tone="warning" title="This firewall is managed by Panorama.">
      Its own config export only holds local settings — the security policy, zones and profiles live in
      Panorama's device groups and templates, so sections showing no rules or profiles likely reflect that gap.
      Treat this assessment as incomplete; upload an export from Panorama itself to assess the pushed policy.
    </Callout>
  );
}

function Yes({ children }: { children: ReactNode }) {
  return <span className="text-good-fg">{children}</span>;
}
function Bad({ children }: { children: ReactNode }) {
  return <span className="text-critical-fg">{children}</span>;
}

const TLS_LABEL: Record<string, string> = {
  "tls1-0": "TLSv1.0", "tls1-1": "TLSv1.1", "tls1-2": "TLSv1.2", "tls1-3": "TLSv1.3", max: "Max",
};

const SCOPE_LABEL: Record<string, string> = {
  shared_pre: "Shared pre", device_group_pre: "Device group pre",
  device_group_post: "Device group post", shared_post: "Shared post",
};

// `inEffect` false → the setting exists but nothing enforces it, so no status color.
function OnOff({ value, inEffect }: { value: boolean | null | undefined; inEffect: boolean }) {
  if (value == null) return <span style={{ color: "var(--text-muted)" }}>Not set</span>;
  const color = !inEffect ? "var(--text-muted)" : value ? "var(--good-text)" : "var(--sev-critical-text)";
  return <span style={{ color }}>{value ? "Yes" : "No"}</span>;
}

const DECRYPT_ACTIONS = new Set(["decrypt", "decrypt-and-forward"]);

const SECURITY_PROFILE_TYPES: { key: string; label: string }[] = [
  { key: "antivirus", label: "Antivirus" },
  { key: "vulnerability", label: "Vulnerability Protection" },
  { key: "spyware", label: "Anti-Spyware" },
  { key: "url_filtering", label: "URL Filtering" },
  { key: "wildfire_analysis", label: "WildFire Analysis" },
  { key: "file_blocking", label: "File Blocking" },
];

const SECURITY_PROFILE_LABELS: Record<string, string> = Object.fromEntries(
  SECURITY_PROFILE_TYPES.map((t) => [t.key, t.label])
);

// Which BPA-vs-actual checks apply to each profile type — used to scope the
// per-profile "Issues" list to findings that actually belong to that profile.
const PROFILE_CHECK_RULE_IDS: Record<string, string[]> = {
  antivirus: ["av_decoder_below_baseline", "av_inline_ml_disabled"],
  spyware: [
    "spyware_severity_below_baseline", "spyware_dns_category_mismatch",
    "spyware_inline_cloud_analysis_disabled", "spyware_inline_cloud_model_not_reset",
  ],
  vulnerability: [
    "vulnerability_severity_below_baseline",
    "vulnerability_inline_cloud_analysis_disabled", "vulnerability_inline_cloud_model_not_reset",
  ],
  url_filtering: [
    "url_mandatory_category_not_blocked",
    "url_elevated_risk_category_not_blocked",
    "url_credential_enforcement_disabled",
  ],
  wildfire_analysis: ["wildfire_missing_recommended_filetype"],
  file_blocking: ["file_blocking_nothing_blocked"],
};

function profileIssues(ptype: string, profileName: string, findings: Finding[]): Finding[] {
  const ruleIds = PROFILE_CHECK_RULE_IDS[ptype] || [];
  return findings.filter(
    (f) =>
      !f.dismissed &&
      ruleIds.includes(f.rule_id) &&
      (f.finding_key === `${f.rule_id}:${profileName}` || f.finding_key.startsWith(`${f.rule_id}:${profileName}:`))
  );
}

function inlineCloudSummary(s: ProfileSettings): string {
  const ica = s.inline_cloud_analysis;
  if (!ica) return "";
  if (!ica.enabled) return " · Inline Cloud Analysis off";
  const models = Object.values(ica.models);
  const reset = models.filter((a) => a === "reset-both").length;
  return ` · Inline Cloud Analysis on (${reset}/${models.length} models reset-both)`;
}

function profileSettingsSummary(ptype: string, s: ProfileSettings): string {
  return baseSettingsSummary(ptype, s) +
    (ptype === "spyware" || ptype === "vulnerability" ? inlineCloudSummary(s) : "");
}

function baseSettingsSummary(ptype: string, s: ProfileSettings): string {
  switch (ptype) {
    case "antivirus": {
      const decoderCount = Object.keys(s.decoders || {}).length;
      const belowBaseline = Object.values(s.decoders || {}).filter(
        (d) => d.action !== "reset-both" || d.wildfire_action !== "reset-both" || d.mlav_action !== "reset-both"
      ).length;
      const mlEntries = Object.values(s.inline_ml || {});
      const mlEnabled = mlEntries.filter((a) => a !== "disable").length;
      return `${decoderCount} decoder${decoderCount === 1 ? "" : "s"} · ${belowBaseline} below baseline · ` +
        `Inline ML ${mlEnabled}/${mlEntries.length} enabled`;
    }
    case "spyware": {
      const rules = s.severity_rules || [];
      const dnsCats = Object.values(s.dns_categories || {});
      const sinkholed = dnsCats.filter((c) => c.action === "sinkhole").length;
      return `${rules.length} severity rule${rules.length === 1 ? "" : "s"} · DNS sinkhole ` +
        `${s.dns_sinkhole_enabled ? "enabled" : "NOT enabled"} · ${sinkholed}/${dnsCats.length} categories sinkholed`;
    }
    case "vulnerability": {
      const rules = s.severity_rules || [];
      return `${rules.length} severity rule${rules.length === 1 ? "" : "s"}`;
    }
    case "url_filtering": {
      const blockCount = (s.block_categories || []).length;
      const alertCount = (s.alert_categories || []).length;
      return `${blockCount} categories blocked · ${alertCount} alert-only · Credential enforcement: ` +
        `${s.credential_enforcement_mode === "disabled" ? "disabled" : s.credential_enforcement_mode}`;
    }
    case "wildfire_analysis": {
      const rules = s.rules || [];
      const fileTypes = new Set(rules.flatMap((r) => r.file_types));
      return `${rules.length} rule${rules.length === 1 ? "" : "s"} · ${fileTypes.size} file type${fileTypes.size === 1 ? "" : "s"} covered`;
    }
    case "file_blocking": {
      const rules = s.rules || [];
      const blocking = rules.filter((r) => r.action === "block").length;
      return `${rules.length} rule${rules.length === 1 ? "" : "s"} · ${blocking} block${blocking === 1 ? "s" : "ing"} traffic`;
    }
    default:
      return "";
  }
}

function profileExclusions(ptype: string, s: ProfileSettings): string[] {
  const out: string[] = [];
  if (ptype === "antivirus" && s.threat_exceptions?.length) {
    out.push(`${s.threat_exceptions.length} threat exception(s) by ID: ${(s.threat_exceptions as string[]).join(", ")}`);
  }
  if (ptype === "spyware") {
    if (s.whitelist?.length) {
      out.push(...s.whitelist.map((w) => `Whitelisted: ${w.name}${w.description ? ` — "${w.description}"` : ""}`));
    }
  }
  if (ptype === "vulnerability" && s.threat_exceptions?.length) {
    out.push(
      ...(s.threat_exceptions as VulnerabilityException[]).map(
        (e) => `Threat exception ${e.id} (${e.action})${e.exempt_ips.length ? ` — exempted IPs: ${e.exempt_ips.join(", ")}` : ""}`
      )
    );
  }
  return out;
}
const SEVERITY_RANK: Record<Severity, number> = { CRITICAL: 0, WARNING: 1, LOW: 2, INFORMATIONAL: 3 };

type TabId = "summary" | "overview" | "remediation" | "findings" | "policy" | "profiles" | "network" | "globalprotect" | "changes" | "scm" | "notes";

/**
 * Panels are all rendered (so the printed report includes every section); only the active one
 * shows on screen. On paper each panel opens a new page under a numbered section heading.
 */
function TabPanel({ id, active, heading, children }: {
  id: TabId; active: TabId; heading: { n: number; label: string } | null; children: ReactNode;
}) {
  return (
    <div
      role="tabpanel"
      id={`panel-${id}`}
      aria-labelledby={`tab-${id}`}
      className={cn(
        "tab-panel flex-col gap-5",
        id === active ? "flex animate-in" : "hidden",
        heading ? "print-section" : "print:!hidden",
      )}
    >
      {heading && (
        <div className="print-only print-section-heading">
          <div className="print-section-number">{String(heading.n).padStart(2, "0")}</div>
          <h2>{heading.label}</h2>
        </div>
      )}
      {children}
    </div>
  );
}

interface License { feature: string; expires: string; expired: string }

/** "December 14, 2025" → "Dec 14, 2025"; anything unparseable ("Never") passes through. */
function shortDate(text: string): string {
  const t = Date.parse(text);
  return Number.isNaN(t) ? text : new Date(t).toLocaleDateString(undefined, { dateStyle: "medium" });
}

const SOON_MS = 60 * 86_400_000;

/** Licenses as one compact table: expired first, then soonest to expire; a status pill per row. */
function LicenseTable({ licenses }: { licenses: License[] }) {
  const rows = licenses.map((l) => {
    const t = Date.parse(l.expires);
    const expired = l.expired === "yes";
    const soon = !expired && !Number.isNaN(t) && t - Date.now() < SOON_MS;
    return { ...l, t: Number.isNaN(t) ? Infinity : t, expired, soon };
  }).sort((a, b) => Number(b.expired) - Number(a.expired) || a.t - b.t || a.feature.localeCompare(b.feature));
  const expiredCount = rows.filter((r) => r.expired).length;
  const soonCount = rows.filter((r) => r.soon).length;
  if (rows.length === 0) return <p className="text-[13px] text-fg-muted m-0">No licenses in this file.</p>;
  return (
    <>
      <p className="text-[12px] text-fg-muted m-0 mb-2 tab-num">
        {rows.length} licenses
        {expiredCount > 0 && <> · <span className="text-critical-fg font-medium">{expiredCount} expired</span></>}
        {soonCount > 0 && <> · <span className="text-warning-fg font-medium">{soonCount} expiring within 60 days</span></>}
        {expiredCount === 0 && soonCount === 0 && " · all current"}
      </p>
      <div className="table-scroll">
        <table className="text-[12.5px]">
          <thead>
            <tr><th>License</th><th className="w-[84px]">Status</th><th className="w-[104px] text-right">Expires</th></tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.feature}>
                <td className="py-1.5 text-fg">{r.feature}</td>
                <td className="py-1.5">
                  {r.expired ? <Badge tone="critical">Expired</Badge>
                    : r.soon ? <Badge tone="warning">Expiring</Badge>
                    : <Badge tone="good">Active</Badge>}
                </td>
                <td className={cn("py-1.5 text-right whitespace-nowrap tab-num", r.expired ? "text-critical-fg" : "text-fg-2")}>
                  {r.t === Infinity && /never/i.test(r.expires) ? "No expiry" : shortDate(r.expires)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

function TopFindings({ findings, total, onOpen, onViewAll }: {
  findings: Finding[];
  total: number;
  onOpen: (severity: Severity) => void;
  onViewAll: () => void;
}) {
  const top = findings
    .filter((f) => !f.dismissed && !f.rule_disabled && !f.not_scored_reason)
    .sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity])
    .slice(0, 6);
  return (
    <Card title="Top findings" description="The most severe active findings." className="no-print" flush>
      {top.length === 0 ? (
        <p className="text-[13px] text-fg-muted px-5 pb-4 m-0">No active findings.</p>
      ) : (
        <ul className="m-0 p-0 list-none border-t border-divider">
          {top.map((f) => (
            <li key={f.finding_key} className="border-b border-divider">
              <button
                type="button"
                onClick={() => onOpen(f.severity)}
                className="w-full text-left flex gap-3 px-5 py-2.5 bg-transparent border-0 hover:bg-surface-2 transition-colors"
              >
                <SeverityIcon severity={f.severity} size={14} className="mt-[3px] shrink-0" />
                <span className="min-w-0 flex-1">
                  <span className="text-[13px] font-medium text-fg leading-5 line-clamp-2">{f.title}</span>
                  <span className="text-[12px] text-fg-muted leading-5 line-clamp-1 break-all">{f.category} · {f.message}</span>
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
      {total > 0 && (
        <div className="px-3 py-2">
          <Button variant="ghost" size="sm" onClick={onViewAll} className="w-full justify-between">
            View all {total} findings<ArrowRight size={14} />
          </Button>
        </div>
      )}
    </Card>
  );
}

/** Re-parses the stored file with the current parser and checks, in place. */
function ReanalyzeButton({ assessmentId, available, onDone }: {
  assessmentId: number; available: boolean; onDone: (r: ReanalyzeResult) => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <span className="inline-flex items-center gap-2">
      {error && <span className="text-[12px] text-critical-fg max-w-[260px] text-right">{error}</span>}
      <Button
        disabled={!available || busy}
        title={available
          ? "Parse the stored file again with the latest checks — no re-upload. Dismissals, notes and the Palo Alto SCM run are kept."
          : "This assessment was uploaded before its file was kept — upload it again to get the latest checks."}
        onClick={async () => {
          setBusy(true);
          setError(null);
          try {
            await onDone(await api.reanalyzeAssessment(assessmentId));
          } catch (e) {
            setError(e instanceof Error ? e.message : String(e));
          } finally {
            setBusy(false);
          }
        }}
      >
        <RefreshCw size={15} className={busy ? "animate-spin" : undefined} />{busy ? "Re-analyzing…" : "Re-analyze"}
      </Button>
    </span>
  );
}

function ReanalyzedCallout({ result, onClose }: { result: ReanalyzeResult; onClose: () => void }) {
  const { before, after } = result;
  const change = (a: number, b: number, unit: string) => (a === b ? `${b} ${unit}, unchanged` : `${a} → ${b} ${unit}`);
  return (
    <Callout title="Re-analyzed with the latest checks.">
      <span className="tab-num">
        Risk score {change(before.score, after.score, "points")}; {change(before.total, after.total, "active findings")}.
      </span>{" "}
      {!result.full_source && "System info, licenses and HA status are from the original upload: this tech support file was uploaded before those were kept. "}
      <button type="button" onClick={onClose} className="text-fg-muted underline underline-offset-2 bg-transparent border-0 p-0 cursor-pointer">
        Dismiss
      </button>
    </Callout>
  );
}

/** Print report; when the findings list is filtered, asks first whether to print just that or everything. */
function PrintButton({ narrowedBy, shown, total, onClearFilters }: {
  narrowedBy: string[]; shown: number; total: number; onClearFilters: () => void;
}) {
  if (narrowedBy.length === 0) {
    return (
      <Button onClick={() => window.print()}
        title="Opens the print dialog — choose 'Save as PDF'. Prints the branded cover, then every section in order.">
        <Printer size={15} />Print report
      </Button>
    );
  }
  return (
    <Popover
      align="end"
      width={340}
      trigger={({ toggle, ref }) => (
        <Button ref={ref as (el: HTMLButtonElement | null) => void} onClick={toggle}>
          <Printer size={15} />Print report
          <span className="text-[11px] px-1.5 rounded-full leading-[18px] bg-warning/15 text-warning-fg">Filtered</span>
        </Button>
      )}
    >
      {(close) => (
        <div className="p-4 flex flex-col gap-3 text-[13px]">
          <div>
            <div className="font-semibold text-fg">The findings list is filtered</div>
            <p className="m-0 mt-1 text-fg-2 leading-5">
              {narrowedBy.join(" · ")}: {shown} of {total} findings. The printed report will say it's a filtered view.
            </p>
          </div>
          <div className="flex flex-col gap-2">
            <Button variant="primary" onClick={() => { close(); onClearFilters(); window.print(); }}>
              Clear filters and print everything
            </Button>
            <Button onClick={() => { close(); setTimeout(() => window.print(), 0); }}>
              Print only these {shown} findings
            </Button>
          </div>
        </div>
      )}
    </Popover>
  );
}

export function DashboardPage() {
  const { id } = useParams<{ id: string }>();
  const [assessment, setAssessment] = useState<AssessmentDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [clients, setClients] = useState<string[]>([]);
  const [view, setView] = useState<FindingsView>(DEFAULT_VIEW);
  const [reanalyzed, setReanalyzed] = useState<ReanalyzeResult | null>(null);
  const { severity: severityFilter, category: categoryFilter } = view;
  const [params, setParams] = useSearchParams();
  const tabsRef = useRef<HTMLDivElement>(null);
  const { isVisible } = useSectionVisibility();
  usePrintFilename(
    assessment
      ? (assessment.hostname && assessment.hostname !== "N/A" ? assessment.hostname : assessment.filename.replace(/\.(xml|tgz|tar\.gz)$/i, ""))
      : null
  );

  const [changes, setChanges] = useState<CompareResult | null>(null);
  const load = useCallback(async () => {
    if (!id) return;
    const data = await api.getAssessment(Number(id));
    setAssessment(data);
    setLoading(false);
    // Loaded up front (not when the tab opens) so the printed report can include it.
    setChanges(data.previous_run ? await api.compareAssessments(data.previous_run.id, data.id).catch(() => null) : null);
  }, [id]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { api.listClients().then((c) => setClients(c.map((x) => x.name))); }, []);

  const tabs = useMemo(() => {
    const all: { id: TabId; label: string; count?: number; show: boolean }[] = [
      { id: "summary", label: "Executive summary", show: isVisible("summary") },
      { id: "overview", label: "Overview", show: true },
      {
        id: "remediation", label: "Remediation plan", count: assessment?.remediation?.length || undefined,
        show: isVisible("remediation") && !!assessment?.remediation,
      },
      { id: "findings", label: "Findings", count: assessment?.summary.total, show: isVisible("findings") },
      { id: "policy", label: "Policy & decryption", show: isVisible("policy") || isVisible("nat") || isVisible("rulebase") || isVisible("decryption") },
      { id: "profiles", label: "Security profiles", show: isVisible("threat") },
      { id: "network", label: "Network & access", show: isVisible("zones") || isVisible("access") || isVisible("dos") || isVisible("vpn") || isVisible("certificates") },
      {
        id: "globalprotect", label: "GlobalProtect",
        count: assessment?.findings.filter((f) => f.rule_id.startsWith("gp_") && !f.dismissed).length || undefined,
        show: isVisible("globalprotect") && !!(assessment?.data.globalprotect?.portals.length || assessment?.data.globalprotect?.gateways.length),
      },
      {
        id: "changes", label: "Changes since last run",
        count: changes ? changes.new.length + changes.resolved.length || undefined : undefined,
        show: isVisible("changes") && !!assessment?.previous_run,
      },
      { id: "scm", label: "Palo Alto SCM", show: isVisible("scm") },
      // Last, so it prints as the report's appendix.
      { id: "notes", label: "Notes", count: assessment?.notes?.length || undefined, show: !!assessment?.notes?.length },
    ];
    return all.filter((t) => t.show);
  }, [assessment, isVisible, changes]);
  // The printed report leaves out the Palo Alto SCM section until a run has produced results;
  // numbering and the cover's contents follow what actually prints.
  const printTabs = useMemo(
    () => tabs.filter((t) => t.id !== "scm" || assessment?.scm.run?.status === "completed"),
    [tabs, assessment],
  );
  const heading = (id: TabId) => {
    const i = printTabs.findIndex((t) => t.id === id);
    return i < 0 ? null : { n: i + 1, label: printTabs[i].label };
  };
  const requested = params.get("tab") as TabId | null;
  const defaultTab: TabId = tabs[0]?.id ?? "overview";
  const tab: TabId = tabs.some((t) => t.id === requested) ? requested! : defaultTab;

  function selectTab(next: string) {
    const p = new URLSearchParams(params);
    if (next === defaultTab) p.delete("tab"); else p.set("tab", next);
    setParams(p, { replace: true });
  }

  function showFindings(severity: Severity | "ALL", category = "ALL") {
    setView((v) => ({ ...v, severity, category }));
    selectTab("findings");
    requestAnimationFrame(() => tabsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }));
  }

  async function saveIdentity(body: { client_name?: string | null; serial?: string | null }) {
    if (!assessment) return;
    const updated = await api.updateAssessment(assessment.id, body);
    const { also_applied: _alsoApplied, ...identity } = updated;
    setAssessment({ ...assessment, ...identity });
    if ("client_name" in body) api.listClients().then((c) => setClients(c.map((x) => x.name)));
  }

  async function handleDismiss(key: string) {
    if (!assessment) return;
    await api.dismissFinding(assessment.id, key);
    load();
  }
  async function handleUndismiss(key: string) {
    if (!assessment) return;
    await api.undismissFinding(assessment.id, key);
    load();
  }

  // Clicking the tile that's already filtering, or Overall risk, clears the filter and stays put.
  function handleSeverityTileClick(severity: Severity | "ALL") {
    if (severity === "ALL" || (severity === severityFilter && categoryFilter === "ALL")) {
      setView((v) => ({ ...v, severity: "ALL", category: "ALL" }));
      return;
    }
    showFindings(severity);
  }

  function handleCategorySegmentClick(category: string, severity: Severity) {
    if (category === categoryFilter && severity === severityFilter) {
      showFindings("ALL");
      return;
    }
    showFindings(severity, category);
  }

  if (loading || !assessment) {
    return <div className="py-24 text-center text-fg-muted text-[13px]">Loading assessment…</div>;
  }

  const { data, findings, summary } = assessment;
  const narrowedBy = isVisible("findings") ? describeView(view) : [];
  const decryptionHasScope = data.decryption?.rules.some((r) => r.rule_scope) ?? false;
  const title = assessment.hostname || assessment.filename;
  const uploaded = new Date(assessment.uploaded_at);
  const sourceLabel = SOURCE_LABEL[assessment.source] ?? assessment.source;
  const model = assessment.model ?? (data.system_info.available ? data.system_info.model : null);
  const version = data.system_info.available ? data.system_info.sw_version : null;

  const notes = assessment.notes ?? [];
  const setNotes = (next: Note[]) => setAssessment((a) => (a ? { ...a, notes: next } : a));
  // Waits for the tab switch to render before scrolling.
  const afterRender = (fn: () => void) => setTimeout(fn, 60);
  const notesApi: NotesApi = {
    byTarget: indexNotes(notes),
    save: async (kind, key, label, body) => {
      setNotes(await api.saveNote(assessment.id, { target_kind: kind, target_key: key, target_label: label, body }));
    },
    remove: async (note) => setNotes(await api.deleteNote(assessment.id, note.id)),
    openNote: (note) => {
      selectTab("notes");
      afterRender(() => flash(document.getElementById(noteAnchor(note.number))));
    },
    openTarget: (note) => {
      const target: Record<NoteKind, TabId> = { finding: "findings", remediation: "remediation", security_rule: "policy",
                                                nat_rule: "policy" };
      // Clear filters so the finding's row is on screen.
      if (note.target_kind === "finding") setView({ ...DEFAULT_VIEW, showDismissed: true, showDisabledRule: true });
      selectTab(target[note.target_kind]);
      afterRender(() => flash(document.getElementById(noteRefAnchor(note.number))?.closest("tr, li") ?? null));
    },
  };

  return (
    <NotesContext.Provider value={notesApi}>
    <PrintCover assessment={assessment} sections={printTabs.map((t) => t.label)}
      findingsFilter={narrowedBy.length
        ? { narrowedBy, shown: filterFindings(findings, view).length, total: listedByDefault(findings) } : undefined} />
    <div className="animate-in">
      <div className="no-print">
      <PageHeader
        breadcrumb={<><Link to="/" className="text-fg-muted hover:text-fg">Assessments</Link><span className="mx-1.5 text-fg-faint">/</span><span className="text-fg-2">{title}</span></>}
        title={<span className="inline-flex flex-wrap items-center gap-3">{title}<SeverityBadge severity={summary.risk_label} className="text-[12px] h-6 px-2" /></span>}
        meta={
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-2 text-[13px] text-fg-2">
            <ClientCombobox value={assessment.client_name} clients={clients} onSave={(v) => saveIdentity({ client_name: v })} />
            <span className="inline-flex items-center gap-1.5">
              <Cpu size={14} className="text-fg-muted" aria-hidden="true" />
              {model ?? <span className="text-fg-muted">Model not in file</span>}
              {version && <span className="text-fg-muted">· PAN-OS {version}</span>}
            </span>
            <SerialEdit value={assessment.serial} onSave={(v) => saveIdentity({ serial: v })} />
            <span className="inline-flex items-center gap-1.5 text-fg-muted min-w-0 max-w-full" title={assessment.filename}>
              <FileText size={14} className="shrink-0" aria-hidden="true" />
              <span className="truncate">
                {assessment.filename} · {sourceLabel} · {uploaded.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}
                {assessment.reanalyzed_at && <> · re-analyzed {new Date(assessment.reanalyzed_at + "Z").toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}</>}
              </span>
            </span>
          </div>
        }
        actions={
          <div className="flex items-center gap-2">
          <ReanalyzeButton
            assessmentId={assessment.id}
            available={assessment.scm.config_stored}
            onDone={async (result) => { await load(); setReanalyzed(result); }}
          />
          <PrintButton
            narrowedBy={narrowedBy}
            shown={isVisible("findings") ? filterFindings(findings, view).length : 0}
            total={listedByDefault(findings)}
            onClearFilters={() => flushSync(() => setView(DEFAULT_VIEW))}
          />
          </div>
        }
      />
      </div>

      <div className="no-print flex flex-col gap-3 mb-6">
        <SeveritySummary summary={summary} activeSeverityFilter={severityFilter} onSeverityClick={handleSeverityTileClick} />
        {reanalyzed && <ReanalyzedCallout result={reanalyzed} onClose={() => setReanalyzed(null)} />}
        <SourceCallout assessment={assessment} />
      </div>

      <div ref={tabsRef} className="scroll-mt-4">
        <Tabs tabs={tabs} value={tab} onChange={selectTab} className="mb-5" />
      </div>

      {isVisible("summary") && (
        <TabPanel id="summary" active={tab} heading={heading("summary")}>
          <Card reportSection className="exec-summary-card" bodyClassName="px-6 py-6">
            <ExecutiveSummary assessment={assessment} changes={changes} onOpenPlan={() => selectTab("remediation")} />
          </Card>
        </TabPanel>
      )}

      <TabPanel id="overview" active={tab} heading={heading("overview")}>
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-5 items-start">
          <div className="xl:col-span-2 flex flex-col gap-5 min-w-0">
            {isVisible("charts") && (
              <SectionCard
                title="Findings by category"
                note="Scored findings by category and severity. Click a segment to see those findings."
              >
                <CategorySeverityChart
                  findings={findings}
                  activeCategory={categoryFilter}
                  activeSeverity={severityFilter}
                  onSegmentClick={handleCategorySegmentClick}
                />
              </SectionCard>
            )}
            <div className="grid grid-cols-1 md:grid-cols-5 gap-5 items-start">
              {(isVisible("system") || isVisible("ha")) && (
                <div className="overview-side md:col-span-2 flex flex-col gap-5 min-w-0">
                  {isVisible("system") && (
                    <SectionCard title="System">
                      <KV label="Hostname" value={data.system_info.hostname} />
                      {data.system_info.available ? (
                        <>
                          <KV label="Model" value={data.system_info.model} />
                          <KV label="PAN-OS" value={data.system_info.sw_version} />
                          <KV label="Serial" value={data.system_info.serial} />
                          <KV label="Uptime" value={data.system_info.uptime} />
                        </>
                      ) : (
                        <>
                          {data.system_info.serial && <KV label="Serial" value={data.system_info.serial} />}
                          <Unavailable reason={data.system_info.reason} />
                        </>
                      )}
                    </SectionCard>
                  )}
                  {isVisible("ha") && (
                    <SectionCard title="High availability" className="overview-ha">
                      {data.ha.available && (
                        <>
                          <KV label="Enabled" value={data.ha.enabled ? "Yes" : "No"} />
                          {data.ha.enabled && <KV label="Sync status" value={data.ha.sync_status} warn={data.ha.sync_status !== "synchronized"} />}
                        </>
                      )}
                      {data.ha_config ? (
                        <HaConfigRows ha={data.ha_config} findings={findings} />
                      ) : (
                        !data.ha.available && <Unavailable reason={data.ha.reason} />
                      )}
                    </SectionCard>
                  )}
                </div>
              )}
              {isVisible("licenses") && (
                <SectionCard title="Licenses" className="md:col-span-3" bare>
                  {data.licenses.available ? (
                    <LicenseTable licenses={data.licenses.licenses} />
                  ) : (
                    <Unavailable reason={data.licenses.reason} />
                  )}
                </SectionCard>
              )}
            </div>
            {isVisible("advisories") && assessment.advisories && (
              <SectionCard
                title="Known vulnerabilities"
                note="Palo Alto Networks security advisories that list this exact PAN-OS version and hotfix as affected. Some apply only when a feature is configured; each advisory says which."
              >
                <AdvisoriesSection report={assessment.advisories} />
              </SectionCard>
            )}
          </div>
          <TopFindings findings={findings} total={summary.total} onOpen={(s) => showFindings(s)} onViewAll={() => showFindings("ALL")} />
        </div>
      </TabPanel>

      {isVisible("remediation") && assessment.remediation && (
        <TabPanel id="remediation" active={tab} heading={heading("remediation")}>
          <SectionCard
            title="Remediation plan"
            note="The scored findings grouped into pieces of work, most urgent first. Dismissed findings and findings on disabled rules aren't included."
          >
            <RemediationPlan items={assessment.remediation} totalPoints={summary.score} findings={findings} />
          </SectionCard>
        </TabPanel>
      )}

      {isVisible("findings") && (
        <TabPanel id="findings" active={tab} heading={heading("findings")}>
          <SectionCard
            bare
            title="All findings"
            note="Dismiss a finding you've reviewed and accept — it's hidden and excluded from the score, not deleted. Findings on disabled security rules are excluded automatically."
          >
            <FindingsTable
              findings={findings}
              view={view}
              onViewChange={setView}
              onDismiss={handleDismiss}
              onUndismiss={handleUndismiss}
            />
          </SectionCard>
        </TabPanel>
      )}

      <TabPanel id="policy" active={tab} heading={heading("policy")}>
        {isVisible("policy") && assessment.threat_intel && data.security_rules.length > 0 && (
          <SectionCard
            title="Threat-intelligence blocking"
            note="Palo Alto Networks' built-in IP lists should each be blocked by a deny rule in both directions, and QUIC blocked so browsers fall back to TLS (Internet Gateway Best Practices, steps 1 and 3)."
            bare
          >
            <ThreatIntelCoverage coverage={assessment.threat_intel} />
          </SectionCard>
        )}
        {isVisible("policy") && (
          <SectionCard title="Security policy" note={`Every rule in evaluation order, with the ${brand.ruleSet} issues found on it.`}>
            <RuleTable rules={data.security_rules} findings={findings} />
          </SectionCard>
        )}
        {isVisible("nat") && data.nat_rules && data.nat_rules.length > 0 && (
          <SectionCard
            title="NAT policy"
            note="NAT rules in evaluation order — first match wins, on the packet before translation. Internet-facing zones are recognised by name."
          >
            <NatTable rules={data.nat_rules} findings={findings} />
          </SectionCard>
        )}
        {isVisible("rulebase") && assessment.rulebase && (
          <SectionCard
            title="Rulebase analysis"
            note="Rules an earlier rule makes unreachable, objects nothing uses, and objects that duplicate each other."
          >
            <RulebaseSection
              analysis={assessment.rulebase}
              unused={data.object_usage?.available ? data.object_usage.unused : null}
              unusedReason={data.object_usage ? data.object_usage.reason : "This assessment was uploaded before unused-object checks — re-upload the file to run them."}
              viaDynamicGroup={data.object_usage?.used_via_dynamic_group}
            />
          </SectionCard>
        )}
        {isVisible("decryption") && (
          <SectionCard
            title="Decryption"
            note="SSL/TLS decryption rules and the profiles they use. Without an active decrypt rule, security profiles can't see threats inside encrypted sessions."
          >
            {data.decryption === undefined ? (
              <NotCaptured />
            ) : (
              <>
                <CardSection title="Rules">
                  {data.decryption.rules.length === 0 ? (
                    <p className="text-[13px] text-critical-fg m-0">No decryption rules defined</p>
                  ) : (
                    <table>
                      <thead>
                        <tr>
                          <th>Rule</th>
                          {decryptionHasScope && <th>Scope</th>}
                          <th>Action</th><th>Type</th><th>Profile</th>
                        </tr>
                      </thead>
                      <tbody>
                        {data.decryption.rules.map((r) => {
                          const off = r.disabled === "yes";
                          return (
                            <tr key={`${r.rule_scope ?? ""}:${r.name}`} className={off ? "opacity-50" : undefined}>
                              <td className="font-medium">
                                {r.name}
                                {off && <span className="ml-2 text-[11px] text-fg-muted font-normal">Disabled</span>}
                              </td>
                              {decryptionHasScope && <td className="text-fg-2">{r.rule_scope ? SCOPE_LABEL[r.rule_scope] : "—"}</td>}
                              <td>{r.action}</td>
                              <td className="text-fg-2">{r.type}</td>
                              <td className={r.profile ? "" : "text-fg-muted"}>{r.profile ?? "None"}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  )}
                </CardSection>
                <CardSection title="Profiles">
                  {data.decryption.profiles.length === 0 ? (
                    <p className="text-[13px] text-fg-muted m-0">No decryption profiles defined.</p>
                  ) : (
                    <table>
                      <thead>
                        <tr>
                          <th>Profile</th><th>Used by enabled rules</th><th>Minimum TLS</th>
                          <th>Expired certs (forward proxy)</th><th>Untrusted issuers (forward proxy)</th>
                          <th>Expired certs (no-decrypt)</th><th>Untrusted issuers (no-decrypt)</th>
                        </tr>
                      </thead>
                      <tbody>
                        {data.decryption.profiles.map((p) => {
                          const activeUsers = data.decryption?.rules.filter(
                            (r) => r.profile === p.name && r.disabled !== "yes" && DECRYPT_ACTIONS.has(r.action)
                          ) ?? [];
                          const inEffect = activeUsers.length > 0;
                          const forwardProxyInEffect = activeUsers.some((r) => r.type === "ssl-forward-proxy");
                          const noDecryptUsers = data.decryption?.rules.filter(
                            (r) => r.profile === p.name && r.disabled !== "yes" && r.action === "no-decrypt"
                          ) ?? [];
                          const noDecryptInEffect = noDecryptUsers.length > 0;
                          const weak = p.min_version === "tls1-0" || p.min_version === "tls1-1";
                          return (
                            <tr key={p.name}>
                              <td className="font-medium">{p.name}</td>
                              <td className={inEffect || noDecryptInEffect ? "" : "text-fg-muted"}>
                                {[...activeUsers, ...noDecryptUsers].map((r) => r.name).join(", ") || "None"}
                              </td>
                              <td className={!inEffect ? "text-fg-muted" : weak ? "text-critical-fg" : "text-good-fg"}>
                                {TLS_LABEL[p.min_version] ?? p.min_version}
                                {!p.min_version_explicit && <span className="text-[11px] text-fg-muted"> (PAN-OS default)</span>}
                              </td>
                              <td><OnOff value={p.forward_proxy_block_expired} inEffect={forwardProxyInEffect} /></td>
                              <td><OnOff value={p.forward_proxy_block_untrusted} inEffect={forwardProxyInEffect} /></td>
                              <td><OnOff value={p.no_proxy_block_expired ?? null} inEffect={noDecryptInEffect} /></td>
                              <td><OnOff value={p.no_proxy_block_untrusted ?? null} inEffect={noDecryptInEffect} /></td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  )}
                </CardSection>
              </>
            )}
          </SectionCard>
        )}
      </TabPanel>

      {isVisible("threat") && (
        <TabPanel id="profiles" active={tab} heading={heading("profiles")}>
          <SectionCard
            title="Security profiles"
            note="Each profile type: how many rules use each profile, what's configured inside it, and where it differs from Palo Alto's best-practice guidance."
          >
            <InlineCloudGateNote gate={assessment.license_gates?.inline_cloud_analysis} />
            {SECURITY_PROFILE_TYPES.map(({ key, label }) => {
              const entries = data.security_profiles[key] || [];
              return (
                <CardSection key={key} title={label}>
                  {entries.length === 0 ? (
                    <p className="text-[13px] text-critical-fg m-0">No {label.toLowerCase()} profiles defined</p>
                  ) : (
                    <table>
                      <thead>
                        <tr>
                          <th className="w-[180px]">Profile</th>
                          <th className="w-[90px]">Rules using it</th>
                          <th>Configuration</th>
                          <th>vs. best practice</th>
                        </tr>
                      </thead>
                      <tbody>
                        {entries.map((p) => {
                          // Assessments stored before profile settings were captured have no
                          // "settings" at all — shown as not captured, not as a pile of gaps.
                          const hasSettings = p.settings !== undefined;
                          const settings = p.settings || {};
                          const issues = profileIssues(key, p.name, findings);
                          const exclusions = profileExclusions(key, settings);
                          return (
                            <tr key={p.name}>
                              <td className="font-medium">{p.name}</td>
                              <td className={p.rule_count === 0 ? "text-fg-muted tab-num" : "tab-num"}>{p.rule_count}</td>
                              <td className="text-fg-2 text-[12px]">
                                {hasSettings ? (
                                  <>
                                    {profileSettingsSummary(key, settings)}
                                    {exclusions.length > 0 && (
                                      <div className="mt-1.5">
                                        <div className="eyebrow text-[10px]">Exclusions</div>
                                        <ul className="m-0 mt-0.5 pl-4">
                                          {exclusions.map((ex, i) => <li key={i}>{ex}</li>)}
                                        </ul>
                                      </div>
                                    )}
                                  </>
                                ) : (
                                  <span className="text-fg-muted">Not captured — re-upload to see configuration details</span>
                                )}
                              </td>
                              <td className="text-[12px]">
                                {!hasSettings ? (
                                  <span className="text-fg-muted">—</span>
                                ) : issues.length === 0 ? (
                                  <Yes>Matches best practice</Yes>
                                ) : (
                                  <ul className="m-0 pl-0 list-none flex flex-col gap-1">
                                    {issues.map((i) => (
                                      <li key={i.finding_key} className="flex gap-1.5">
                                        <SeverityIcon severity={i.severity} size={12} className="mt-0.5 shrink-0" />
                                        <span className="text-fg-2">{i.message}</span>
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
                  )}
                </CardSection>
              );
            })}

            <CardSection title="Security profile groups">
              {data.profile_groups.length === 0 ? (
                <p className="text-[13px] text-fg-muted m-0">No security profile groups defined.</p>
              ) : (
                <table>
                  <thead><tr><th>Group</th><th>Profiles</th><th className="w-[120px]">Rules using it</th></tr></thead>
                  <tbody>
                    {data.profile_groups.map((g) => (
                      <tr key={g.name}>
                        <td className="font-medium">{g.name}</td>
                        <td className="text-fg-2">
                          {Object.entries(g.members)
                            .map(([type, names]) => `${SECURITY_PROFILE_LABELS[type] ?? type}: ${names.join(", ")}`)
                            .join(" · ") || "—"}
                        </td>
                        <td className="tab-num">{g.rule_count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </CardSection>
          </SectionCard>
        </TabPanel>
      )}

      <TabPanel id="network" active={tab} heading={heading("network")}>
        {isVisible("zones") && (
          <SectionCard title="Security zones">
            <table>
              <thead><tr><th>Zone</th><th>Mode</th><th>Zone protection profile</th></tr></thead>
              <tbody>
                {data.zones.map((z) => (
                  <tr key={z.name}>
                    <td className="font-medium">{z.name}</td>
                    <td className="text-fg-2">{z.mode}</td>
                    <td>{z.zone_protection_profile || <Bad>Not assigned</Bad>}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            <CardSection title="Zone protection profiles">
              {data.zone_protection_profiles === undefined ? (
                <NotCaptured />
              ) : data.zone_protection_profiles.length === 0 ? (
                <p className="text-[13px] text-fg-muted m-0">No zone protection profiles defined.</p>
              ) : (
                <table>
                  <thead>
                    <tr><th>Profile</th><th>Assigned zones</th><th>Flood protection</th><th>Reconnaissance protection (scan: action)</th><th>Packet-based attacks</th></tr>
                  </thead>
                  <tbody>
                    {data.zone_protection_profiles.map((p) => {
                      const zones = data.zones.filter((z) => z.zone_protection_profile === p.name).map((z) => z.name);
                      const floodEntries = Object.entries(p.flood);
                      const enabled = floodEntries.filter(([, v]) => v === true).map(([k]) => k);
                      const disabled = floodEntries.filter(([, v]) => v === false).map(([k]) => k);
                      const activeScans = p.scans.filter((s) => s.action !== "allow");
                      return (
                        <tr key={p.name} className={zones.length ? undefined : "opacity-60"}>
                          <td className="font-medium">{p.name}</td>
                          <td className={zones.length ? "" : "text-fg-muted"}>{zones.join(", ") || "Not assigned"}</td>
                          <td className="text-[12px]">
                            {enabled.length > 0 && (
                              <div><Yes>On:</Yes> {enabled.join(", ")}{p.syn_action && enabled.includes("tcp-syn") ? ` (SYN: ${p.syn_action})` : ""}</div>
                            )}
                            {disabled.length > 0 && <div><Bad>Off:</Bad> {disabled.join(", ")}</div>}
                            {enabled.length === 0 && disabled.length === 0 && <span className="text-fg-muted">Not set in config</span>}
                          </td>
                          <td className="text-[12px]">
                            {p.scans.length === 0 ? (
                              <Bad>None enabled</Bad>
                            ) : (
                              <span className={activeScans.length ? "" : "text-critical-fg"}>
                                {p.scans.map((s) => `${s.id}: ${s.action}`).join(" · ")}
                              </span>
                            )}
                          </td>
                          <td className="text-[12px] tab-num">
                            {p.packet_based === undefined ? <span className="text-fg-muted">—</span> : (() => {
                              const opts = Object.values(p.packet_based);
                              const on = opts.filter(Boolean).length;
                              const flagged = findings.some((f) => !f.dismissed && f.finding_key === `zone_protection_packet_based_off:${p.name}`);
                              return <span className={flagged ? "text-critical-fg" : ""}>{on} of {opts.length} recommended drops on</span>;
                            })()}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </CardSection>
          </SectionCard>
        )}

        {isVisible("access") && (
          <SectionCard title="Administrative access">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-x-8">
              <div>
                <KV label="Management ACL (permitted IPs)" value={data.management.mgmt_acl ? "Configured" : "Not configured"} warn={!data.management.mgmt_acl} />
                <KV label="Login banner" value={data.management.login_banner ? "Configured" : "Not set"} warn={!data.management.login_banner} />
                <KV label="NTP primary" value={data.management.ntp_primary || "Not set"} warn={!data.management.ntp_primary} />
                <KV label="Syslog server profiles" value={String(data.syslog_profiles)} warn={data.syslog_profiles === 0} />
              </div>
              <div>
                <table>
                  <thead><tr><th>Administrator</th><th>Authentication profile</th></tr></thead>
                  <tbody>
                    {data.admin_accounts.map((a) => (
                      <tr key={a.name}>
                        <td className="font-medium">{a.name}</td>
                        <td>{a.auth_profile === "local" ? <Bad>local</Bad> : <Yes>{a.auth_profile}</Yes>}</td>
                      </tr>
                    ))}
                    {data.admin_accounts.length === 0 && (
                      <tr><td colSpan={2} className="text-fg-muted">No administrator accounts in this file.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {data.mgmt_plane && (
              <CardSection
                title="Management plane"
                description="Administrator sign-in, authentication servers, log forwarding and content updates. Red values have an open finding."
              >
                <MgmtPlaneSection mp={data.mgmt_plane} findings={findings} />
              </CardSection>
            )}

            <CardSection title="Interface management profiles">
              {data.interface_mgmt_profiles === undefined ? (
                <NotCaptured />
              ) : data.interface_mgmt_profiles.length === 0 ? (
                <p className="text-[13px] text-fg-muted m-0">No interface management profiles defined.</p>
              ) : (
                <table>
                  <thead><tr><th>Profile</th><th>Services enabled</th><th>Permitted IPs</th><th>Attached to</th></tr></thead>
                  <tbody>
                    {data.interface_mgmt_profiles.map((p) => {
                      const services = Object.entries(p.services).filter(([, on]) => on).map(([s]) => s);
                      return (
                        <tr key={p.name} className={p.interfaces.length ? undefined : "opacity-60"}>
                          <td className="font-medium">{p.name}</td>
                          <td>
                            {services.length === 0 ? <span className="text-fg-muted">None</span> : services.map((s, i) => (
                              <span key={s} className={s === "telnet" || s === "http" ? "text-critical-fg" : ""}>{i > 0 && ", "}{s}</span>
                            ))}
                          </td>
                          <td className={p.permitted_ip.length ? "" : "text-fg-muted"}>{p.permitted_ip.join(", ") || "Any"}</td>
                          <td className={p.interfaces.length ? "" : "text-fg-muted"}>{p.interfaces.join(", ") || "Not attached"}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </CardSection>

            <CardSection
              title="Management access reachability"
              description="Who can reach each interface's management services, checking both the profile's permitted-IP list and security policy from every zone — walked top-down, first match wins, so a catch-all deny ends the walk. Flagged only when there's no permitted-IP list and policy allows any source."
            >
              {assessment.mgmt_exposure == null ? <NotCaptured /> : <MgmtReachability exposure={assessment.mgmt_exposure} />}
            </CardSection>
          </SectionCard>
        )}
        {isVisible("dos") && data.dos && (
          <SectionCard
            title="DoS & session protection"
            note="DoS Protection policy and profiles, zone Packet Buffer Protection and global session settings. Red values have an open finding."
          >
            <DosSection data={data} findings={findings} />
          </SectionCard>
        )}

        {isVisible("vpn") && data.vpn && (data.vpn.tunnels.length > 0 || data.vpn.gateways.length > 0) && (
          <SectionCard
            title="Site-to-site VPN"
            note="IPSec tunnels, their IKE gateways and the crypto profiles they negotiate. Red values have an open finding."
          >
            <VpnSection vpn={data.vpn} findings={findings} />
          </SectionCard>
        )}

        {isVisible("certificates") && data.certificates && data.certificates.certificates.length > 0 && (
          <SectionCard
            title="Certificates"
            note="Certificates in the configuration, soonest expiry first, and what uses each one. Red values have an open finding; faded rows aren't used."
          >
            <CertificatesSection certs={data.certificates.certificates} findings={findings} />
          </SectionCard>
        )}
      </TabPanel>

      {isVisible("globalprotect") && data.globalprotect && (
        <TabPanel id="globalprotect" active={tab} heading={heading("globalprotect")}>
          <GlobalProtectSection
            portals={data.globalprotect.portals}
            gateways={data.globalprotect.gateways}
            findings={findings}
            onShowFindings={() => showFindings("ALL", "GlobalProtect")}
          />
        </TabPanel>
      )}

      {isVisible("changes") && assessment.previous_run && (
        <TabPanel id="changes" active={tab} heading={heading("changes")}>
          <p className="text-[13px] text-fg-muted m-0">
            Compared with this firewall's previous run,{" "}
            <Link to={`/assessments/${assessment.previous_run.id}`} className="text-accent-fg hover:underline">
              {new Date(assessment.previous_run.uploaded_at).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}
            </Link>
            {" "}({assessment.previous_run.filename}).
          </p>
          {changes ? <CompareView result={changes} /> : <p className="text-[13px] text-fg-muted">Comparing…</p>}
        </TabPanel>
      )}

      {isVisible("scm") && (
        <TabPanel id="scm" active={tab} heading={heading("scm")}>
          <SectionCard
            bare
            title="Palo Alto SCM Best Practice Assessment"
            note={`Palo Alto Networks' own BPA checks from Strata Cloud Manager, in Palo Alto's wording. Its findings join the ${brand.ruleSet} findings, tagged PAN SCM with the check number.`}
          >
            <ScmBpaSection
              scm={assessment.scm}
              findings={findings}
              onRun={async () => { await api.runScmBpa(assessment.id); await load(); }}
            />
          </SectionCard>
          {assessment.scm_coverage && (
            <SectionCard
              title={`${brand.ruleSet} coverage of this SCM run`}
              note={`Every failed SCM check, and whether a ${brand.ruleSetShort} rule caught the same thing. Gaps are what would go unreported if the SCM BPA couldn't be run. Uses the stored run, so it stays available.`}
            >
              <ScmCoverage coverage={assessment.scm_coverage} />
            </SectionCard>
          )}
        </TabPanel>
      )}

      {notes.length > 0 && (
        <TabPanel id="notes" active={tab} heading={heading("notes")}>
          <SectionCard
            title="Notes"
            note="Notes added to findings and other entries, numbered in the order they were added. A numbered marker on an entry points here."
          >
            <NotesAppendix notes={notes} />
          </SectionCard>
        </TabPanel>
      )}
    </div>
    </NotesContext.Provider>
  );
}



