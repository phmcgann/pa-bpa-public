import { ExternalLink, FileSearch, GitCompare, MoreHorizontal, Search, Trash2, Upload, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { ClientCombobox, SerialEdit } from "../components/IdentityFields";
import { RiskTrendChart, type TrendSeries } from "../components/RiskTrendChart";
import { SeverityBadge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { EmptyState, PageHeader } from "../components/ui/PageHeader";
import { MenuItem, Popover } from "../components/ui/Popover";
import { SeverityIcon } from "../components/ui/SeverityIcon";
import { Stat } from "../components/ui/Stat";
import { SEVERITY_META, SEVERITY_ORDER } from "../severity";
import type { AssessmentListItem } from "../types";
import { brand } from "@brand";

const NO_CLIENT = "__none__";

/** One physical firewall across runs: its serial when known, otherwise its hostname. */
function deviceKey(a: AssessmentListItem): string {
  return a.serial ? `sn:${a.serial}` : `host:${a.hostname || a.filename}`;
}

function deviceName(a: AssessmentListItem): string {
  return a.hostname || a.filename;
}

const SOURCE_LABEL: Record<string, string> = {
  file_upload: "Config export", panorama_export: "Panorama export", tsf_upload: "Tech support file", live: "Live device",
};

/** Severity mix as a thin stacked bar (2px gaps), with the counts in its accessible label. */
function SeverityMix({ counts }: { counts: AssessmentListItem["summary"]["severity_counts"] }) {
  const total = SEVERITY_ORDER.reduce((n, s) => n + counts[s], 0);
  const label = SEVERITY_ORDER.map((s) => `${counts[s]} ${SEVERITY_META[s].label.toLowerCase()}`).join(", ");
  return (
    <div className="flex items-center gap-2.5" title={label}>
      <span className="tab-num text-fg w-8 text-right">{total}</span>
      <div className="flex gap-[2px] w-24 h-1.5" role="img" aria-label={label}>
        {total > 0 ? SEVERITY_ORDER.filter((s) => counts[s] > 0).map((s) => (
          <span key={s} className="h-full rounded-[2px]" style={{ flex: counts[s], background: SEVERITY_META[s].color }} />
        )) : <span className="h-full w-full rounded-[2px] bg-surface-3" />}
      </div>
    </div>
  );
}

function RowMenu({ onOpen, onDelete, onComparePrevious }: {
  onOpen: () => void; onDelete: () => void; onComparePrevious?: () => void;
}) {
  return (
    <Popover
      align="end"
      width={230}
      trigger={({ toggle, ref, open }) => (
        <Button
          ref={ref as (el: HTMLButtonElement | null) => void}
          variant="ghost" size="sm" iconOnly aria-label="Row actions" aria-expanded={open}
          onClick={(e) => { e.stopPropagation(); toggle(); }}
        >
          <MoreHorizontal size={16} />
        </Button>
      )}
    >
      {(close) => (
        <>
          <MenuItem icon={<ExternalLink size={14} />} onSelect={() => { close(); onOpen(); }}>Open</MenuItem>
          {onComparePrevious && (
            <MenuItem icon={<GitCompare size={14} />} onSelect={() => { close(); onComparePrevious(); }}>
              Compare with previous run
            </MenuItem>
          )}
          <MenuItem danger icon={<Trash2 size={14} />} onSelect={() => { close(); onDelete(); }}>Delete</MenuItem>
        </>
      )}
    </Popover>
  );
}

export function HistoryPage() {
  const [items, setItems] = useState<AssessmentListItem[] | null>(null);
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const clientFilter = params.get("client") ?? "";
  const deviceFilter = params.get("device") ?? "";
  const query = params.get("q") ?? "";

  function load() {
    api.listAssessments().then(setItems);
  }
  useEffect(load, []);

  function setParam(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value); else next.delete(key);
    if (key === "client") next.delete("device");
    setParams(next, { replace: true });
  }

  const clientNames = useMemo(
    () => [...new Set((items ?? []).map((a) => a.client_name).filter((c): c is string => !!c))]
      .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" })),
    [items],
  );

  const forClient = useMemo(() => (items ?? []).filter((a) =>
    clientFilter === "" ? true : clientFilter === NO_CLIENT ? !a.client_name : a.client_name === clientFilter
  ), [items, clientFilter]);

  // Firewalls within the selected client, most recently assessed first.
  const devices = useMemo(() => {
    const byKey = new Map<string, AssessmentListItem[]>();
    for (const a of forClient) byKey.set(deviceKey(a), [...(byKey.get(deviceKey(a)) ?? []), a]);
    return [...byKey.entries()]
      .map(([key, runs]) => ({ key, runs, latest: runs[0] }))
      .sort((a, b) => new Date(b.latest.uploaded_at).getTime() - new Date(a.latest.uploaded_at).getTime());
  }, [forClient]);
  const activeDevice = devices.some((d) => d.key === deviceFilter) ? deviceFilter : "";

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return forClient.filter((a) =>
      (!activeDevice || deviceKey(a) === activeDevice) &&
      (!q || [a.hostname, a.filename, a.serial, a.model, a.client_name].some((v) => v?.toLowerCase().includes(q)))
    );
  }, [forClient, activeDevice, query]);

  // Chart colours follow the firewall, not its position: slots go by when each firewall was first
  // assessed, so a filter never repaints the lines that remain.
  const colorSlot = useMemo(() => {
    const first = new Map<string, number>();
    for (const a of items ?? []) {
      const t = new Date(a.uploaded_at).getTime();
      first.set(deviceKey(a), Math.min(first.get(deviceKey(a)) ?? Infinity, t));
    }
    return new Map([...first.entries()].sort((a, b) => a[1] - b[1]).map(([key], i) => [key, i]));
  }, [items]);

  const series: TrendSeries[] = useMemo(() => {
    const byKey = new Map<string, AssessmentListItem[]>();
    for (const a of shown) byKey.set(deviceKey(a), [...(byKey.get(deviceKey(a)) ?? []), a]);
    return [...byKey.entries()]
      .map(([key, runs]) => ({
        key, runs, label: deviceName(runs[0]), slot: colorSlot.get(key),
        latest: new Date(runs[0].uploaded_at).getTime(),
      }))
      .sort((a, b) => b.latest - a.latest);
  }, [shown, colorSlot]);

  const latestPerDevice = series.map((s) => s.runs[0]);
  const criticalNow = latestPerDevice.filter((a) => a.summary.risk_label === "CRITICAL").length;
  const clientsInScope = new Set(shown.map((a) => a.client_name).filter(Boolean)).size;
  const unassigned = latestPerDevice.filter((a) => !a.client_name).length;
  const filtered = !!(clientFilter || activeDevice || query);
  const deviceCount = new Set((items ?? []).map(deviceKey)).size;

  // Two ticked rows can be compared; the earlier one is always the baseline.
  const [picked, setPicked] = useState<number[]>([]);
  function togglePick(id: number) {
    setPicked((p) => p.includes(id) ? p.filter((x) => x !== id) : [...p, id].slice(-2));
  }
  function compare(a: AssessmentListItem, b: AssessmentListItem) {
    const [base, target] = new Date(a.uploaded_at) <= new Date(b.uploaded_at) ? [a, b] : [b, a];
    navigate(`/compare?base=${base.id}&target=${target.id}`);
  }
  // The run just before this one on the same firewall, if any.
  function previousRun(a: AssessmentListItem): AssessmentListItem | undefined {
    return (items ?? [])
      .filter((x) => deviceKey(x) === deviceKey(a) && new Date(x.uploaded_at) < new Date(a.uploaded_at))
      .sort((x, y) => new Date(y.uploaded_at).getTime() - new Date(x.uploaded_at).getTime())[0];
  }
  const pickedItems = picked.map((id) => (items ?? []).find((a) => a.id === id)).filter((a): a is AssessmentListItem => !!a);

  async function saveIdentity(id: number, body: { client_name?: string | null; serial?: string | null }) {
    const updated = await api.updateAssessment(id, body);
    if (updated.also_applied) load();
    else setItems((prev) => prev?.map((a) => (a.id === id ? { ...a, ...updated } : a)) ?? null);
  }

  async function remove(a: AssessmentListItem) {
    if (!confirm(`Delete the assessment of ${deviceName(a)} from ${new Date(a.uploaded_at).toLocaleString()}?`)) return;
    await api.deleteAssessment(a.id);
    load();
  }

  const activeDeviceRow = devices.find((d) => d.key === activeDevice);
  const scopeLabel = activeDeviceRow
    ? deviceName(activeDeviceRow.latest)
    : clientFilter === NO_CLIENT ? "No client assigned" : clientFilter || "All clients";

  return (
    <div className="animate-in">
      <PageHeader
        title="Assessments"
        description={items
          ? `${items.length} assessment${items.length === 1 ? "" : "s"} of ${deviceCount} firewall${deviceCount === 1 ? "" : "s"}`
          : "Loading…"}
        actions={<Button variant="primary" onClick={() => navigate("/upload")}><Upload size={15} />New assessment</Button>}
      />

      {items && items.length === 0 ? (
        <Card>
          <EmptyState
            icon={<FileSearch size={36} strokeWidth={1.5} />}
            title="No assessments yet"
            action={<Button variant="primary" onClick={() => navigate("/upload")}><Upload size={15} />Upload a configuration</Button>}
          >
            Upload a PAN-OS config export, a tech support file, or a Panorama export to run the {brand.ruleSet} checks.
          </EmptyState>
        </Card>
      ) : (
        <>
          {/* Filters: one row above everything they scope. */}
          <div className="flex flex-wrap items-center gap-2 mb-5">
            <div className="relative w-full sm:w-auto">
              <Search size={15} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-fg-faint pointer-events-none" aria-hidden="true" />
              <input
                type="search"
                value={query}
                onChange={(e) => setParam("q", e.target.value)}
                placeholder="Search firewall, serial, file…"
                aria-label="Search assessments"
                className="w-full sm:w-64 pl-8"
              />
            </div>
            <select value={clientFilter} onChange={(e) => setParam("client", e.target.value)} aria-label="Filter by client" className="flex-1 min-w-0 sm:flex-none">
              <option value="">All clients</option>
              {clientNames.map((c) => <option key={c} value={c}>{c}</option>)}
              {(items ?? []).some((a) => !a.client_name) && <option value={NO_CLIENT}>No client assigned</option>}
            </select>
            <select value={activeDevice} onChange={(e) => setParam("device", e.target.value)} aria-label="Filter by firewall" className="flex-1 min-w-0 sm:flex-none sm:max-w-80">
              <option value="">All firewalls ({devices.length})</option>
              {devices.map((d) => (
                <option key={d.key} value={d.key}>
                  {[deviceName(d.latest), d.latest.model, d.latest.serial].filter(Boolean).join(" · ")} ({d.runs.length})
                </option>
              ))}
            </select>
            {filtered && (
              <Button variant="ghost" onClick={() => setParams({}, { replace: true })}>
                <X size={14} />Clear
              </Button>
            )}
          </div>

          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-5">
            <Stat label="Firewalls" value={series.length} sub={scopeLabel} />
            <Stat
              label="Assessments"
              value={shown.length}
              sub={shown.length ? `Latest ${new Date(shown[0].uploaded_at).toLocaleDateString(undefined, { month: "short", day: "numeric" })}` : "—"}
            />
            <Stat
              label="At critical risk"
              icon={<SeverityIcon severity="CRITICAL" size={13} />}
              value={criticalNow}
              sub={`of ${series.length} firewall${series.length === 1 ? "" : "s"}, latest run`}
            />
            <Stat label="Clients" value={clientsInScope} sub={unassigned ? `${unassigned} firewall${unassigned === 1 ? "" : "s"} unassigned` : "All firewalls assigned"} />
          </div>

          {shown.length > 1 && (
            <Card
              className="mb-5"
              title="Risk score over time"
              description={series.length === 1
                ? `Every run of ${series[0].label}. Lower is better.`
                : "One line per firewall. Lower is better — pick a firewall above to follow just one."}
            >
              <RiskTrendChart series={series} onSelect={(id) => navigate(`/assessments/${id}`)} />
            </Card>
          )}

          <div className="flex items-center gap-3 mb-2 min-h-8 text-[13px]">
            {pickedItems.length === 2 ? (
              <>
                <Button variant="primary" size="sm" onClick={() => compare(pickedItems[0], pickedItems[1])}>
                  <GitCompare size={14} />Compare these 2
                </Button>
                <Button variant="ghost" size="sm" onClick={() => setPicked([])}><X size={14} />Clear</Button>
              </>
            ) : (
              <span className="text-fg-muted">
                {pickedItems.length === 1 ? "Tick one more assessment to compare." : "Tick two assessments to compare them."}
              </span>
            )}
          </div>
          <Card flush>
            <div className="table-scroll">
              <table className="min-w-[960px]">
                <thead>
                  <tr>
                    <th className="w-10 pl-5" aria-label="Select to compare" />
                    <th>Firewall</th>
                    <th>Client</th>
                    <th>Serial</th>
                    <th>Risk</th>
                    <th>Findings</th>
                    <th>Uploaded</th>
                    <th className="w-10" aria-label="Actions" />
                  </tr>
                </thead>
                <tbody>
                  {shown.map((a) => {
                    const when = new Date(a.uploaded_at);
                    return (
                      <tr key={a.id} onClick={() => navigate(`/assessments/${a.id}`)} className="cursor-pointer">
                        <td className="pl-5 align-middle" onClick={(e) => e.stopPropagation()}>
                          <input
                            type="checkbox"
                            className="size-4 accent-[var(--accent)] cursor-pointer"
                            aria-label={`Select ${deviceName(a)} ${when.toLocaleString()} to compare`}
                            checked={picked.includes(a.id)}
                            onChange={() => togglePick(a.id)}
                          />
                        </td>
                        <td className="align-middle">
                          <div className="font-medium text-fg leading-5">{deviceName(a)}</div>
                          <div className="text-[12px] text-fg-muted leading-5 truncate max-w-[280px]">
                            {[a.model, SOURCE_LABEL[a.source] ?? a.source].filter(Boolean).join(" · ")}
                          </div>
                        </td>
                        <td className="align-middle max-w-[200px]">
                          <ClientCombobox compact value={a.client_name} clients={clientNames} onSave={(v) => saveIdentity(a.id, { client_name: v })} />
                        </td>
                        <td className="align-middle">
                          <SerialEdit compact value={a.serial} onSave={(v) => saveIdentity(a.id, { serial: v })} />
                        </td>
                        <td className="align-middle">
                          <div className="flex items-center gap-2">
                            <SeverityBadge severity={a.summary.risk_label} />
                            <span className="tab-num text-[12px] text-fg-muted">{a.summary.score} pts</span>
                          </div>
                        </td>
                        <td className="align-middle"><SeverityMix counts={a.summary.severity_counts} /></td>
                        <td className="align-middle whitespace-nowrap">
                          <div className="text-fg leading-5">{when.toLocaleDateString(undefined, { dateStyle: "medium" })}</div>
                          <div className="text-[12px] text-fg-muted leading-5">{when.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" })}</div>
                        </td>
                        <td className="align-middle pr-3">
                          <RowMenu
                            onOpen={() => navigate(`/assessments/${a.id}`)}
                            onDelete={() => remove(a)}
                            onComparePrevious={(() => { const prev = previousRun(a); return prev ? () => compare(prev, a) : undefined; })()}
                          />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {items && shown.length === 0 && (
              <EmptyState
                icon={<Search size={28} strokeWidth={1.5} />}
                title="No assessments match these filters"
                action={<Button onClick={() => setParams({}, { replace: true })}><X size={14} />Clear filters</Button>}
              />
            )}
            {!items && <div className="py-10 text-center text-fg-muted text-[13px]">Loading…</div>}
          </Card>
          {items && items.length > 0 && (
            <p className="text-[12px] text-fg-muted mt-3">
              Assigning a client to one run also assigns it to that firewall's other unassigned runs (matched by serial).
            </p>
          )}
        </>
      )}
    </div>
  );
}
