import { ArrowLeft, CheckCircle2, ChevronRight, CircleAlert, Clock, FileArchive, FileCode2, Loader2, Network, Search, Server, UploadCloud } from "lucide-react";
import { useRef, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Callout } from "../components/ui/Callout";
import { Card } from "../components/ui/Card";
import { PageHeader } from "../components/ui/PageHeader";
import { cn } from "../lib/cn";
import type { PanoramaDeviceGroup, PanoramaUploadResult } from "../types";

const ACCEPT = ".xml,.tgz,.tar.gz";

type BatchItem = {
  name: string;
  status: "queued" | "working" | "done" | "failed" | "panorama";
  id?: number;
  hostname?: string | null;
  error?: string;
  panorama?: PanoramaUploadResult;
};

/** One line per file in a multi-file upload. */
function BatchRow({ item, onPanorama }: { item: BatchItem; onPanorama: (p: PanoramaUploadResult) => void }) {
  const icon = {
    queued: <Clock size={16} className="text-fg-muted" />,
    working: <Loader2 size={16} className="animate-spin text-accent-fg" />,
    done: <CheckCircle2 size={16} className="text-good-fg" />,
    failed: <CircleAlert size={16} className="text-critical-fg" />,
    panorama: <Network size={16} className="text-accent-fg" />,
  }[item.status];
  return (
    <li className="flex items-start gap-3 py-2.5 border-t border-divider first:border-t-0">
      <span className="mt-0.5 shrink-0" aria-hidden="true">{icon}</span>
      <div className="min-w-0 flex-1">
        <div className="text-[13px] font-medium text-fg truncate">{item.name}</div>
        <div className="text-[12px] text-fg-muted leading-5">
          {item.status === "queued" && "Waiting"}
          {item.status === "working" && "Analyzing…"}
          {item.status === "done" && <>Assessed{item.hostname && item.hostname !== "N/A" ? ` as ${item.hostname}` : ""}</>}
          {item.status === "failed" && <span className="text-critical-fg">{item.error}</span>}
          {item.status === "panorama" && "Panorama export — pick a device group to assess"}
        </div>
      </div>
      {item.status === "done" && item.id != null && (
        <Link to={`/assessments/${item.id}`} className="text-[13px] font-medium text-accent-fg hover:underline shrink-0">Open</Link>
      )}
      {item.status === "panorama" && item.panorama && (
        <Button size="sm" onClick={() => onPanorama(item.panorama!)}>Choose device group</Button>
      )}
    </li>
  );
}

function Breadcrumb({ here }: { here: string }) {
  return (
    <>
      <Link to="/" className="text-fg-muted hover:text-fg">Assessments</Link>
      <span className="mx-1.5 text-fg-faint">/</span>
      <span className="text-fg-2">{here}</span>
    </>
  );
}

/** One kind of file the tool accepts: what it is, where to get it, what it gives you. */
function FileKind({ icon, title, badge, path, children }: {
  icon: ReactNode; title: string; badge?: ReactNode; path: string; children: ReactNode;
}) {
  return (
    <li className="flex gap-3 py-3.5 border-t border-divider first:border-t-0 first:pt-0">
      <span className="mt-0.5 size-8 shrink-0 rounded-lg bg-surface-3 text-fg-2 inline-flex items-center justify-center">{icon}</span>
      <div className="min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[13px] font-semibold text-fg">{title}</span>
          {badge}
        </div>
        <div className="text-[12px] text-fg-muted mt-0.5">{path}</div>
        <p className="text-[12.5px] text-fg-2 leading-5 mt-1.5 mb-0">{children}</p>
      </div>
    </li>
  );
}

function DeviceGroupPicker({ filename, groups, busy, error, onPick, onBack }: {
  filename: string;
  groups: PanoramaDeviceGroup[];
  busy: string | null;
  error: string | null;
  onPick: (name: string) => void;
  onBack: () => void;
}) {
  const [query, setQuery] = useState("");
  const q = query.trim().toLowerCase();
  const shown = groups.filter((g) =>
    !q || [g.name, ...g.device_serials, ...g.reference_templates].some((v) => v.toLowerCase().includes(q))
  );
  return (
    <div className="animate-in max-w-3xl">
      <PageHeader
        breadcrumb={<Breadcrumb here="Panorama export" />}
        title="Which device group?"
        description={
          <>
            <span className="text-fg font-medium">{filename}</span> is a Panorama export covering {groups.length} device
            group{groups.length === 1 ? "" : "s"}. Pick the one to assess — its rules, zones and profiles are resolved from the shared and
            device-group rulebases and its template stack.
          </>
        }
      />
      <Card flush>
        {groups.length > 6 && (
          <div className="px-4 pt-4 pb-3 border-b border-divider">
            <div className="relative">
              <Search size={15} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-fg-faint pointer-events-none" aria-hidden="true" />
              <input
                type="search"
                autoFocus
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search device groups, serials, templates…"
                aria-label="Search device groups"
                className="w-full pl-8"
              />
            </div>
          </div>
        )}
        <ul className="m-0 p-0 list-none">
          {shown.map((dg) => (
            <li key={dg.name} className="border-b border-divider last:border-b-0">
              <button
                type="button"
                disabled={!!busy}
                onClick={() => onPick(dg.name)}
                className="w-full flex items-center gap-3 px-4 py-3.5 text-left bg-transparent border-0 hover:bg-surface-2 transition-colors disabled:opacity-60"
              >
                <span className="size-9 shrink-0 rounded-lg bg-surface-3 text-fg-2 inline-flex items-center justify-center">
                  <Server size={16} aria-hidden="true" />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block text-[14px] font-medium text-fg">{dg.name}</span>
                  <span className="block text-[12px] text-fg-muted mt-0.5 truncate">
                    {dg.device_serials.length > 0
                      ? `${dg.device_serials.length} firewall${dg.device_serials.length === 1 ? "" : "s"} · S/N ${dg.device_serials.join(", ")}`
                      : "No firewall assigned"}
                    {dg.reference_templates.length > 0 && ` · Templates: ${dg.reference_templates.join(", ")}`}
                  </span>
                </span>
                {busy === dg.name
                  ? <Loader2 size={16} className="animate-spin text-fg-muted" aria-label="Building assessment" />
                  : <ChevronRight size={16} className="text-fg-faint" aria-hidden="true" />}
              </button>
            </li>
          ))}
          {shown.length === 0 && (
            <li className="px-4 py-8 text-center text-[13px] text-fg-muted">No device groups match.</li>
          )}
        </ul>
      </Card>
      {error && <Callout tone="warning" className="mt-4" title="Couldn't build the assessment.">{error}</Callout>}
      <Button variant="ghost" className="mt-4 -ml-2" onClick={onBack}>
        <ArrowLeft size={15} />Upload a different file
      </Button>
    </div>
  );
}

export function UploadPage() {
  const [dragOver, setDragOver] = useState(false);
  const [busyFile, setBusyFile] = useState<string | null>(null);
  const [busyGroup, setBusyGroup] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [panoramaChoice, setPanoramaChoice] = useState<
    { uploadId: number; filename: string; deviceGroups: PanoramaDeviceGroup[] } | null
  >(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const [batch, setBatch] = useState<BatchItem[] | null>(null);

  function handleFiles(list: FileList | null | undefined) {
    const files = Array.from(list ?? []);
    if (files.length === 1) handleFile(files[0]);
    else if (files.length > 1) uploadBatch(files);
  }

  // Several files: upload one after another (each is parsed and checked on the server), keeping a
  // status line per file instead of jumping to the first result.
  async function uploadBatch(files: File[]) {
    setError(null);
    const items: BatchItem[] = files.map((f) => ({ name: f.name, status: "queued" }));
    setBatch([...items]);
    for (let i = 0; i < files.length; i++) {
      items[i] = { ...items[i], status: "working" };
      setBatch([...items]);
      try {
        const result = await api.uploadAssessment(files[i]);
        items[i] = "panorama_export" in result
          ? { ...items[i], status: "panorama", panorama: result }
          : { ...items[i], status: "done", id: result.id, hostname: result.hostname };
      } catch (e) {
        items[i] = { ...items[i], status: "failed", error: e instanceof Error ? e.message : "Upload failed" };
      }
      setBatch([...items]);
    }
    if (inputRef.current) inputRef.current.value = "";
  }

  async function handleFile(file: File) {
    setError(null);
    setBusyFile(file.name);
    try {
      const result = await api.uploadAssessment(file);
      if ("panorama_export" in result) {
        setPanoramaChoice({ uploadId: result.upload_id, filename: result.filename, deviceGroups: result.device_groups });
      } else {
        navigate(`/assessments/${result.id}`);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Upload failed");
    } finally {
      setBusyFile(null);
      if (inputRef.current) inputRef.current.value = "";
    }
  }

  async function handlePickDeviceGroup(name: string) {
    if (!panoramaChoice) return;
    setError(null);
    setBusyGroup(name);
    try {
      const result = await api.createFromPanorama(panoramaChoice.uploadId, name);
      navigate(`/assessments/${result.id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to build assessment");
    } finally {
      setBusyGroup(null);
    }
  }

  if (panoramaChoice) {
    return (
      <DeviceGroupPicker
        filename={panoramaChoice.filename}
        groups={panoramaChoice.deviceGroups}
        busy={busyGroup}
        error={error}
        onPick={handlePickDeviceGroup}
        onBack={() => { setPanoramaChoice(null); setError(null); }}
      />
    );
  }

  const batchRunning = !!batch?.some((b) => b.status === "queued" || b.status === "working");
  const busy = busyFile !== null || batchRunning;

  return (
    <div className="animate-in">
      <PageHeader
        breadcrumb={<Breadcrumb here="New assessment" />}
        title="New assessment"
        description="Upload a configuration export or tech support file from a Palo Alto Networks firewall or Panorama."
      />

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-5 items-start">
        <div className="lg:col-span-3 flex flex-col gap-4">
          <div
            role="button"
            tabIndex={busy ? -1 : 0}
            aria-label="Upload config .xml or tech support .tgz files"
            aria-busy={busy}
            onKeyDown={(e) => { if (!busy && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); inputRef.current?.click(); } }}
            onDragOver={(e) => { e.preventDefault(); if (!busy) setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragOver(false);
              if (!busy) handleFiles(e.dataTransfer.files);
            }}
            onClick={() => { if (!busy) inputRef.current?.click(); }}
            className={cn(
              "relative flex flex-col items-center justify-center text-center min-h-[340px] px-6 py-12",
              "rounded-[var(--radius-card)] border-2 border-dashed transition-colors",
              busy ? "cursor-progress border-line bg-surface"
                : dragOver ? "cursor-copy border-brand bg-accent-soft"
                : "cursor-pointer border-line-strong bg-surface hover:border-fg-faint hover:bg-surface-2",
            )}
          >
            <input
              ref={inputRef}
              type="file"
              accept={ACCEPT}
              multiple
              className="hidden"
              onChange={(e) => handleFiles(e.target.files)}
            />
            {busy ? (
              <>
                <Loader2 size={30} className="animate-spin text-accent-fg" aria-hidden="true" />
                <div className="text-[15px] font-semibold text-fg mt-4">
                  {batchRunning
                    ? `Analyzing ${batch!.filter((b) => b.status !== "queued" && b.status !== "working").length + 1} of ${batch!.length}`
                    : `Analyzing ${busyFile}`}
                </div>
                <div className="text-[13px] text-fg-muted mt-1">Parsing the configuration and running every check — usually a few seconds.</div>
              </>
            ) : (
              <>
                <span className={cn(
                  "size-14 rounded-2xl inline-flex items-center justify-center transition-colors",
                  dragOver ? "bg-brand text-white" : "bg-surface-3 text-fg-2",
                )}>
                  <UploadCloud size={26} aria-hidden="true" />
                </span>
                <div className="text-[16px] font-semibold text-fg mt-4">
                  {dragOver ? "Drop to upload" : "Drop files here"}
                </div>
                <div className="text-[13px] text-fg-muted mt-1">
                  A config <span className="font-mono text-fg-2">.xml</span> or tech support{" "}
                  <span className="font-mono text-fg-2">.tgz</span> — one or several at once
                </div>
                <Button variant="primary" className="mt-5 pointer-events-none" tabIndex={-1}>Choose files</Button>
              </>
            )}
          </div>

          {error && <Callout tone="warning" title="Upload failed.">{error}</Callout>}

          {batch && (
            <Card
              title={batchRunning ? "Uploading" : "Uploaded"}
              description={`${batch.filter((b) => b.status === "done").length} of ${batch.length} assessed`
                + (batch.some((b) => b.status === "failed") ? ` · ${batch.filter((b) => b.status === "failed").length} failed` : "")}
              actions={!batchRunning && (
                <Button size="sm" onClick={() => navigate("/")}>View assessments</Button>
              )}
            >
              <ul className="m-0 p-0 list-none" aria-live="polite">
                {batch.map((item, i) => (
                  <BatchRow
                    key={`${item.name}-${i}`}
                    item={item}
                    onPanorama={(p) => setPanoramaChoice({ uploadId: p.upload_id, filename: p.filename, deviceGroups: p.device_groups })}
                  />
                ))}
              </ul>
            </Card>
          )}

          <p className="text-[12px] text-fg-muted leading-5 m-0">
            Files are analyzed on this server. Nothing is sent to Palo Alto Networks unless you run the Palo Alto SCM
            BPA from an assessment.
          </p>
        </div>

        <Card className="lg:col-span-2" title="Which file should I use?">
          <ul className="m-0 p-0 list-none">
            <FileKind
              icon={<FileArchive size={16} />}
              title="Tech support file"
              badge={<Badge tone="good">Most complete</Badge>}
              path="Device → Support → Generate Tech Support File"
            >
              Adds licenses, PAN-OS version, uptime and HA state, and — on a Panorama-managed firewall — the real
              merged policy the firewall is running.
            </FileKind>
            <FileKind
              icon={<FileCode2 size={16} />}
              title="Configuration export"
              path="Device → Setup → Operations → Export named configuration snapshot"
            >
              The full configuration. Licenses, version, uptime and HA state show as unavailable, since they aren't
              in the config.
            </FileKind>
            <FileKind
              icon={<Network size={16} />}
              title="Panorama export"
              path="Panorama → Setup → Operations → Export named Panorama configuration snapshot"
            >
              You'll pick which device group to assess after uploading.
            </FileKind>
          </ul>
        </Card>
      </div>
    </div>
  );
}
