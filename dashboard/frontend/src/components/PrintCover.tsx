import { brand, Logo } from "@brand";
import { SEVERITY_ORDER, severityLabel } from "../severity";
import type { AssessmentDetail } from "../types";
import { SeverityBadge } from "./ui/Badge";
import { SeverityIcon } from "./ui/SeverityIcon";

const SOURCE_LABEL: Record<string, string> = {
  file_upload: "configuration export",
  panorama_export: "Panorama export",
  tsf_upload: "tech support file",
  live: "live device",
};

/**
 * First page of the printed report, in the same visual language as the app: logo, the firewall
 * as the title, the risk summary as the same tiles the dashboard shows, and the report's contents.
 * Print always uses the light tokens, so it looks the same whatever theme the viewer is in.
 */
export function PrintCover({ assessment, sections, findingsFilter }: {
  assessment: AssessmentDetail; sections: string[];
  /** Set when the findings list was filtered at print time, so the cover says so. */
  findingsFilter?: { narrowedBy: string[]; shown: number; total: number };
}) {
  const { summary, data } = assessment;
  const info = data.system_info;
  const title = assessment.hostname || assessment.filename;
  const date = new Date(assessment.uploaded_at).toLocaleDateString(undefined, { dateStyle: "long" });
  const meta = [
    assessment.model ?? (info.available ? info.model : null),
    info.available && info.sw_version ? `PAN-OS ${info.sw_version}` : null,
    assessment.serial ? `S/N ${assessment.serial}` : null,
  ].filter(Boolean);

  return (
    <section className="print-only print-cover">
      <div className="cover-page">
        <header className="flex items-start justify-between">
          <Logo variant="full" height={40} title={brand.company} />
          <div className="text-right text-[11px] leading-4 text-fg-muted pt-1">
            <div>{date}</div>
            <div>Confidential</div>
          </div>
        </header>

        <div className="mt-[1.7in]">
          <div className="h-1 w-14 rounded-full bg-brand mb-5" />
          <div className="text-[11px] font-semibold tracking-[0.14em] uppercase text-accent-fg">
            Firewall best practice assessment
          </div>
          <h1 className="text-[46px] leading-[1.05] font-semibold tracking-tight mt-3 mb-0 break-words">{title}</h1>
          {assessment.client_name && (
            <div className="text-[18px] text-fg-2 mt-2">Prepared for {assessment.client_name}</div>
          )}
          {meta.length > 0 && <div className="text-[13px] text-fg-muted mt-3">{meta.join("  ·  ")}</div>}
          <p className="text-[13px] leading-5 text-fg-2 mt-5 mb-0 max-w-[5.2in]">
            An assessment of <strong className="font-semibold text-fg">{title}</strong> against Palo Alto Networks'
            published best practices and the CIS Palo Alto Firewall Benchmark, from a{" "}
            {SOURCE_LABEL[assessment.source] ?? assessment.source} dated {date}.
          </p>
        </div>

        <div className="grid grid-cols-5 gap-2.5 mt-10">
          <div className="cover-tile">
            <div className="text-[10px] font-medium text-fg-muted">Overall risk</div>
            <div className="text-[26px] font-semibold leading-8 tab-num mt-1">{summary.score}<span className="text-[11px] font-normal text-fg-muted ml-1">pts</span></div>
            <SeverityBadge severity={summary.risk_label} className="mt-1" />
          </div>
          {SEVERITY_ORDER.map((sev) => (
            <div key={sev} className="cover-tile">
              <div className="flex items-center gap-1 text-[10px] font-medium text-fg-muted">
                <SeverityIcon severity={sev} size={11} />{severityLabel(sev)}
              </div>
              <div className="text-[26px] font-semibold leading-8 tab-num mt-1">{summary.severity_counts[sev]}</div>
              <div className="text-[10px] text-fg-muted tab-num">{summary.score_breakdown[sev].points} pts</div>
            </div>
          ))}
        </div>

        {findingsFilter && (
          <div className="cover-filter-note mt-6 text-[12px] leading-5 text-fg">
            <strong>Filtered report.</strong> The findings list is limited to {findingsFilter.narrowedBy.join(" · ")}{" "}
            ({findingsFilter.shown} of {findingsFilter.total} findings). The scores above cover every finding.
          </div>
        )}

        <div className="mt-10">
          <div className="text-[11px] font-semibold tracking-[0.14em] uppercase text-fg-muted mb-2">Contents</div>
          <ol className="grid grid-cols-2 gap-x-8 m-0 p-0 list-none">
            {sections.map((s, i) => (
              <li key={s} className="flex items-baseline gap-3 py-1.5 border-b border-divider text-[13px]">
                <span className="tab-num text-accent-fg font-semibold w-5">{String(i + 1).padStart(2, "0")}</span>
                {s}
              </li>
            ))}
          </ol>
        </div>

        <footer className="mt-auto flex items-end justify-between border-t border-line pt-4">
          <div className="text-[11px] leading-4">
            <div className="font-semibold text-fg">Prepared by {brand.company}</div>
            {brand.website && <div className="text-fg-muted">{brand.website.label}</div>}
          </div>
          <Logo variant="mark" height={26} />
        </footer>
      </div>
      <div className="cover-band" />
    </section>
  );
}
