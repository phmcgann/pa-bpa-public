import { ExternalLink } from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "../api";
import type { ContentInfo, ContentItem } from "../types";
import { Badge } from "./ui/Badge";

function longDate(iso: string) {
  // Date-only ISO strings parse as UTC midnight; format them in UTC so they don't shift a day.
  return new Date(`${iso.slice(0, 10)}T00:00:00Z`).toLocaleDateString(undefined, { dateStyle: "long", timeZone: "UTC" });
}

function Status({ item }: { item: ContentItem }) {
  if (item.kind === "live") {
    if (item.status === "ok") return <Badge tone="good" title="Downloaded while the dashboard runs">Live</Badge>;
    if (item.status === "disabled") return <Badge tone="neutral">Off</Badge>;
    if (item.status === "error") return <Badge tone="warning">Unreachable</Badge>;
    return <Badge tone="info">Downloading</Badge>;
  }
  return item.review_due
    ? <Badge tone="warning" title={`Over ${item.age_days} days old`}>Review due</Badge>
    : <Badge tone="good">Current</Badge>;
}

/**
 * What the checks know about Palo Alto, and how new it is. Bundled content is a snapshot taken for this
 * release; it's flagged once it's old enough that Palo Alto has likely changed something.
 */
export function PaloAltoContent() {
  const [info, setInfo] = useState<ContentInfo | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    api.getContentInfo().then(setInfo, () => setFailed(true));
  }, []);

  if (failed) return <p className="text-[13px] text-fg-muted m-0">Couldn't load this.</p>;
  if (!info) return <p className="text-[13px] text-fg-muted m-0">Loading…</p>;
  return (
    <div className="flex flex-col">
      {info.items.map((item) => (
        <div key={item.id} className="flex gap-3 py-3 border-t border-divider first:border-t-0">
          <div className="min-w-0 flex-1">
            <div className="text-[13px] font-medium text-fg leading-5">{item.label}</div>
            <div className="text-[12px] text-fg-2 leading-5 tab-num">
              {item.kind === "live"
                ? (item.fetched_at ? `Last downloaded ${new Date(item.fetched_at).toLocaleString()}` : "Not downloaded yet")
                : item.as_of && `As of ${longDate(item.as_of)}`}
            </div>
            {item.detail && <p className="text-[12px] text-fg-muted leading-5 mt-0.5 mb-0 max-w-3xl">{item.detail}</p>}
            {item.source && (
              <a href={item.source} target="_blank" rel="noreferrer"
                 className="inline-flex items-center gap-1 text-[12px] mt-0.5">
                Palo Alto source <ExternalLink size={11} aria-hidden />
              </a>
            )}
          </div>
          <div className="shrink-0"><Status item={item} /></div>
        </div>
      ))}
      <p className="text-[12px] text-fg-muted leading-5 mt-2 mb-0 max-w-3xl">
        Bundled content is updated with each dashboard release, and is marked for review once it's over{" "}
        {info.review_after_days} days old. To spot checks Palo Alto has added since, run the Palo Alto SCM BPA on an
        assessment: they're labelled "New from Palo Alto" in its SCM coverage, and included in the copied gap list.
      </p>
    </div>
  );
}
