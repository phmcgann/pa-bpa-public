import { useEffect, useRef, useState } from "react";
import { severityLabel } from "../severity";
import type { AssessmentListItem } from "../types";
import { SeverityIcon } from "./ui/SeverityIcon";

export interface TrendSeries {
  key: string;
  label: string;
  runs: AssessmentListItem[];
  /** Stable colour slot for this firewall; used when every shown series has one within range. */
  slot?: number;
}

const HEIGHT = 260;
const PAD = { top: 16, right: 20, bottom: 40, left: 44 };
const MAX_SERIES = 6; // validated categorical slots; more than this gets folded out with a note
const DIRECT_LABEL_WIDTH = 120;

function niceStep(rough: number): number {
  if (rough <= 0) return 1;
  const base = 10 ** Math.floor(Math.log10(rough));
  const f = rough / base;
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * base;
}

const DAY = 86_400_000;

function tickFormat(spanMs: number) {
  if (spanMs < 2 * DAY) {
    return (t: number) => [
      new Date(t).toLocaleDateString(undefined, { month: "short", day: "numeric" }),
      new Date(t).toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" }),
    ];
  }
  if (spanMs < 300 * DAY) return (t: number) => [new Date(t).toLocaleDateString(undefined, { month: "short", day: "numeric" })];
  return (t: number) => [new Date(t).toLocaleDateString(undefined, { month: "short", year: "numeric" })];
}

function useWidth() {
  const ref = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => setWidth(Math.floor(entry.contentRect.width)));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return { ref, width };
}

/**
 * Risk score over time, one line per firewall on a shared time axis. Colors follow the series
 * (never rank); a legend is always shown for 2+ series and the latest point of each line is
 * labelled directly when there's room. Hover a point for its run; click to open it.
 */
export function RiskTrendChart({ series, onSelect }: {
  series: TrendSeries[];
  onSelect?: (assessmentId: number) => void;
}) {
  const { ref, width } = useWidth();
  const [hover, setHover] = useState<{ s: number; i: number } | null>(null);

  const shown = series.slice(0, MAX_SERIES);
  const hidden = series.length - shown.length;
  const all = shown.flatMap((s) => s.runs);
  const times = all.map((r) => new Date(r.uploaded_at).getTime());
  const tMin = Math.min(...times);
  const tMax = Math.max(...times);
  const span = tMax - tMin;
  const direct = shown.length > 1 && shown.length <= 4 && width >= 640;
  const plotRight = width - PAD.right - (direct ? DIRECT_LABEL_WIDTH : 0);
  const plotW = Math.max(10, plotRight - PAD.left);
  const plotH = HEIGHT - PAD.top - PAD.bottom;

  const maxScore = Math.max(1, ...all.map((r) => r.summary.score));
  const yStep = niceStep(maxScore / 4);
  const yMax = Math.ceil((maxScore * 1.08) / yStep) * yStep;

  const pad = span === 0 ? DAY : span * 0.04;
  const x = (t: number) => PAD.left + ((t - (tMin - pad)) / (span + 2 * pad)) * plotW;
  const y = (v: number) => PAD.top + plotH * (1 - v / yMax);

  const points = shown.map((s) =>
    [...s.runs]
      .sort((a, b) => new Date(a.uploaded_at).getTime() - new Date(b.uploaded_at).getTime())
      .map((r) => ({ run: r, px: x(new Date(r.uploaded_at).getTime()), py: y(r.summary.score) })));

  const fmt = tickFormat(span);
  const tickCount = Math.max(2, Math.min(7, Math.floor(plotW / 120)));
  const xTicks = span === 0
    ? [{ t: tMin, lines: fmt(tMin) }]
    : Array.from({ length: tickCount }, (_, k) => {
      const t = tMin + (span * k) / (tickCount - 1);
      return { t, lines: fmt(t) };
    });

  // Direct labels at each line's last point, nudged apart so they never overlap.
  const endLabels = direct
    ? points.map((pts, s) => ({ s, y: pts[pts.length - 1].py })).sort((a, b) => a.y - b.y)
    : [];
  for (let k = 1; k < endLabels.length; k++) {
    if (endLabels[k].y - endLabels[k - 1].y < 16) endLabels[k].y = endLabels[k - 1].y + 16;
  }

  function onMove(e: React.MouseEvent<SVGSVGElement>) {
    const rect = e.currentTarget.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    let best: { s: number; i: number } | null = null;
    let bestD = 28;
    points.forEach((pts, s) => pts.forEach((p, i) => {
      const d = Math.hypot(p.px - mx, p.py - my);
      if (d < bestD) { bestD = d; best = { s, i }; }
    }));
    setHover(best);
  }

  const hovered = hover ? points[hover.s]?.[hover.i] : null;
  const stable = shown.every((s) => s.slot !== undefined && s.slot < MAX_SERIES);
  const color = (s: number) => `var(--series-${(stable ? shown[s].slot! : s) + 1})`;

  return (
    <div>
      {shown.length > 1 && (
        <div className="flex flex-wrap gap-x-4 gap-y-1.5 mb-3" aria-label="Legend">
          {shown.map((s, i) => (
            <span key={s.key} className="inline-flex items-center gap-1.5 text-[12px] text-fg-2">
              <span className="inline-block w-3.5 h-0.5 rounded-full" style={{ background: color(i) }} aria-hidden="true" />
              {s.label}
              <span className="text-fg-faint tab-num">· {s.runs.length}</span>
            </span>
          ))}
          {hidden > 0 && <span className="text-[12px] text-fg-muted">+{hidden} more — filter to a client or firewall to see them</span>}
        </div>
      )}
      <div ref={ref} className="relative w-full" style={{ height: HEIGHT }}>
        {width > 0 && (
          <svg
            width={width}
            height={HEIGHT}
            role="img"
            aria-label={`Risk score over time for ${shown.map((s) => s.label).join(", ")}`}
            onMouseMove={onMove}
            onMouseLeave={() => setHover(null)}
            onClick={() => hovered && onSelect?.(hovered.run.id)}
            style={{ cursor: hovered && onSelect ? "pointer" : "default", display: "block" }}
          >
            {Array.from({ length: Math.round(yMax / yStep) + 1 }, (_, k) => k * yStep).map((v) => (
              <g key={v}>
                <line x1={PAD.left} x2={plotRight} y1={y(v)} y2={y(v)} stroke="var(--divider)" strokeWidth={1} />
                <text x={PAD.left - 10} y={y(v) + 4} textAnchor="end" fontSize={11} fill="var(--text-muted)" className="tab-num">{v}</text>
              </g>
            ))}
            <line x1={PAD.left} x2={plotRight} y1={y(0)} y2={y(0)} stroke="var(--border-strong)" strokeWidth={1} />

            {xTicks.map(({ t, lines }, k) => {
              const anchor = xTicks.length > 1 && k === 0 ? "start" : xTicks.length > 1 && k === xTicks.length - 1 ? "end" : "middle";
              return (
                <text key={t} x={x(t)} y={HEIGHT - PAD.bottom + 18} textAnchor={anchor} fontSize={11} fill="var(--text-muted)">
                  {lines.map((l, j) => <tspan key={j} x={x(t)} dy={j === 0 ? 0 : 14}>{l}</tspan>)}
                </text>
              );
            })}

            {hovered && (
              <line x1={hovered.px} x2={hovered.px} y1={PAD.top} y2={y(0)} stroke="var(--border-strong)" strokeDasharray="3 3" />
            )}

            {points.map((pts, s) => (
              <g key={shown[s].key} opacity={hover && hover.s !== s ? 0.35 : 1} style={{ transition: "opacity 150ms" }}>
                {pts.length > 1 && (
                  <path
                    d={pts.map((p, i) => `${i ? "L" : "M"}${p.px},${p.py}`).join("")}
                    fill="none" stroke={color(s)} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round"
                  />
                )}
                {pts.map((p, i) => (
                  <circle
                    key={p.run.id}
                    cx={p.px} cy={p.py}
                    r={hover && hover.s === s && hover.i === i ? 5.5 : 4}
                    fill={color(s)} stroke="var(--surface)" strokeWidth={2}
                  />
                ))}
              </g>
            ))}

            {endLabels.map(({ s, y: ly }) => (
              <text key={s} x={plotRight + 10} y={ly + 4} fontSize={12} fill="var(--text-secondary)">
                {shown[s].label.length > 16 ? `${shown[s].label.slice(0, 15)}…` : shown[s].label}
              </text>
            ))}
          </svg>
        )}

        {hovered && (
          <div
            className="pointer-events-none absolute z-10 bg-surface border border-line rounded-lg shadow-pop px-3 py-2 text-[12px] whitespace-nowrap"
            style={{
              left: Math.min(Math.max(hovered.px, 90), width - 90),
              top: hovered.py < 90 ? hovered.py + 14 : hovered.py - 12,
              transform: hovered.py < 90 ? "translate(-50%, 0)" : "translate(-50%, -100%)",
            }}
          >
            <div className="font-semibold text-fg">{hovered.run.hostname || hovered.run.filename}</div>
            <div className="text-fg-muted">
              {new Date(hovered.run.uploaded_at).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}
            </div>
            <div className="flex items-center gap-1.5 mt-1 text-fg">
              <span className="tab-num font-semibold">{hovered.run.summary.score} pts</span>
              <span className="text-fg-faint">·</span>
              <SeverityIcon severity={hovered.run.summary.risk_label} size={12} />
              {severityLabel(hovered.run.summary.risk_label)}
            </div>
            {onSelect && <div className="text-fg-faint mt-0.5">Click to open</div>}
          </div>
        )}
      </div>
    </div>
  );
}
