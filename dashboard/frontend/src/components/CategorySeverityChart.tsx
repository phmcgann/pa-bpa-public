import { useMemo, useRef, useState } from "react";
import type { Finding, Severity } from "../types";
import { SEVERITY_META, SEVERITY_ORDER } from "../severity";
import { ChartTooltip, ChartTooltipLabel, ChartTooltipValue } from "./ChartTooltip";
import { SeverityIcon } from "./ui/SeverityIcon";

const BAR_HEIGHT = 14;

interface HoverState {
  x: number;
  y: number;
  anchor: "above" | "below";
  category: string;
  severity: Severity;
  count: number;
}

export function CategorySeverityChart({
  findings,
  activeCategory,
  activeSeverity,
  onSegmentClick,
}: {
  findings: Finding[];
  activeCategory: string;
  activeSeverity: Severity | "ALL";
  onSegmentClick: (category: string, severity: Severity) => void;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [hover, setHover] = useState<HoverState | null>(null);

  const rows = useMemo(() => {
    const byCategory = new Map<string, Record<Severity, number>>();
    for (const f of findings) {
      if (f.dismissed || f.rule_disabled || f.not_scored_reason) continue;
      const counts = byCategory.get(f.category) ?? { CRITICAL: 0, WARNING: 0, LOW: 0, INFORMATIONAL: 0 };
      counts[f.severity] += 1;
      byCategory.set(f.category, counts);
    }
    return Array.from(byCategory.entries())
      .map(([category, counts]) => ({
        category,
        counts,
        total: SEVERITY_ORDER.reduce((sum, s) => sum + counts[s], 0),
      }))
      .sort((a, b) => b.total - a.total);
  }, [findings]);

  if (rows.length === 0) return null;

  const maxTotal = Math.max(...rows.map((r) => r.total));

  function showTooltipAt(clientX: number, clientY: number, category: string, severity: Severity, count: number) {
    const rect = containerRef.current?.getBoundingClientRect();
    if (!rect) return;
    const y = clientY - rect.top;
    const flipBelow = y < 50;
    setHover({
      x: clientX - rect.left, y: flipBelow ? y + 14 : y - 10,
      anchor: flipBelow ? "below" : "above", category, severity, count,
    });
  }

  function showTooltipForElement(el: HTMLElement, category: string, severity: Severity, count: number) {
    const r = el.getBoundingClientRect();
    showTooltipAt(r.left + r.width / 2, r.top + r.height / 2, category, severity, count);
  }

  const selectionActive = activeCategory !== "ALL" && activeSeverity !== "ALL";

  return (
    <div ref={containerRef} className="relative">
      <div className="flex flex-wrap gap-x-4 gap-y-1 mb-4 text-[12px] text-fg-2" aria-label="Legend">
        {SEVERITY_ORDER.map((s) => (
          <span key={s} className="inline-flex items-center gap-1.5">
            <SeverityIcon severity={s} size={12} />
            {SEVERITY_META[s].label}
          </span>
        ))}
      </div>

      <div className="flex flex-col gap-2.5">
        {rows.map((row) => (
          <div key={row.category} className="grid grid-cols-[132px_1fr_32px] items-center gap-3">
            <div className="text-[12px] text-fg-2 text-right truncate" title={row.category}>{row.category}</div>
            <div
              className="flex gap-[2px]"
              style={{ width: `${(row.total / maxTotal) * 100}%`, minWidth: 6, height: BAR_HEIGHT }}
            >
              {SEVERITY_ORDER.filter((s) => row.counts[s] > 0).map((s, i, visible) => {
                const selected = selectionActive && activeCategory === row.category && activeSeverity === s;
                const last = i === visible.length - 1;
                return (
                  <div
                    key={s}
                    role="button"
                    tabIndex={0}
                    aria-label={`${row.counts[s]} ${SEVERITY_META[s].label} findings in ${row.category} — show in findings`}
                    aria-pressed={selected}
                    onClick={() => onSegmentClick(row.category, s)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        onSegmentClick(row.category, s);
                      }
                    }}
                    onMouseMove={(e) => showTooltipAt(e.clientX, e.clientY, row.category, s, row.counts[s])}
                    onMouseLeave={() => setHover(null)}
                    onFocus={(e) => showTooltipForElement(e.currentTarget, row.category, s, row.counts[s])}
                    onBlur={() => setHover(null)}
                    className="h-full cursor-pointer transition-opacity hover:brightness-110 focus-visible:outline-2"
                    style={{
                      flex: `${row.counts[s]} 0 0`, minWidth: 3,
                      background: SEVERITY_META[s].color,
                      borderRadius: last ? "0 4px 4px 0" : 0,
                      opacity: selectionActive && !selected ? 0.3 : 1,
                    }}
                  />
                );
              })}
            </div>
            <div className="text-[12px] text-fg-2 tab-num">{row.total}</div>
          </div>
        ))}
      </div>

      {hover && (
        <ChartTooltip x={hover.x} y={hover.y} anchor={hover.anchor}>
          <ChartTooltipValue>{hover.count} {SEVERITY_META[hover.severity].label}</ChartTooltipValue>
          <ChartTooltipLabel>{hover.category}</ChartTooltipLabel>
          <div className="text-fg-faint text-[11px] mt-0.5">Click to show these findings</div>
        </ChartTooltip>
      )}
    </div>
  );
}
