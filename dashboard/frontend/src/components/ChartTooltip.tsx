import type { ReactNode } from "react";

export function ChartTooltip({
  x, y, anchor = "above", children,
}: {
  x: number; y: number; anchor?: "above" | "below"; children: ReactNode;
}) {
  return (
    <div
      className="absolute z-10 pointer-events-none bg-surface border border-line rounded-lg shadow-pop px-3 py-2 text-[12px] leading-5 whitespace-nowrap"
      style={{ left: x, top: y, transform: anchor === "above" ? "translate(-50%, -100%)" : "translate(-50%, 0)" }}
    >
      {children}
    </div>
  );
}

export function ChartTooltipValue({ children }: { children: ReactNode }) {
  return <div className="font-semibold text-fg text-[13px] tab-num">{children}</div>;
}

export function ChartTooltipLabel({ children }: { children: ReactNode }) {
  return <div className="text-fg-2">{children}</div>;
}
