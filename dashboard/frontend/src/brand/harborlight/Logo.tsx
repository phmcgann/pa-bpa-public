import type { LogoProps } from "../types";
import { lockup, symbol, type LogoData } from "./logoData";

const LOGOS: Record<LogoProps["variant"], LogoData> = { full: lockup, mark: symbol };

/** Colours come from theme.css (--logo-*), so the logo follows light, dark and print. */
const FILL = {
  ink: "var(--logo-ink)",
  gold: "var(--logo-gold)",
  green: "var(--logo-green)",
  muted: "var(--logo-muted)",
  paper: "#ffffff",
  signal: "#3fb37b",
} as const;

/** The Harborlight logo at its true proportions. */
export function Logo({ variant, height, title, style }: LogoProps) {
  const logo = LOGOS[variant];
  const [, , w, h] = logo.viewBox.split(" ").map(Number);
  return (
    <svg
      viewBox={logo.viewBox}
      width={(height * w) / h}
      height={height}
      role={title ? "img" : undefined}
      aria-label={title}
      aria-hidden={title ? undefined : true}
      style={{ display: "block", flexShrink: 0, ...style }}
    >
      {logo.paths.map((p, i) => (
        <path key={i} d={p.d} fill={FILL[p.tone]} />
      ))}
    </svg>
  );
}
