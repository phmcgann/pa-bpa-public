import type { CSSProperties } from "react";

/**
 * What a brand pack provides. The build picks one pack (VITE_BRAND, default "harborlight") and
 * the app imports it as "@brand"; each pack also ships theme.css (colour tokens, fonts, the print
 * header/footer), fonts.ts, favicon.svg and meta.json (the page title).
 */
export interface Brand {
  /** Full name, as on the report cover: "Harborlight Consulting". */
  company: string;
  /** The assessment's own rule set, as labelled on findings: "Harborlight BPA". */
  ruleSet: string;
  /** Short form for "<short> rule": "Harborlight". */
  ruleSetShort: string;
  /** Shown in the sidebar and on the cover when set. */
  website?: { label: string; href: string };
}

export interface LogoProps {
  /** full: the sidebar and cover lockup. mark: the small symbol for the cover footer. */
  variant: "full" | "mark";
  height: number;
  title?: string;
  style?: CSSProperties;
}
