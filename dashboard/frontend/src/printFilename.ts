import { useEffect } from "react";

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/**
 * "PA-5410_22Sep2026-2226": firewall name plus the local date and time of printing.
 * Characters that aren't allowed in Windows/macOS file names are replaced with "-".
 */
export function printFilename(name: string, at: Date = new Date()): string {
  const safe = name.trim().replace(/[\\/:*?"<>|\s]+/g, "-").replace(/^-+|-+$/g, "") || "firewall";
  const pad = (n: number) => String(n).padStart(2, "0");
  const date = `${pad(at.getDate())}${MONTHS[at.getMonth()]}${at.getFullYear()}`;
  const time = `${pad(at.getHours())}${pad(at.getMinutes())}`;
  return `${safe}_${date}-${time}`;
}

/**
 * Browsers name a "Save as PDF" file after document.title, so swap the title in for
 * the length of the print (the Print button or Ctrl+P alike) and put it back afterwards.
 */
export function usePrintFilename(name: string | null) {
  useEffect(() => {
    if (!name) return;
    let saved: string | null = null;
    const before = () => {
      saved = document.title;
      document.title = printFilename(name);
    };
    const after = () => {
      if (saved !== null) document.title = saved;
      saved = null;
    };
    window.addEventListener("beforeprint", before);
    window.addEventListener("afterprint", after);
    return () => {
      window.removeEventListener("beforeprint", before);
      window.removeEventListener("afterprint", after);
      after();
    };
  }, [name]);
}
