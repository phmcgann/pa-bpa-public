import { useCallback, useEffect, useState } from "react";

const STORAGE_KEY = "pa-bpa-hidden-sections";

function readHidden(): Set<string> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return new Set(raw ? JSON.parse(raw) : []);
  } catch {
    return new Set();
  }
}

function writeHidden(hidden: Set<string>) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(Array.from(hidden)));
}

export const DASHBOARD_SECTIONS = [
  { key: "summary", label: "Executive Summary" },
  { key: "system", label: "System Overview" },
  { key: "licenses", label: "License Status" },
  { key: "advisories", label: "Known Vulnerabilities" },
  { key: "zones", label: "Security Zones" },
  { key: "policy", label: "Security Policy" },
  { key: "nat", label: "NAT Policy" },
  { key: "rulebase", label: "Rulebase Analysis" },
  { key: "threat", label: "Security Profiles" },
  { key: "decryption", label: "Decryption" },
  { key: "access", label: "Administrative Access" },
  { key: "dos", label: "DoS & Session Protection" },
  { key: "vpn", label: "Site-to-site VPN" },
  { key: "certificates", label: "Certificates" },
  { key: "ha", label: "High Availability" },
  { key: "globalprotect", label: "GlobalProtect" },
  { key: "changes", label: "Changes Since Last Run" },
  { key: "scm", label: "Palo Alto SCM BPA" },
  { key: "charts", label: "Findings by Category (chart)" },
  { key: "remediation", label: "Remediation Plan" },
  { key: "findings", label: "All Findings" },
];

export function useSectionVisibility() {
  const [hidden, setHidden] = useState<Set<string>>(() => readHidden());

  useEffect(() => {
    const onStorage = () => setHidden(readHidden());
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  const setVisible = useCallback((key: string, visible: boolean) => {
    setHidden((prev) => {
      const next = new Set(prev);
      if (visible) next.delete(key);
      else next.add(key);
      writeHidden(next);
      return next;
    });
  }, []);

  const isVisible = useCallback((key: string) => !hidden.has(key), [hidden]);

  return { hidden, isVisible, setVisible };
}
