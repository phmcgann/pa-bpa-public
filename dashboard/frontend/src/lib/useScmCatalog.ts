import { useEffect, useState } from "react";
import { api } from "../api";
import type { ScmCheck } from "../types";

// One fetch per page load, shared by every component that needs check names.
let cache: Promise<Map<number, ScmCheck>> | null = null;

function load(): Promise<Map<number, ScmCheck>> {
  cache ??= api.getScmCatalog()
    .then((c) => new Map(c.checks.map((ch) => [ch.id, ch])))
    .catch(() => { cache = null; return new Map<number, ScmCheck>(); });
  return cache;
}

/** Palo Alto SCM checks by id, or null while loading. */
export function useScmCatalog(): Map<number, ScmCheck> | null {
  const [checks, setChecks] = useState<Map<number, ScmCheck> | null>(null);
  useEffect(() => {
    let live = true;
    load().then((m) => { if (live) setChecks(m); });
    return () => { live = false; };
  }, []);
  return checks;
}
