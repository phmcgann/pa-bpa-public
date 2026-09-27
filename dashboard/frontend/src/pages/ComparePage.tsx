import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { CompareView } from "../components/CompareView";
import { Callout } from "../components/ui/Callout";
import { PageHeader } from "../components/ui/PageHeader";
import type { CompareResult } from "../types";

/** Compare any two assessments (from the Assessments list). */
export function ComparePage() {
  const [params] = useSearchParams();
  const base = Number(params.get("base"));
  const target = Number(params.get("target"));
  const [result, setResult] = useState<CompareResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setResult(null); setError(null);
    if (!base || !target) { setError("Pick two assessments to compare."); return; }
    api.compareAssessments(base, target).then(setResult).catch((e) => setError(String(e.message ?? e)));
  }, [base, target]);

  const breadcrumb = <><Link to="/" className="hover:underline">Assessments</Link> / Compare</>;
  if (error) return <div><PageHeader breadcrumb={breadcrumb} title="Compare assessments" /><Callout tone="warning">{error}</Callout></div>;
  if (!result) return <div className="py-16 text-center text-fg-muted text-[13px]">Comparing…</div>;
  return (
    <div>
      <PageHeader
        breadcrumb={breadcrumb}
        title="Compare assessments"
        description="What changed between two runs, and which checks account for the difference in score."
      />
      <CompareView result={result} />
    </div>
  );
}
