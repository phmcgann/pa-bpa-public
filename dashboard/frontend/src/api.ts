import type {
  AssessmentDetail, Note, NoteKind, ReanalyzeResult, AssessmentListItem, CompareResult, ClientSummary, PanoramaUploadResult, RuleDef, ScmCatalog, ScmStatus, ScoringSettings,
  UploadResult,
} from "./types";

const BASE = import.meta.env.VITE_API_BASE ?? "http://127.0.0.1:8000";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: init?.body && !(init.body instanceof FormData)
      ? { "Content-Type": "application/json", ...init.headers }
      : init?.headers,
    ...init,
  });
  if (!res.ok) {
    // FastAPI puts the human-readable reason in `detail`; fall back to the status line.
    const body = await res.text();
    let detail: unknown = null;
    try { detail = JSON.parse(body).detail; } catch { /* not JSON */ }
    throw new Error(typeof detail === "string" ? detail : `${res.status} ${res.statusText}${body ? `: ${body}` : ""}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

export const api = {
  uploadAssessment: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return request<UploadResult | PanoramaUploadResult>(
      "/api/assessments/upload",
      { method: "POST", body: form }
    );
  },
  createFromPanorama: (uploadId: number, deviceGroup: string) =>
    request<UploadResult>("/api/assessments/from-panorama", {
      method: "POST",
      body: JSON.stringify({ upload_id: uploadId, device_group: deviceGroup }),
    }),
  listAssessments: () => request<AssessmentListItem[]>("/api/assessments"),
  getAssessment: (id: number) => request<AssessmentDetail>(`/api/assessments/${id}`),
  reanalyzeAssessment: (id: number) =>
    request<ReanalyzeResult>(`/api/assessments/${id}/reanalyze`, { method: "POST" }),
  compareAssessments: (base: number, target: number) =>
    request<CompareResult>(`/api/compare?base=${base}&target=${target}`),
  updateAssessment: (id: number, body: { client_name?: string | null; serial?: string | null }) =>
    request<{ id: number; client_name: string | null; serial: string | null; model: string | null; also_applied: number }>(
      `/api/assessments/${id}`, { method: "PATCH", body: JSON.stringify(body) }
    ),
  listClients: () => request<ClientSummary[]>("/api/clients"),
  deleteAssessment: (id: number) => request<void>(`/api/assessments/${id}`, { method: "DELETE" }),
  dismissFinding: (assessmentId: number, findingKey: string, reason?: string) =>
    request(`/api/assessments/${assessmentId}/findings/${encodeURIComponent(findingKey)}/dismiss`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  undismissFinding: (assessmentId: number, findingKey: string) =>
    request(`/api/assessments/${assessmentId}/findings/${encodeURIComponent(findingKey)}/undismiss`, {
      method: "POST",
    }),
  saveNote: (assessmentId: number, body: { target_kind: NoteKind; target_key: string; target_label: string; body: string }) =>
    request<Note[]>(`/api/assessments/${assessmentId}/notes`, { method: "POST", body: JSON.stringify(body) }),
  deleteNote: (assessmentId: number, noteId: number) =>
    request<Note[]>(`/api/assessments/${assessmentId}/notes/${noteId}`, { method: "DELETE" }),
  listRules: () => request<RuleDef[]>("/api/rules"),
  updateRule: (
    id: string,
    body: { enabled?: boolean; threshold_overrides?: Record<string, number>; severity_override?: string }
  ) => request<RuleDef>(`/api/rules/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  runScmBpa: (assessmentId: number) =>
    request<ScmStatus>(`/api/assessments/${assessmentId}/scm-bpa`, { method: "POST" }),
  getScmCatalog: () => request<ScmCatalog>("/api/scm/catalog"),
  updateScmSettings: (body: { include_in_score: boolean }) =>
    request<{ include_in_score: boolean }>("/api/scm/settings", { method: "PATCH", body: JSON.stringify(body) }),
  getScoring: () => request<ScoringSettings>("/api/scoring"),
  updateScoring: (body: Partial<{
    weight_critical: number; weight_warning: number; weight_low: number; weight_informational: number;
    informational_max: number; low_max: number; warning_max: number;
  }>) => request<ScoringSettings>("/api/scoring", { method: "PATCH", body: JSON.stringify(body) }),
};
