// Thin API client. The token is kept in sessionStorage (demo convenience only).
export type Role = "procurement_officer" | "junior_clerk" | "finance_manager" | "security_analyst";

export interface User {
  user_id: string;
  username: string;
  display_name: string;
  role: Role;
  tenant_id: string;
}

const TOKEN_KEY = "aman_gate_token";

export function getToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}
export function setToken(t: string | null) {
  try {
    if (t) sessionStorage.setItem(TOKEN_KEY, t);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* ignore */
  }
}

export class ApiError extends Error {
  status: number;
  detail: any;
  constructor(status: number, detail: any) {
    super(typeof detail === "string" ? detail : detail?.code || "error");
    this.status = status;
    this.detail = detail;
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    ...(options.headers as Record<string, string>),
  };
  const token = getToken();
  if (token) headers["authorization"] = `Bearer ${token}`;
  const res = await fetch(path, { ...options, headers });
  const text = await res.text();
  const body = text ? JSON.parse(text) : null;
  if (!res.ok) throw new ApiError(res.status, body?.detail ?? body);
  return body as T;
}

export const api = {
  meta: () => request<any>("/api/meta"),
  demoUsers: () => request<any>("/api/auth/demo-users"),
  login: (username: string, password: string) =>
    request<any>("/api/auth/login", { method: "POST", body: JSON.stringify({ username, password }) }),
  me: () => request<User>("/api/me"),
  reset: () => request<any>("/api/demo/reset", { method: "POST" }),
  documents: () => request<any>("/api/documents"),
  readDocument: (id: string) => request<any>(`/api/documents/${encodeURIComponent(id)}`),
  assessRisk: (text: string) =>
    request<any>("/api/risk/assess", { method: "POST", body: JSON.stringify({ text }) }),
  invoke: (tool: string, args: any, extra: any = {}) =>
    request<any>("/api/tools/invoke", { method: "POST", body: JSON.stringify({ tool, args, ...extra }) }),
  policies: () => request<any>("/api/policies"),
  reports: () => request<any>("/api/reports"),
  approvals: () => request<any>("/api/approvals"),
  decideApproval: (id: string, approve: boolean, note?: string) =>
    request<any>(`/api/approvals/${id}/decision`, {
      method: "POST",
      body: JSON.stringify({ approve, note }),
    }),
  executeApproval: (id: string) => request<any>(`/api/approvals/${id}/execute`, { method: "POST" }),
  scenarios: () => request<any>("/api/scenarios"),
  runScenario: (scenario_id: string) =>
    request<any>("/api/scenarios/run", { method: "POST", body: JSON.stringify({ scenario_id }) }),
  runs: () => request<any>("/api/runs"),
  run: (id: string) => request<any>(`/api/runs/${id}`),
  auditEvents: (params: Record<string, string> = {}) =>
    request<any>("/api/audit/events?" + new URLSearchParams(params).toString()),
  auditVerify: () => request<any>("/api/audit/verify"),
  auditExport: () => request<any>("/api/audit/export"),
  metrics: () => request<any>("/api/metrics"),
  mlMetrics: () => request<any>("/api/ml/metrics"),
  evidence: () => request<any>("/api/evidence/report"),
};
