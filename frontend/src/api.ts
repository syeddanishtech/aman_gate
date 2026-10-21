// Thin API client. The token is kept in sessionStorage (demo convenience only).
import * as mock from "./mock";

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
  let body: any = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    // Non-JSON body (e.g. a dev-proxy error page when the API is down) — surface it as the error detail.
    body = { detail: text.slice(0, 200) };
  }
  if (!res.ok) throw new ApiError(res.status, body?.detail ?? body);
  return body as T;
}

/** A document row as returned by the REAL `GET /api/documents` (AMAN 1.0). */
export interface RegistryDoc {
  document_id: string;
  title: string;
  doc_type: string;
  classification: string;
  trust_label: string;
  readable: boolean;
  acl_reason?: string;
  sha256: string;
  lab_fixture?: boolean;
}

export const api = {
  meta: () => request<any>("/api/meta"),
  demoUsers: () => request<any>("/api/auth/demo-users"),
  login: (username: string, password: string) =>
    request<any>("/api/auth/login", { method: "POST", body: JSON.stringify({ username, password }) }),
  me: () => request<User>("/api/me"),
  reset: () => request<any>("/api/demo/reset", { method: "POST" }),
  documents: () => request<{ documents: RegistryDoc[] }>("/api/documents"),
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

/* =====================================================================================================
 * AMAN Gate 2.0 — PROVISIONAL API CONTRACT (Privacy Shield · Safe Cloud Bridge · Output Assurance)
 *
 * The backends for these endpoints are being built in parallel (WP1–WP3) and DO NOT EXIST in this branch.
 * Everything below is the single place to re-point once the real routes land:
 *   1. edit ENDPOINTS if a path changes,
 *   2. edit the interfaces if a response shape changes,
 *   3. delete the `mock.*` fallbacks when you no longer want sample data.
 * Each call returns `Tagged<T>`: the data plus where it came from, so the UI can NEVER present mock output
 * as real — every panel that renders a Tagged value shows a LIVE / MOCK tag, and mock values trigger the
 * global "Simulation" watermark.
 * =================================================================================================== */

export const ENDPOINTS = {
  privacyAnalyze: "/api/privacy/analyze", // POST {document_id}
  privacyArtifact: (id: string) => `/api/privacy/artifacts/${encodeURIComponent(id)}`, // GET
  bridgeSend: "/api/bridge/send", // POST {artifact_id, provider_mode}
  assuranceCheck: "/api/assurance/check", // POST {response}
} as const;

/** Names of the contract endpoints (for the Settings status table). */
export const CONTRACT_ROWS: { key: string; method: "GET" | "POST"; path: string }[] = [
  { key: "privacyAnalyze", method: "POST", path: "/api/privacy/analyze" },
  { key: "privacyArtifact", method: "GET", path: "/api/privacy/artifacts/{id}" },
  { key: "bridgeSend", method: "POST", path: "/api/bridge/send" },
  { key: "assuranceCheck", method: "POST", path: "/api/assurance/check" },
];

/** Compile-time default for the mock fallback. The WP1-WP3 backends are now wired (privacy/bridge/assurance
 *  routes exist), so the integrated build runs LIVE with no sample data — filmed screens show real results. */
export const USE_MOCK = false;

export type MockMode = "auto" | "force" | "off";
const MOCK_MODE_KEY = "aman_gate_mock_mode";

/** auto  = call the real endpoint, fall back to labelled mock data ONLY on a 404/405 (route missing)
 *  force = never call the endpoints; always render labelled mock data
 *  off   = never mock; a missing route is surfaced as an error */
export function getMockMode(): MockMode {
  if (!USE_MOCK) return "off";
  try {
    const v = sessionStorage.getItem(MOCK_MODE_KEY);
    if (v === "auto" || v === "force" || v === "off") return v;
  } catch {
    /* ignore */
  }
  return "auto";
}
export function setMockMode(m: MockMode) {
  try {
    sessionStorage.setItem(MOCK_MODE_KEY, m);
  } catch {
    /* ignore */
  }
}

export type DataSource = "live" | "mock";
export interface Tagged<T> {
  data: T;
  source: DataSource;
}

// ---- response shapes (provisional) ----------------------------------------------------------------

export interface DisclosureElement {
  id: string;
  type: string;
  page: number;
  sensitivity: string; // e.g. public | internal | confidential | restricted
  source_trust: string; // e.g. trusted_internal | untrusted_external
  action: string; // keep | generalize | pseudonymize | redact | omit | deny
}

export interface AnalyzeResponse {
  disclosure: { elements: DisclosureElement[]; findings_count: number };
  safe_artifact_id: string;
  /** Provisional: READY_FOR_REVIEW | BLOCKED (| APPROVED). Normalised by `normalizeDecision`. */
  decision: string;
  /** Not in the agreed contract — optional extra the UI shows when present (the mock fills it). */
  blocked_reason?: string;
}

/** `findings:[...]` is unspecified in the contract. The UI highlights using, in order of preference:
 *  start/end offsets into `original_preview`, else the literal `original` / `replacement` strings. */
export interface Finding {
  id?: string;
  type: string;
  page?: number;
  sensitivity?: string;
  action?: string;
  start?: number;
  end?: number;
  original?: string;
  replacement?: string;
}

export interface ArtifactResponse {
  original_preview: string;
  safe_copy_preview: string;
  findings: Finding[];
}

export type ProviderMode = "LOCAL_SIMULATOR" | "LOCAL_LLM" | "REAL_CLOUD";

export interface BridgeSendResponse {
  mode: "LOCAL_SIMULATOR" | string;
  response: string;
  watermark: boolean;
  egress_blocked_reasons?: string[];
}

/** Shape of `placeholder_integrity` / `leaks` / `flags` / `rehydrated` is unspecified; kept permissive and
 *  rendered through the defensive helpers in `lib/contract.ts`. */
export interface AssuranceResponse {
  placeholder_integrity: unknown;
  leaks: unknown[];
  flags: unknown[];
  rehydrated: string | boolean | null;
}

// ---- transport + fallback ---------------------------------------------------------------------------

export interface EndpointStatus {
  source: DataSource | "error";
  at: number;
  note?: string;
}
const endpointStatus: Record<string, EndpointStatus> = {};
export function getEndpointStatus(): Record<string, EndpointStatus> {
  return { ...endpointStatus };
}

/** A 404/405 from FastAPI's router ("Not Found" / "Method Not Allowed") means the ROUTE is missing. A real
 *  handler that wants to say "no such document" returns a structured {code,message} detail, which is NOT
 *  treated as a missing route and is surfaced as a normal error. */
function isMissingRoute(e: unknown): boolean {
  if (!(e instanceof ApiError)) return false;
  if (e.status !== 404 && e.status !== 405) return false;
  const d = e.detail;
  if (d == null) return true;
  if (typeof d === "string") return /^(not found|method not allowed)$/i.test(d.trim());
  return false;
}

async function withMockFallback<T>(
  key: string,
  live: () => Promise<T>,
  fallback: () => Promise<T> | T,
): Promise<Tagged<T>> {
  const mode = getMockMode();
  if (mode === "force") {
    const data = await fallback();
    endpointStatus[key] = { source: "mock", at: Date.now(), note: "forced simulation" };
    return { data, source: "mock" };
  }
  try {
    const data = await live();
    endpointStatus[key] = { source: "live", at: Date.now() };
    return { data, source: "live" };
  } catch (e) {
    if (mode === "auto" && isMissingRoute(e)) {
      const data = await fallback();
      endpointStatus[key] = { source: "mock", at: Date.now(), note: `route missing (${(e as ApiError).status})` };
      return { data, source: "mock" };
    }
    endpointStatus[key] = { source: "error", at: Date.now(), note: e instanceof Error ? e.message : String(e) };
    throw e;
  }
}

/** Fetch the REAL document text through the gateway (so mock detection runs over genuine registry content
 *  and a genuine ACL denial still blocks). Returns text, or the denial detail. */
async function readRealDocument(documentId: string): Promise<{ text?: string; denied?: any; meta?: any }> {
  try {
    const res = await api.readDocument(documentId);
    return { text: res?.document?.content ?? "", meta: res?.document };
  } catch (e) {
    if (e instanceof ApiError && (e.status === 403 || e.status === 404 || e.status === 401)) {
      return { denied: e.detail };
    }
    throw e;
  }
}

export const privacy = {
  analyze: (documentId: string) =>
    withMockFallback<AnalyzeResponse>(
      "privacyAnalyze",
      () =>
        request<AnalyzeResponse>(ENDPOINTS.privacyAnalyze, {
          method: "POST",
          body: JSON.stringify({ document_id: documentId }),
        }),
      async () => {
        const doc = await readRealDocument(documentId);
        return mock.analyze(documentId, doc);
      },
    ),
  artifact: (artifactId: string) =>
    withMockFallback<ArtifactResponse>(
      "privacyArtifact",
      () => request<ArtifactResponse>(ENDPOINTS.privacyArtifact(artifactId)),
      () => mock.artifact(artifactId),
    ),
};

export const bridge = {
  send: (artifactId: string, providerMode: ProviderMode = "LOCAL_SIMULATOR") =>
    withMockFallback<BridgeSendResponse>(
      "bridgeSend",
      () =>
        request<BridgeSendResponse>(ENDPOINTS.bridgeSend, {
          method: "POST",
          body: JSON.stringify({ artifact_id: artifactId, provider_mode: providerMode }),
        }),
      () => mock.bridgeSend(artifactId, providerMode),
    ),
};

export const assurance = {
  // `artifactId` names the vault session stored at analyze time; without it the backend has no token map,
  // so placeholder integrity is "not determined" and rehydration is null. Always pass it when known.
  check: (response: string, artifactId?: string) =>
    withMockFallback<AssuranceResponse>(
      "assuranceCheck",
      () =>
        request<AssuranceResponse>(ENDPOINTS.assuranceCheck, {
          method: "POST",
          body: JSON.stringify(artifactId ? { response, artifact_id: artifactId } : { response }),
        }),
      () => mock.assuranceCheck(response),
    ),
};
