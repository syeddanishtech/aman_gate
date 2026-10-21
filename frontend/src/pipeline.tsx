// Shared state for the 2.0 document journey:
//   Upload → Detect Sensitive Data → Sanitize & Verify → Approve AI Access → Check AI Result
// One provider feeds the Overview hero, Protect Documents, Safe Cloud Bridge, Output Assurance and Judge Demo,
// so the whole app tells one consistent story. Every backend-derived value is kept as Tagged<T> (live | mock).
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  ApiError,
  api,
  assurance as assuranceApi,
  bridge as bridgeApi,
  privacy as privacyApi,
  type AnalyzeResponse,
  type ArtifactResponse,
  type AssuranceResponse,
  type BridgeSendResponse,
  type DataSource,
  type ProviderMode,
  type RegistryDoc,
  type Tagged,
} from "./api";
import { normalizeDecision, type Decision } from "./lib/contract";
import { SAMPLE_DOC_ID, sampleArtifact } from "./mock";

export type StepStatus = "done" | "current" | "todo" | "blocked";
export interface JourneyStep {
  id: "upload" | "detect" | "sanitize" | "approve" | "check";
  label: string;
  status: StepStatus;
  detail: string;
}

export type PrimaryId = "analyze" | "review" | "approve" | "run" | "result" | "blocked";
export interface PrimaryAction {
  id: PrimaryId;
  label: string;
  disabled: boolean;
  hint?: string;
}

interface State {
  docs: RegistryDoc[] | null;
  docsError: string | null;
  documentId: string | null;
  analysis: Tagged<AnalyzeResponse> | null;
  artifact: Tagged<ArtifactResponse> | null;
  reviewed: boolean;
  approved: boolean;
  providerMode: ProviderMode;
  bridge: Tagged<BridgeSendResponse> | null;
  assurance: Tagged<AssuranceResponse> | null;
  assuranceInput: string;
  busy: "analyze" | "run" | "check" | null;
  error: string | null;
  protectedIds: string[]; // distinct safe artifacts produced this session
  protectedAnyMock: boolean;
}

const initial: State = {
  docs: null,
  docsError: null,
  documentId: null,
  analysis: null,
  artifact: null,
  reviewed: false,
  approved: false,
  providerMode: "LOCAL_SIMULATOR",
  bridge: null,
  assurance: null,
  assuranceInput: "",
  busy: null,
  error: null,
  protectedIds: [],
  protectedAnyMock: false,
};

const JOURNEY: { id: JourneyStep["id"]; label: string }[] = [
  { id: "upload", label: "Upload" },
  { id: "detect", label: "Detect Sensitive Data" },
  { id: "sanitize", label: "Sanitize & Verify" },
  { id: "approve", label: "Approve AI Access" },
  { id: "check", label: "Check AI Result" },
];

export interface Pipeline extends State {
  decision: Decision;
  blockedReason: string | null;
  steps: JourneyStep[];
  primary: PrimaryAction;
  /** What the two-pane hero shows: the analyzed artifact, or the labelled built-in sample. */
  view: { artifact: ArtifactResponse; isSample: boolean; label: string; source: DataSource };
  simulationReasons: string[];
  selectDocument: (id: string) => void;
  setProviderMode: (m: ProviderMode) => void;
  analyze: () => Promise<void>;
  review: () => void;
  approve: () => void;
  runAI: () => Promise<void>;
  checkResponse: (text: string) => Promise<void>;
  runPrimary: () => Promise<void>;
  runAll: () => Promise<void>;
  reset: () => void;
  clearError: () => void;
}

const Ctx = createContext<Pipeline | null>(null);

export function usePipeline(): Pipeline {
  const v = useContext(Ctx);
  if (!v) throw new Error("usePipeline outside PipelineProvider");
  return v;
}

export function errMsg(e: unknown): string {
  if (e instanceof ApiError) {
    const d = e.detail;
    if (d && typeof d === "object") return d.message || d.code || `HTTP ${e.status}`;
    return typeof d === "string" ? d : `HTTP ${e.status}`;
  }
  return e instanceof Error ? e.message : String(e);
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function PipelineProvider({ refreshKey, children }: { refreshKey: number; children: ReactNode }) {
  const [state, setRaw] = useState<State>(initial);
  const ref = useRef<State>(initial);
  const set = useCallback((patch: Partial<State> | ((s: State) => Partial<State>)) => {
    const p = typeof patch === "function" ? patch(ref.current) : patch;
    ref.current = { ...ref.current, ...p };
    setRaw(ref.current);
  }, []);

  // Registry is REAL data (GET /api/documents, ACL-aware).
  useEffect(() => {
    api
      .documents()
      .then((d) => {
        // B18: do NOT auto-select a document. Pre-selecting one made the "Upload" step show as completed
        // before the user had chosen anything. The list is shown; the user picks, and only then is step 1 done.
        set((s) => ({ docs: d.documents, docsError: null, documentId: s.documentId }));
      })
      .catch((e) => set({ docsError: errMsg(e) }));
  }, [refreshKey, set]);

  const selectDocument = useCallback(
    (id: string) => {
      if (ref.current.documentId === id) return;
      set({ documentId: id, analysis: null, artifact: null, reviewed: false, approved: false, bridge: null, assurance: null, assuranceInput: "", error: null });
    },
    [set],
  );

  const reset = useCallback(
    () => set({ analysis: null, artifact: null, reviewed: false, approved: false, bridge: null, assurance: null, assuranceInput: "", error: null, busy: null }),
    [set],
  );

  const analyze = useCallback(async () => {
    const id = ref.current.documentId;
    if (!id || ref.current.busy) return;
    set({ busy: "analyze", error: null, analysis: null, artifact: null, reviewed: false, approved: false, bridge: null, assurance: null, assuranceInput: "" });
    try {
      const a = await privacyApi.analyze(id);
      set({ analysis: a });
      let art: Tagged<ArtifactResponse> | null = null;
      if (a.data.safe_artifact_id) art = await privacyApi.artifact(a.data.safe_artifact_id);
      set((s) => {
        const blocked = normalizeDecision(a.data.decision) === "BLOCKED";
        const known = s.protectedIds.includes(a.data.safe_artifact_id);
        return {
          artifact: art,
          protectedIds: !blocked && a.data.safe_artifact_id && !known ? [...s.protectedIds, a.data.safe_artifact_id] : s.protectedIds,
          protectedAnyMock: s.protectedAnyMock || (!blocked && (a.source === "mock" || art?.source === "mock")),
        };
      });
    } catch (e) {
      set({ error: errMsg(e) });
    } finally {
      set({ busy: null });
    }
  }, [set]);

  const review = useCallback(() => {
    if (ref.current.analysis && normalizeDecision(ref.current.analysis.data.decision) !== "BLOCKED") set({ reviewed: true });
  }, [set]);

  const approve = useCallback(() => {
    const s = ref.current;
    if (s.analysis && s.reviewed && normalizeDecision(s.analysis.data.decision) !== "BLOCKED") set({ approved: true });
  }, [set]);

  const checkResponse = useCallback(
    async (text: string) => {
      const artifactId = ref.current.analysis?.data.safe_artifact_id || undefined;
      set({ busy: "check", error: null, assuranceInput: text });
      try {
        const a = await assuranceApi.check(text, artifactId);
        set({ assurance: a });
      } catch (e) {
        set({ error: errMsg(e) });
      } finally {
        set({ busy: null });
      }
    },
    [set],
  );

  const runAI = useCallback(async () => {
    const s = ref.current;
    const artifactId = s.analysis?.data.safe_artifact_id;
    if (!artifactId || !s.approved || s.busy) return;
    set({ busy: "run", error: null, bridge: null, assurance: null });
    try {
      const b = await bridgeApi.send(artifactId, s.providerMode);
      set({ bridge: b, assuranceInput: b.data.response });
      const a = await assuranceApi.check(b.data.response, artifactId);
      set({ assurance: a });
    } catch (e) {
      set({ error: errMsg(e) });
    } finally {
      set({ busy: null });
    }
  }, [set]);

  const decision: Decision = useMemo(() => {
    if (!state.analysis) return "NOT_SHARED";
    const d = normalizeDecision(state.analysis.data.decision);
    if (d === "BLOCKED") return "BLOCKED";
    return state.approved ? "APPROVED" : "READY_FOR_REVIEW";
  }, [state.analysis, state.approved]);

  const blockedReason = useMemo(() => {
    if (decision !== "BLOCKED") return null;
    return state.analysis?.data.blocked_reason ?? "The gateway or policy refused to produce a shareable copy. Nothing can be sent to an AI.";
  }, [decision, state.analysis]);

  const steps: JourneyStep[] = useMemo(() => {
    const blocked = decision === "BLOCKED";
    const done: Record<JourneyStep["id"], boolean> = {
      upload: !!state.documentId,
      detect: !!state.analysis,
      sanitize: state.reviewed,
      approve: state.approved,
      check: !!state.assurance,
    };
    const detail: Record<JourneyStep["id"], string> = {
      upload: state.documentId ?? "Choose a document",
      detect: state.analysis ? `${state.analysis.data.disclosure.findings_count} finding(s)` : "Find PII, IDs, secrets",
      sanitize: state.reviewed ? "Safe copy verified" : state.analysis ? "Review the safe copy" : "Build a safe copy",
      approve: state.approved ? "Sharing approved" : "Human sign-off",
      check: state.assurance ? "Result checked" : "Leaks & placeholders",
    };
    let currentSeen = false;
    return JOURNEY.map((j) => {
      let status: StepStatus;
      if (done[j.id]) status = "done";
      else if (blocked && j.id !== "upload" && j.id !== "detect") status = "blocked";
      else if (!currentSeen) {
        status = "current";
        currentSeen = true;
      } else status = "todo";
      return { ...j, status, detail: status === "blocked" ? "Not available — blocked" : detail[j.id] };
    });
  }, [decision, state.documentId, state.analysis, state.reviewed, state.approved, state.assurance]);

  const primary: PrimaryAction = useMemo(() => {
    if (state.busy === "analyze") return { id: "analyze", label: "Analyzing…", disabled: true };
    if (state.busy === "run") return { id: "run", label: "Running simulator…", disabled: true };
    if (!state.analysis)
      return { id: "analyze", label: "Analyze Document", disabled: !state.documentId, hint: state.documentId ? undefined : "Pick a document first" };
    if (decision === "BLOCKED") return { id: "blocked", label: "Blocked — nothing to share", disabled: true };
    if (!state.reviewed) return { id: "review", label: "Review Safe Copy", disabled: !state.artifact };
    if (!state.approved) return { id: "approve", label: "Approve Sharing", disabled: false };
    if (!state.bridge) return { id: "run", label: "Run AI (Simulator)", disabled: false };
    return { id: "result", label: "Check AI Result", disabled: false };
  }, [state.busy, state.analysis, state.documentId, state.reviewed, state.approved, state.artifact, state.bridge, decision]);

  const runPrimary = useCallback(async () => {
    const id = primary.id;
    if (id === "analyze") await analyze();
    else if (id === "review") review();
    else if (id === "approve") approve();
    else if (id === "run") await runAI();
    // "result" is navigation — handled by the caller (it knows the router).
  }, [primary.id, analyze, review, approve, runAI]);

  const runAll = useCallback(async () => {
    reset();
    await sleep(60);
    await analyze();
    if (!ref.current.analysis || normalizeDecision(ref.current.analysis.data.decision) === "BLOCKED") return;
    await sleep(600);
    review();
    await sleep(600);
    approve();
    await sleep(600);
    await runAI();
  }, [reset, analyze, review, approve, runAI]);

  const view = useMemo(() => {
    if (state.artifact) {
      return { artifact: state.artifact.data, isSample: false, label: state.documentId ?? "document", source: state.artifact.source };
    }
    return { artifact: sampleArtifact(), isSample: true, label: `${SAMPLE_DOC_ID} (built-in sample)`, source: "mock" as DataSource };
  }, [state.artifact, state.documentId]);

  const simulationReasons = useMemo(() => {
    const r: string[] = [];
    if (!state.artifact) r.push("Sample preview — mock data");
    const anyMock = [state.analysis, state.artifact, state.bridge, state.assurance].some((t) => t?.source === "mock");
    if (anyMock) r.push("Mock data — backend endpoint not available");
    if (state.bridge) r.push("Local simulator — no real AI provider");
    return r;
  }, [state.analysis, state.artifact, state.bridge, state.assurance]);

  const value: Pipeline = {
    ...state,
    decision,
    blockedReason,
    steps,
    primary,
    view,
    simulationReasons,
    selectDocument,
    setProviderMode: (m) => set({ providerMode: m }),
    analyze,
    review,
    approve,
    runAI,
    checkResponse,
    runPrimary,
    runAll,
    reset,
    clearError: () => set({ error: null }),
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
