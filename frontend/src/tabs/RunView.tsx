import { Bot, ShieldCheck, ArrowRight, AlertTriangle, CheckCircle2 } from "lucide-react";
import { DecisionBadge, Pill } from "../ui";

// Shared renderer for a baseline-vs-gated scenario result.
export function GatedSteps({ steps }: { steps: any[] }) {
  return (
    <div className="space-y-2">
      {steps.map((s, i) => (
        <div key={i} className="rounded-lg border border-navy-700 bg-navy-900/60 p-3">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <span className="mono text-xs font-semibold text-slate-200">{s.tool}</span>
              {s.origin?.startsWith("document_injection") ? (
                <Pill tone="deny">
                  <AlertTriangle size={11} /> from document
                </Pill>
              ) : (
                <Pill>user task</Pill>
              )}
            </div>
            <DecisionBadge decision={s.decision} />
          </div>
          <div className="mono mt-1.5 text-[11px] text-slate-500">{JSON.stringify(s.args)}</div>
          <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-[11px]">
            <span className="mono rounded bg-navy-800 px-1.5 py-0.5 text-slate-400">{s.policy_id}</span>
            {s.reason_codes?.map((c: string) => (
              <span key={c} className="mono rounded bg-navy-800 px-1.5 py-0.5 text-slate-300">
                {c}
              </span>
            ))}
            <span className="text-slate-600">· {s.decision_latency_ms?.toFixed(2)} ms</span>
            <span className="text-slate-600">· risk {s.risk_band}</span>
          </div>
          {s.explanation && <p className="mt-1 text-[11px] text-slate-400">{s.explanation}</p>}
          {s.approval_followup && (
            <div className="mt-2 rounded border border-approve/30 bg-approve/5 p-2 text-[11px] text-slate-300">
              {s.approval_followup.result === "EXECUTED" && (
                <span>
                  Approved by <b>{s.approval_followup.approver}</b> → executed to local simulator. Replay
                  attempt: <b>{s.approval_followup.replay_attempt?.code || "refused"}</b>.
                </span>
              )}
              {s.approval_followup.result === "REFUSED" && (
                <span>
                  Execution refused: <b>{s.approval_followup.code}</b> — {s.approval_followup.message}
                </span>
              )}
            </div>
          )}
          {s.output?.content_sha256 && (
            <div className="mono mt-1 text-[11px] text-slate-600">
              content sha256 {s.output.content_sha256.slice(0, 16)}… ({s.output.content_chars} chars, not logged)
            </div>
          )}
          {s.event_id && <div className="mono mt-1 text-[10px] text-slate-700">event {s.event_id}</div>}
        </div>
      ))}
    </div>
  );
}

export function BaselineSteps({ steps, summary }: { steps: any[]; summary: any }) {
  return (
    <div className="space-y-2">
      <div className="rounded-lg border border-deny/30 bg-deny/5 p-2.5 text-[11px] text-slate-300">
        <b className="text-deny-ink">Baseline lab (no enforcement).</b> Intentionally insufficient
        authorization. Safe local sandbox — no network, no real files.
      </div>
      {steps.map((s, i) => (
        <div key={i} className="rounded-lg border border-navy-700 bg-navy-900/60 p-3">
          <div className="flex items-center justify-between gap-2">
            <span className="mono text-xs font-semibold text-slate-200">{s.tool}</span>
            <Pill tone="deny">{String(s.decision).replace(/_/g, " ")}</Pill>
          </div>
          <div className="mono mt-1 text-[11px] text-slate-500">{JSON.stringify(s.args)}</div>
          {s.lab_note && <p className="mt-1 text-[11px] text-approve-ink">{s.lab_note}</p>}
        </div>
      ))}
      {summary?.exposed_restricted_resources?.length > 0 && (
        <div className="rounded-lg border border-deny/40 bg-deny/10 p-2.5 text-[11px] text-deny-ink">
          Without AMAN Gate the baseline exposed restricted resources:{" "}
          <b className="mono">{summary.exposed_restricted_resources.join(", ")}</b>
        </div>
      )}
    </div>
  );
}

export function SplitRun({ result }: { result: any }) {
  const gated = result.gated;
  const baseline = result.baseline;
  // B1: count each gated decision once. injected_attempts_blocked is a SUBSET of deny, so it must not be
  // added again — the badge is simply the denials plus the held (needs-approval) actions.
  const blocked = (gated?.summary?.deny || 0) + (gated?.summary?.needs_approval || 0);
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <div className="card p-4">
        <div className="mb-3 flex items-center gap-2">
          <Bot size={18} className="text-slate-300" />
          <h3 className="text-sm font-semibold text-slate-100">AI Procurement Assistant</h3>
          <span className="tag border border-navy-600 bg-navy-800 text-slate-400">scripted planner · no LLM</span>
          <span className="ml-auto text-[11px] text-slate-500">
            proposes {gated?.steps?.length || 0} action(s)
          </span>
        </div>
        {gated?.followed_injection ? (
          <div className="mb-3 flex items-center gap-2 rounded-lg border border-deny/30 bg-deny/5 px-3 py-2 text-[11px] text-deny-ink">
            <AlertTriangle size={13} /> The assistant was manipulated by text hidden in{" "}
            {gated.injection_sources?.join(", ")} and tried extra actions.
          </div>
        ) : (
          <div className="mb-3 flex items-center gap-2 rounded-lg border border-navy-700 bg-navy-800 px-3 py-2 text-[11px] text-slate-400">
            <CheckCircle2 size={13} /> No injected instructions detected in this scenario.
          </div>
        )}
        {baseline ? (
          <BaselineSteps steps={baseline.steps} summary={baseline.summary} />
        ) : (
          <p className="text-xs text-slate-500">Baseline lab disabled.</p>
        )}
      </div>

      <div className="card border-allow/20 p-4">
        <div className="mb-3 flex items-center gap-2">
          <ShieldCheck size={18} className="text-allow-ink" />
          <h3 className="text-sm font-semibold text-slate-100">AMAN Gate Security Decision</h3>
          <span className="ml-auto tag border border-allow/30 bg-allow/10 text-allow-ink">
            <ArrowRight size={11} /> {blocked} blocked / held
          </span>
        </div>
        <GatedSteps steps={gated?.steps || []} />
      </div>
    </div>
  );
}
