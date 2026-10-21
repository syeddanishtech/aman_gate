import type { ReactNode } from "react";
import { AlertTriangle, ArrowRight, Check, FastForward, RotateCcw, ShieldHalf } from "lucide-react";
import { usePipeline, type PrimaryId, type JourneyStep } from "../pipeline";
import { PageHeader, SourceTag } from "../components/common";
import { DecisionStrip } from "../components/Journey";
import { SafeCopyCard } from "../components/SafeCopyCard";
import { readIntegrity } from "../lib/contract";
import { Card, Pill, Spinner } from "../ui";
import type { NavTarget } from "../nav";

const SCRIPT: { id: JourneyStep["id"]; action?: PrimaryId; actionLabel?: string; say: string; real: string }[] = [
  {
    id: "upload",
    say: "Pick a document the signed-in user may read. AMAN checks the real access list first — a locked document cannot even be analyzed.",
    real: "Real: document registry and per-user access control.",
  },
  {
    id: "detect",
    action: "analyze",
    actionLabel: "Analyze Document",
    say: "Before any AI sees it, AMAN finds emails, phone numbers, national IDs, bank accounts and secret canary tokens.",
    real: "Privacy endpoint if available, otherwise a labelled browser simulation over the real document text.",
  },
  {
    id: "sanitize",
    action: "review",
    actionLabel: "Review Safe Copy",
    say: "Each finding is replaced by a placeholder. The original stays on this machine; only the safe copy can leave.",
    real: "Same source as step 2. The verification list is a UI cross-check of the returned preview.",
  },
  {
    id: "approve",
    action: "approve",
    actionLabel: "Approve Sharing",
    say: "A human decides what the AI may see. Nothing is shared until this click.",
    real: "UI-only approval (no approval endpoint in the provisional contract).",
  },
  {
    id: "check",
    action: "run",
    actionLabel: "Run AI (Simulator)",
    say: "A local simulator answers from the safe copy only, then AMAN scans the answer for leaks and broken placeholders.",
    real: "Local simulator — no real AI is called. Assurance checks come from the endpoint if available, else the simulation.",
  },
];

export default function JudgeDemo({ go }: { go: (t: NavTarget) => void }) {
  const p = usePipeline();
  const running = p.busy !== null;
  const current = p.steps.find((s) => s.status === "current")?.id;

  return (
    <div>
      <PageHeader
        eyebrow="Guided tour"
        title="Judge Demo"
        subtitle="Five steps, about a minute. Follow the script on the left; the result builds on the right. Everything labelled Mock or Simulation is sample data."
        right={
          <>
            <button className="btn-primary" disabled={running || !p.documentId} onClick={() => void p.runAll()}>
              {running ? <Spinner /> : <FastForward size={16} aria-hidden />} Run the whole demo
            </button>
            <button className="btn-ghost" disabled={running} onClick={p.reset}>
              <RotateCcw size={14} aria-hidden /> Reset
            </button>
          </>
        }
      />

      {p.error && (
        <div role="alert" className="mb-4 flex items-start gap-2 rounded-lg border border-deny/40 bg-deny/10 px-3 py-2.5 text-sm text-deny-ink">
          <AlertTriangle size={16} className="mt-0.5 shrink-0" aria-hidden /> {p.error}
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,4fr)_minmax(0,8fr)]">
        <ol className="space-y-3" aria-label="Demo script">
          {SCRIPT.map((s, i) => {
            const step = p.steps.find((x) => x.id === s.id)!;
            const isCurrent = current === s.id;
            const canClick = !!s.action && p.primary.id === s.action && !p.primary.disabled && !running;
            return (
              <li
                key={s.id}
                aria-current={isCurrent ? "step" : undefined}
                className={`card p-4 ${isCurrent ? "border-allow ring-2 ring-allow/20" : ""}`}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={`flex h-7 w-7 items-center justify-center rounded-full border-2 text-xs font-bold ${
                      step.status === "done" ? "border-allow bg-allow text-white" : isCurrent ? "border-allow text-allow-ink" : "border-navy-600 text-slate-500"
                    }`}
                  >
                    {step.status === "done" ? <Check size={14} aria-hidden /> : i + 1}
                  </span>
                  <h2 className="text-sm font-semibold text-slate-100">{step.label}</h2>
                  <Pill tone={step.status === "done" ? "allow" : step.status === "blocked" ? "deny" : "default"}>
                    {step.status === "done" ? "Done" : step.status === "current" ? "Next" : step.status === "blocked" ? "Blocked" : "Upcoming"}
                  </Pill>
                  <span className="ml-auto">
                    {s.id === "upload" ? (
                      <select
                        aria-label="Document to demo"
                        value={p.documentId ?? ""}
                        onChange={(e) => p.selectDocument(e.target.value)}
                        disabled={running || !p.docs}
                        className="max-w-[180px] rounded-lg border px-2 py-1 text-xs"
                      >
                        {(p.docs ?? []).map((d) => (
                          <option key={d.document_id} value={d.document_id}>
                            {d.document_id}
                            {d.readable ? "" : " (no access)"}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <button className={canClick ? "btn-primary px-3 py-1.5 text-xs" : "btn-ghost px-3 py-1.5 text-xs"} disabled={!canClick} onClick={() => void p.runPrimary()}>
                        {s.actionLabel}
                      </button>
                    )}
                  </span>
                </div>
                <p className="mt-2 text-sm text-slate-300">
                  <span className="mr-1 text-[11px] font-bold uppercase tracking-wide text-slate-500">Say</span>
                  {s.say}
                </p>
                <p className="mt-1.5 text-xs text-slate-500">{s.real}</p>
                {step.status === "done" && <p className="mt-1.5 text-xs font-medium text-allow-ink">{step.detail}</p>}
              </li>
            );
          })}

          <li className="card border-dashed p-4">
            <div className="flex flex-wrap items-center gap-2">
              <ShieldHalf size={18} className="text-slate-400" aria-hidden />
              <h2 className="text-sm font-semibold text-slate-100">Bonus — AI Agent Firewall (AMAN 1.0)</h2>
              <Pill tone="allow">Real data</Pill>
              <button className="btn-ghost ml-auto px-3 py-1.5 text-xs" onClick={() => go({ section: "firewall", sub: "live" })}>
                Open live demo <ArrowRight size={13} aria-hidden />
              </button>
            </div>
            <p className="mt-2 text-sm text-slate-300">
              <span className="mr-1 text-[11px] font-bold uppercase tracking-wide text-slate-500">Say</span>
              Separately, the gateway stops a hidden instruction in a supplier quote from opening the restricted budget — enforced on the
              server, independent of the AI.
            </p>
          </li>
        </ol>

        <div className="min-w-0 space-y-4">
          <DecisionStrip decision={p.decision} />
          <SafeCopyCard
            artifact={p.view.artifact}
            label={p.view.label}
            source={p.view.source}
            isSample={p.view.isSample}
            decision={p.decision}
            blockedReason={p.blockedReason}
          />
          {p.bridge && (
            <Card title="AI answer (local simulator)" right={<SourceTag source={p.bridge.source} />}>
              <pre className="whitespace-pre-wrap break-words text-[13px] leading-6 text-slate-200" style={{ fontFamily: "inherit" }}>
                {p.bridge.data.response}
              </pre>
              {p.assurance && (
                <p className="mt-3 flex flex-wrap items-center gap-2 border-t border-navy-700 pt-3 text-sm text-slate-300">
                  Assurance:
                  <Pill tone={p.assurance.data.leaks.length ? "deny" : "allow"}>{p.assurance.data.leaks.length} leak(s)</Pill>
                  <Pill tone={p.assurance.data.flags.length ? "approve" : "allow"}>{p.assurance.data.flags.length} flag(s)</Pill>
                  <Pill tone={readIntegrity(p.assurance.data.placeholder_integrity).ok === false ? "deny" : "allow"}>
                    placeholders {readIntegrity(p.assurance.data.placeholder_integrity).ok === false ? "broken" : "intact"}
                  </Pill>
                  <SourceTag source={p.assurance.source} />
                  <button className="btn-ghost ml-auto px-3 py-1.5 text-xs" onClick={() => go({ section: "assurance" })}>
                    Details <ArrowRight size={13} aria-hidden />
                  </button>
                </p>
              )}
            </Card>
          )}
          {p.assurance && (
            <Card title="What was real in this run">
              <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
                <Row k="Document registry & access" v={<Pill tone="allow">Real</Pill>} />
                <Row k="Sensitive-data detection" v={p.analysis ? <SourceTag source={p.analysis.source} /> : "—"} />
                <Row k="Safe copy" v={p.artifact ? <SourceTag source={p.artifact.source} /> : "—"} />
                <Row k="Approval" v={<Pill>UI session only</Pill>} />
                <Row k="AI provider" v={<Pill tone="approve">Local simulator</Pill>} />
                <Row k="Output assurance" v={<SourceTag source={p.assurance.source} />} />
              </dl>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

function Row({ k, v }: { k: string; v: ReactNode }) {
  return (
    <>
      <dt className="text-slate-500">{k}</dt>
      <dd>{v}</dd>
    </>
  );
}
