import { useEffect, useState } from "react";
import { AlertTriangle, Presentation, RotateCcw } from "lucide-react";
import { api } from "../api";
import { usePipeline } from "../pipeline";
import { CheckList, PrimaryButton, SourceTag } from "../components/common";
import { DecisionStrip, JourneyRail } from "../components/Journey";
import { KpiStrip } from "../components/KpiStrip";
import { SafeCopyCard } from "../components/SafeCopyCard";
import { verifySafeCopy } from "../lib/contract";
import type { NavTarget } from "../nav";

/** Command Center 2.0 — passes the "4-second test": what it is, where I am, what is protected, what next. */
export default function Overview({ refreshKey, go }: { refreshKey: number; go: (t: NavTarget) => void }) {
  const p = usePipeline();
  const [metrics, setMetrics] = useState<any>(null);

  // Re-read the REAL gateway counters whenever a run advances (a document read is itself an audited event).
  useEffect(() => {
    api.metrics().then(setMetrics).catch(() => setMetrics(null));
  }, [refreshKey, p.analysis, p.bridge]);

  const onPrimary = () => (p.primary.id === "result" ? go({ section: "assurance" }) : void p.runPrimary());
  const readable = (p.docs ?? []).filter((d) => d.readable);

  return (
    <div className="space-y-5">
      {/* Hero heading — product name, promise, and the one next action */}
      <div className="flex flex-wrap items-end justify-between gap-5">
        <div className="min-w-0">
          <div className="eyebrow mb-1">Command Center 2.0</div>
          <h1 className="text-[36px] font-bold leading-none tracking-tight text-slate-100">AMAN Gate</h1>
          <p className="mt-2 text-lg text-slate-300">Protect documents before AI sees them</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <label htmlFor="ov-doc" className="eyebrow">
              Document
            </label>
            <select
              id="ov-doc"
              value={p.documentId ?? ""}
              onChange={(e) => p.selectDocument(e.target.value)}
              disabled={!!p.busy || !p.docs}
              className="max-w-[240px] rounded-lg border px-3 py-2 text-sm"
            >
              {(p.docs ?? []).map((d) => (
                <option key={d.document_id} value={d.document_id}>
                  {d.document_id}
                  {d.readable ? "" : " (no access)"}
                </option>
              ))}
            </select>
          </div>
          <PrimaryButton primary={p.primary} onClick={onPrimary} busy={!!p.busy} />
          {p.analysis && (
            <button className="btn-ghost" onClick={p.reset} title="Clear this document's run and start over">
              <RotateCcw size={14} aria-hidden /> Start over
            </button>
          )}
          <button className="btn-ghost" onClick={() => go({ section: "judge" })}>
            <Presentation size={15} aria-hidden /> Judge Demo
          </button>
        </div>
      </div>

      {p.error && (
        <div role="alert" className="flex items-start gap-2 rounded-lg border border-deny/40 bg-deny/10 px-3 py-2.5 text-sm text-deny-ink">
          <AlertTriangle size={16} className="mt-0.5 shrink-0" aria-hidden /> {p.error}
        </div>
      )}
      {p.docsError && (
        <div role="alert" className="rounded-lg border border-approve/50 bg-approve/10 px-3 py-2 text-sm text-approve-ink">
          Document registry unavailable: {p.docsError}
        </div>
      )}

      <KpiStrip metrics={metrics} protectedCount={p.protectedIds.length} protectedAnyMock={p.protectedAnyMock} />

      <section className="card px-6 py-4" aria-label="Protection journey">
        <JourneyRail steps={p.steps} />
      </section>

      <div className="space-y-4">
        <DecisionStrip decision={p.decision} />
        <SafeCopyCard
          artifact={p.view.artifact}
          label={p.view.label}
          source={p.view.source}
          isSample={p.view.isSample}
          decision={p.decision}
          blockedReason={p.blockedReason}
        />
        {p.reviewed && p.artifact && (
          <section className="card p-4" aria-label="Safe copy verification">
            <div className="mb-2 flex items-center gap-2">
              <h2 className="text-sm font-semibold text-slate-100">Safe-copy review</h2>
              <SourceTag source={p.artifact.source} />
            </div>
            <CheckList checks={verifySafeCopy(p.artifact.data)} />
          </section>
        )}
        <p className="text-xs text-slate-500">
          {readable.length} of {(p.docs ?? []).length} registry documents readable by your role (real access control). The two
          panes above are{" "}
          {p.view.isSample
            ? "a built-in synthetic sample — press Analyze Document to run your selected document"
            : p.view.source === "live"
            ? "returned by the Privacy Shield backend"
            : "a labelled simulation built in this browser from the real document text"}
          .
        </p>
      </div>
    </div>
  );
}
