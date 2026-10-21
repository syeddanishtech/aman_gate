import { useEffect, useState } from "react";
import { PlayCircle, CheckCircle2, XCircle } from "lucide-react";
import { api } from "../api";
import { Spinner, Pill } from "../ui";
import { SplitRun } from "./RunView";

export default function Replay({ refreshKey, onChanged }: { refreshKey: number; onChanged: () => void }) {
  const [scenarios, setScenarios] = useState<any[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [result, setResult] = useState<any>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.scenarios().then((d) => {
      setScenarios(d.scenarios);
      if (!selected && d.scenarios[0]) setSelected(d.scenarios[0].id);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refreshKey]);

  async function run(id: string) {
    setSelected(id);
    setBusy(true);
    setResult(null);
    try {
      const res = await api.runScenario(id);
      setResult(res);
      onChanged();
    } finally {
      setBusy(false);
    }
  }

  const selectedScenario = scenarios.find((s) => s.id === selected);

  return (
    <div className="grid gap-4 lg:grid-cols-[340px_1fr]">
      <div className="space-y-2">
        <h2 className="px-1 text-xs font-semibold uppercase tracking-wide text-slate-400">
          Scenarios ({scenarios.length})
        </h2>
        {scenarios.map((s) => (
          <button
            key={s.id}
            onClick={() => run(s.id)}
            className={`w-full rounded-lg border p-3 text-left transition-colors ${
              selected === s.id
                ? "border-allow/40 bg-navy-800"
                : "border-navy-700 bg-navy-850 hover:border-navy-600"
            }`}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="mono text-[11px] text-slate-500">{s.id}</span>
              <Pill>{s.category}</Pill>
            </div>
            <div className="mt-1 text-sm font-medium text-slate-100">{s.title}</div>
            <p className="mt-0.5 line-clamp-2 text-[11px] text-slate-500">{s.description}</p>
          </button>
        ))}
      </div>

      <div className="space-y-4">
        {selectedScenario && (
          <div className="card p-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold text-slate-100">{selectedScenario.title}</h2>
                <p className="mt-0.5 text-xs text-slate-400">{selectedScenario.description}</p>
                <p className="mt-1.5 text-[11px] text-slate-500">
                  <b>Expected:</b> {selectedScenario.expectation}
                </p>
                {selectedScenario.note && (
                  <p className="mt-1 text-[11px] text-approve-ink">Note: {selectedScenario.note}</p>
                )}
              </div>
              <button className="btn-primary shrink-0" disabled={busy} onClick={() => run(selectedScenario.id)}>
                {busy ? <Spinner /> : <PlayCircle size={14} />} Run baseline + gated
              </button>
            </div>
            <div className="mt-3 flex flex-wrap gap-1.5">
              <span className="text-[11px] text-slate-500">acts as</span>
              <Pill>{selectedScenario.actor_username}</Pill>
              {selectedScenario.feed_doc_ids?.map((d: string) => (
                <span key={d} className="mono rounded bg-navy-800 px-1.5 py-0.5 text-[11px] text-slate-400">
                  feeds {d}
                </span>
              ))}
            </div>
          </div>
        )}

        {result && <ParitySummary result={result} />}
        {result ? (
          <SplitRun result={result} />
        ) : (
          <div className="card p-10 text-center text-sm text-slate-500">
            Select a scenario and run it to see the identical input sent through the baseline lab and
            through AMAN Gate side by side.
          </div>
        )}
      </div>
    </div>
  );
}

function ParitySummary({ result }: { result: any }) {
  const p = result.parity || {};
  const gatedExposed = false;
  const baseExposed = (p.baseline_exposed_restricted || []).length > 0;
  return (
    <div className="card p-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="rounded-lg border border-deny/30 bg-deny/5 p-3">
          <div className="flex items-center gap-2 text-xs font-semibold text-deny-ink">
            <XCircle size={14} /> Baseline (no enforcement)
          </div>
          <p className="mt-1 text-[11px] text-slate-300">
            Exposed restricted:{" "}
            <b className="mono">
              {baseExposed ? p.baseline_exposed_restricted.join(", ") : "none in this scenario"}
            </b>
          </p>
        </div>
        <div className="rounded-lg border border-allow/30 bg-allow/5 p-3">
          <div className="flex items-center gap-2 text-xs font-semibold text-allow-ink">
            <CheckCircle2 size={14} /> AMAN Gate
          </div>
          <p className="mt-1 text-[11px] text-slate-300">
            Blocked / held: <b>{p.gated_blocked_or_held}</b> · injected attempts blocked:{" "}
            <b>{p.gated_injected_blocked}</b> · restricted exposed: <b>{gatedExposed ? "yes" : "none"}</b>
          </p>
        </div>
      </div>
      <p className="mt-2 text-[11px] text-slate-500">
        Same run IDs persisted: gated <span className="mono">{result.gated?.run_id}</span>
        {result.baseline && (
          <>
            {" "}
            · baseline <span className="mono">{result.baseline.run_id}</span>
          </>
        )}
      </p>
    </div>
  );
}
