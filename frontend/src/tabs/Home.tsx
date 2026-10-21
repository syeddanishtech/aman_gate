import { useEffect, useState } from "react";
import { PlayCircle, FlaskConical, ShieldCheck, FileWarning, ArrowRight } from "lucide-react";
import { api } from "../api";
import { Stat, Spinner, Pill } from "../ui";
import { SplitRun } from "./RunView";

export default function Home({
  refreshKey,
  goTo,
  onChanged,
}: {
  refreshKey: number;
  goTo: (t: any) => void;
  onChanged: () => void;
}) {
  const [metrics, setMetrics] = useState<any>(null);
  const [scenarios, setScenarios] = useState<any[]>([]);
  const [selected, setSelected] = useState("S2-indirect-injection");
  const [result, setResult] = useState<any>(null);
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    api.metrics().then(setMetrics).catch(() => setMetrics(null));
  }, [refreshKey]);
  useEffect(() => {
    api.scenarios().then((d) => setScenarios(d.scenarios)).catch(() => setScenarios([]));
  }, []);

  const scenario = scenarios.find((s) => s.id === selected);

  async function run(which: "gated" | "both") {
    setBusy(which);
    try {
      const res = await api.runScenario(selected);
      if (which === "gated" && res.baseline) {
        // Hide baseline panel when the judge asked only for the gated run.
        setResult({ ...res, baseline: undefined });
      } else {
        setResult(res);
      }
      onChanged();
    } finally {
      setBusy(null);
    }
  }

  const m = metrics;
  return (
    <div className="space-y-5">
      {/* Top strip */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label="Demo Status" value={<span className="text-base">Lab Data</span>} hint="Synthetic, local only" />
        <Stat label="Runs" value={m ? m.runs : <Spinner />} />
        <Stat label="Denied Actions" value={m ? m.denied_actions : "—"} tone="deny" />
        <Stat
          label="Pending Approvals"
          value={m ? m.pending_approvals : "—"}
          tone="approve"
        />
        <Stat
          label="Audit Integrity"
          value={m ? (m.audit_integrity.valid ? "Verified" : "BROKEN") : "—"}
          tone={m?.audit_integrity?.valid ? "allow" : "deny"}
          hint={m ? `${m.audit_integrity.checked} events chained` : ""}
        />
      </div>

      {/* Headline demo controller */}
      <div className="card p-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <FileWarning className="text-approve-ink" size={18} />
            <h2 className="text-sm font-semibold text-slate-100">Live demonstration</h2>
          </div>
          <select
            value={selected}
            onChange={(e) => {
              setSelected(e.target.value);
              setResult(null);
            }}
            className="rounded-lg border border-navy-700 bg-navy-900 px-3 py-2 text-sm text-slate-100 outline-none focus:border-allow/50"
          >
            {scenarios.map((s) => (
              <option key={s.id} value={s.id}>
                {s.id} · {s.title}
              </option>
            ))}
          </select>
          <div className="ml-auto flex gap-2">
            <button className="btn-ghost" disabled={!!busy} onClick={() => run("both")}>
              {busy === "both" ? <Spinner /> : <FlaskConical size={14} />} Run controlled baseline
            </button>
            <button className="btn-primary" disabled={!!busy} onClick={() => run("gated")}>
              {busy === "gated" ? <Spinner /> : <ShieldCheck size={14} />} Run with AMAN Gate
            </button>
          </div>
        </div>
        {scenario && (
          <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-slate-400">
            <Pill>{scenario.category}</Pill>
            <span>{scenario.description}</span>
            <span className="ml-auto flex items-center gap-1 text-slate-500">
              expected <ArrowRight size={12} /> {scenario.expectation}
            </span>
          </div>
        )}
      </div>

      {result ? (
        <SplitRun result={result} />
      ) : (
        <div className="card flex flex-col items-center justify-center gap-2 p-10 text-center">
          <ShieldCheck className="text-allow-ink/60" size={32} />
          <p className="text-sm text-slate-300">
            Pick a scenario and run it. The left panel shows what the AI assistant tries to do; the right
            panel shows AMAN Gate&apos;s independent allow / deny / approval decisions.
          </p>
          <p className="text-xs text-slate-500">
            Default scenario S2 hides an instruction inside a supplier quote that tells the assistant to
            open the restricted budget and email it out.
          </p>
          <button className="btn-ghost mt-2" onClick={() => goTo("replay")}>
            <PlayCircle size={14} /> Open full Scenario Replay lab
          </button>
        </div>
      )}

      {m && (
        <div className="grid gap-3 md:grid-cols-3">
          <Stat
            label="Gateway decision latency p50"
            value={m.decision_latency_ms.p50 != null ? `${m.decision_latency_ms.p50} ms` : "—"}
            hint="Deterministic policy only"
          />
          <Stat
            label="Gateway decision latency p95"
            value={m.decision_latency_ms.p95 != null ? `${m.decision_latency_ms.p95} ms` : "—"}
          />
          <Stat label="Local simulator sends" value={m.gated_outbox_sends} hint="university.test only" />
        </div>
      )}
    </div>
  );
}
