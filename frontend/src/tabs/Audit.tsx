import { useEffect, useState } from "react";
import { ShieldCheck, ShieldAlert, Download, FileBarChart, Link2 } from "lucide-react";
import { api } from "../api";
import { Card, Pill, Spinner, DecisionBadge } from "../ui";

const FILTERS = ["ALL", "ALLOW", "DENY", "NEEDS_APPROVAL"];

export default function Audit({ refreshKey }: { refreshKey: number }) {
  const [events, setEvents] = useState<any[]>([]);
  const [verify, setVerify] = useState<any>(null);
  const [filter, setFilter] = useState("ALL");
  const [mode, setMode] = useState<string>("gated");
  const [evidence, setEvidence] = useState<any>(null);
  const [ml, setMl] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  function load() {
    setLoading(true);
    const params: Record<string, string> = { limit: "150" };
    if (filter !== "ALL") params.decision = filter;
    if (mode !== "all") params.mode = mode;
    Promise.all([api.auditEvents(params), api.auditVerify()]).then(([e, v]) => {
      setEvents(e.events);
      setVerify(v);
      setLoading(false);
    });
  }
  useEffect(load, [refreshKey, filter, mode]);
  useEffect(() => {
    api.mlMetrics().then(setMl).catch(() => setMl(null));
  }, [refreshKey]);

  function download(obj: any, name: string) {
    const blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function exportChain() {
    const data = await api.auditExport();
    download(data, "aman_gate_audit_chain.json");
  }
  async function genEvidence() {
    const rep = await api.evidence();
    setEvidence(rep);
    download(rep, "aman_gate_evidence_report.json");
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-3">
        <Card
          title="Audit chain integrity"
          subtitle="HMAC-SHA256 chain over canonicalized records."
          className="lg:col-span-1"
        >
          {verify ? (
            <div
              className={`rounded-lg border p-4 ${
                verify.valid ? "border-allow/40 bg-allow/5" : "border-deny/40 bg-deny/10"
              }`}
            >
              <div className="flex items-center gap-2">
                {verify.valid ? (
                  <ShieldCheck className="text-allow-ink" />
                ) : (
                  <ShieldAlert className="text-deny-ink" />
                )}
                <span className={`text-lg font-bold ${verify.valid ? "text-allow-ink" : "text-deny-ink"}`}>
                  {verify.valid ? "VERIFIED" : "TAMPER DETECTED"}
                </span>
              </div>
              <p className="mt-1 text-xs text-slate-400">{verify.checked} events chained.</p>
              {verify.valid ? (
                <p className="mono mt-2 break-all text-[10px] text-slate-500">
                  <Link2 size={10} className="inline" /> head {verify.head_hmac?.slice(0, 32)}…
                </p>
              ) : (
                <p className="mt-2 text-[11px] text-deny-ink">
                  First bad seq {verify.first_bad_seq}: {verify.problems?.join(", ")}
                </p>
              )}
              <p className="mt-2 text-[10px] text-slate-600">{verify.scope_note}</p>
            </div>
          ) : (
            <Spinner />
          )}
          <div className="mt-3 flex flex-wrap gap-2">
            <button className="btn-ghost text-xs" onClick={exportChain}>
              <Download size={13} /> Export chain (JSON)
            </button>
            <button className="btn-primary text-xs" onClick={genEvidence}>
              <FileBarChart size={13} /> Evidence report
            </button>
          </div>
        </Card>

        <Card title="ML classifier (advisory)" subtitle="Disjoint holdout metrics; never changes a decision." className="lg:col-span-2">
          {ml?.available ? (
            <MlMetrics ml={ml} />
          ) : (
            <p className="text-xs text-slate-500">
              Classifier artifact not loaded. Heuristic signals still operate. Train with{" "}
              <span className="mono">python -m scripts.train_model</span>.
            </p>
          )}
        </Card>
      </div>

      {evidence && <EvidenceCard ev={evidence} />}

      <Card
        title="Event timeline"
        subtitle="Every row is a persisted backend decision event. Protected content is never stored here."
        right={
          <div className="flex flex-wrap gap-1.5">
            {FILTERS.map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`tag border ${
                  filter === f ? "border-allow/40 bg-allow/10 text-allow-ink" : "border-navy-600 bg-navy-800 text-slate-400"
                }`}
              >
                {f.replace(/_/g, " ")}
              </button>
            ))}
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value)}
              className="rounded-md border border-navy-600 bg-navy-800 px-2 py-0.5 text-[11px] text-slate-300"
            >
              <option value="gated">gated</option>
              <option value="baseline">baseline</option>
              <option value="system">system</option>
              <option value="all">all modes</option>
            </select>
          </div>
        }
      >
        {loading ? (
          <div className="flex justify-center p-6">
            <Spinner />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-[10px] uppercase tracking-wide text-slate-500">
                <tr className="border-b border-navy-700">
                  <th className="py-2 pr-3">#</th>
                  <th className="py-2 pr-3">Time</th>
                  <th className="py-2 pr-3">Decision</th>
                  <th className="py-2 pr-3">Event</th>
                  <th className="py-2 pr-3">Actor</th>
                  <th className="py-2 pr-3">Tool</th>
                  <th className="py-2 pr-3">Resources</th>
                  <th className="py-2 pr-3">Reasons</th>
                  <th className="py-2 pr-3">Risk</th>
                  <th className="py-2">ms</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.event_id} className="border-b border-navy-800 align-top">
                    <td className="py-1.5 pr-3 mono text-slate-600">{e.seq}</td>
                    <td className="py-1.5 pr-3 mono text-slate-500">
                      {new Date(e.ts).toLocaleTimeString()}
                    </td>
                    <td className="py-1.5 pr-3">
                      <DecisionBadge decision={e.decision} />
                    </td>
                    <td className="py-1.5 pr-3 mono text-slate-300">{e.event_type}</td>
                    <td className="py-1.5 pr-3 text-slate-400">
                      {e.actor_user_id}
                      <div className="text-[10px] text-slate-600">{e.actor_role}</div>
                    </td>
                    <td className="py-1.5 pr-3 mono text-slate-400">{e.tool || "—"}</td>
                    <td className="py-1.5 pr-3 mono text-slate-500">{e.resource_ids?.join(", ") || "—"}</td>
                    <td className="py-1.5 pr-3">
                      <div className="flex flex-wrap gap-1">
                        {e.reason_codes?.map((c: string) => (
                          <span key={c} className="mono rounded bg-navy-800 px-1 py-0.5 text-[10px] text-slate-400">
                            {c}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-1.5 pr-3">
                      {e.risk?.band ? <Pill tone={e.risk.band === "high" ? "deny" : e.risk.band === "medium" ? "approve" : "default"}>{e.risk.band}</Pill> : "—"}
                    </td>
                    <td className="py-1.5 mono text-slate-500">
                      {e.decision_latency_ms != null ? e.decision_latency_ms.toFixed(2) : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {events.length === 0 && <p className="p-4 text-center text-xs text-slate-500">No events match.</p>}
          </div>
        )}
      </Card>
    </div>
  );
}

function MlMetrics({ ml }: { ml: any }) {
  const o = ml.metrics?.holdout_overall;
  if (!o) return <p className="text-xs text-slate-500">No metrics.</p>;
  return (
    <div>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {[
          ["Precision", o.precision],
          ["Recall", o.recall],
          ["False-pos rate", o.false_positive_rate],
          ["F1", o.f1],
        ].map(([k, v]) => (
          <div key={k as string} className="rounded-lg border border-navy-700 bg-navy-900/50 px-3 py-2">
            <div className="text-[10px] uppercase tracking-wide text-slate-500">{k as string}</div>
            <div className="text-lg font-bold tabular-nums text-slate-100">{v as number}</div>
          </div>
        ))}
      </div>
      <p className="mt-2 text-[11px] text-slate-500">
        Holdout n={ml.metrics.split?.holdout} · leakage-free={String(ml.metrics.leakage_check?.ok)} ·{" "}
        {ml.model_version}
      </p>
      <p className="mt-1 text-[10px] text-slate-600">{ml.metrics.note}</p>
    </div>
  );
}

function EvidenceCard({ ev }: { ev: any }) {
  return (
    <Card title={ev.title} subtitle={`Generated ${new Date(ev.generated_at).toLocaleString()} · downloaded as JSON`}>
      <div className="grid gap-3 md:grid-cols-4">
        <Metric label="Attack-block %" value={ev.attack_block.attempt_block_pct} suffix="%" tone="allow"
          hint={`${ev.attack_block.blocked}/${ev.attack_block.attempts} attacks`} />
        <Metric label="False allows" value={ev.attack_block.false_allows} tone={ev.attack_block.false_allows ? "deny" : "allow"} />
        <Metric label="Legit success %" value={ev.legitimate_requests.success_pct} suffix="%" tone="allow"
          hint={`${ev.legitimate_requests.succeeded}/${ev.legitimate_requests.requests}`} />
        <Metric label="False blocks" value={ev.false_blocks.legitimate_actions_denied} tone={ev.false_blocks.legitimate_actions_denied ? "deny" : "allow"} />
      </div>
      <div className="mt-3 grid gap-3 md:grid-cols-3">
        <Metric label="Latency p50" value={ev.latency_ms.p50} suffix=" ms" />
        <Metric label="Latency p95" value={ev.latency_ms.p95} suffix=" ms" />
        <Metric label="Decisions measured" value={ev.latency_ms.count} />
      </div>
      <p className="mt-3 text-[11px] text-slate-500">
        Evaluation machine: {ev.evaluation_machine.platform} · Python {ev.evaluation_machine.python} ·{" "}
        {ev.evaluation_machine.cpu_count} CPUs
      </p>
      <ul className="mt-2 list-disc space-y-0.5 pl-4 text-[10px] text-slate-600">
        {ev.caveats.map((c: string) => (
          <li key={c}>{c}</li>
        ))}
      </ul>
    </Card>
  );
}

function Metric({ label, value, suffix = "", tone = "default", hint }: any) {
  const c = tone === "deny" ? "text-deny-ink" : tone === "allow" ? "text-allow-ink" : "text-slate-100";
  return (
    <div className="rounded-lg border border-navy-700 bg-navy-900/50 px-3 py-2" title={hint}>
      <div className="text-[10px] uppercase tracking-wide text-slate-500">{label}</div>
      <div className={`text-xl font-bold tabular-nums ${c}`}>
        {value ?? "—"}
        {value != null ? suffix : ""}
      </div>
    </div>
  );
}
