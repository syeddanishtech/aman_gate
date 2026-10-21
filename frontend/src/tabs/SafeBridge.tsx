import { AlertTriangle, ArrowRight, Cloud, FlaskConical, HardDrive, Play, ShieldCheck, Undo2 } from "lucide-react";
import type { ProviderMode } from "../api";
import { usePipeline } from "../pipeline";
import { CheckList, PageHeader, SourceTag } from "../components/common";
import { verifySafeCopy, type Check } from "../lib/contract";
import { Card, Pill, Spinner } from "../ui";
import type { NavTarget } from "../nav";

const MODES: { id: ProviderMode; title: string; desc: string; badge: string }[] = [
  { id: "LOCAL_SIMULATOR", title: "Local simulator", desc: "Default. A canned assistant on this machine — zero external calls.", badge: "Default" },
  { id: "LOCAL_LLM", title: "Local LLM", desc: "Optional on-device model. Not configured in this build.", badge: "Optional" },
  { id: "REAL_CLOUD", title: "Real cloud provider", desc: "Opt-in only. Egress is default-deny, so expect the gate to refuse this.", badge: "Opt-in" },
];

export default function SafeBridge({ go }: { go: (t: NavTarget) => void }) {
  const p = usePipeline();
  const artifactId = p.analysis?.data.safe_artifact_id;
  const blocked = p.decision === "BLOCKED";

  const gate: Check[] = [
    {
      label: "A safe copy exists and was not blocked",
      ok: !!p.artifact && !blocked,
      detail: p.artifact ? (blocked ? "policy blocked this document" : `artifact ${artifactId}`) : "analyze a document first",
    },
    { label: "A human approved sharing", ok: p.approved, detail: p.approved ? "approved in this session" : "not approved yet" },
    {
      label: "Outbound payload is the safe copy only",
      ok: p.artifact && !blocked ? true : null,
      detail: p.artifact && !blocked ? `the original (${p.artifact.data.original_preview.length} chars) stays local` : "no payload yet",
    },
    p.artifact && !blocked
      ? { ...verifySafeCopy(p.artifact.data)[0], label: "Payload re-scan: no original sensitive value present" }
      : { label: "Payload re-scan: no original sensitive value present", ok: null, detail: "no payload yet" },
    {
      label: "Provider is allowed to receive data",
      ok: p.providerMode === "LOCAL_SIMULATOR" ? true : null,
      detail: p.providerMode === "LOCAL_SIMULATOR" ? "local simulator — no network" : "default-deny egress: the gate decides, the UI cannot",
    },
  ];

  const canSend = !!artifactId && p.approved && !blocked && !p.busy;

  return (
    <div>
      <PageHeader
        eyebrow="Workstream B"
        title="Safe Cloud Bridge"
        subtitle="Only the approved safe copy can reach an AI. Egress is default-deny and the default provider is a local simulator."
        right={<span className="tag border border-approve/60 bg-approve/10 text-approve-ink"><FlaskConical size={12} aria-hidden /> Local simulator — not a real AI</span>}
      />

      {p.error && (
        <div role="alert" className="mb-4 flex items-start gap-2 rounded-lg border border-deny/40 bg-deny/10 px-3 py-2.5 text-sm text-deny-ink">
          <AlertTriangle size={16} className="mt-0.5 shrink-0" aria-hidden /> {p.error}
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <div className="space-y-6">
          <Card title="Provider mode" subtitle="Where the safe copy may be sent.">
            <div role="radiogroup" aria-label="Provider mode" className="space-y-2">
              {MODES.map((m) => {
                const sel = p.providerMode === m.id;
                return (
                  <button
                    key={m.id}
                    role="radio"
                    aria-checked={sel}
                    disabled={!!p.busy}
                    onClick={() => p.setProviderMode(m.id)}
                    className={`flex w-full items-start gap-3 rounded-lg border-2 px-3 py-2.5 text-left transition-colors ${
                      sel ? "border-allow bg-allow/5" : "border-navy-700 bg-white hover:border-navy-600"
                    }`}
                  >
                    {m.id === "LOCAL_SIMULATOR" ? (
                      <HardDrive size={18} className="mt-0.5 shrink-0 text-allow-ink" aria-hidden />
                    ) : (
                      <Cloud size={18} className="mt-0.5 shrink-0 text-slate-400" aria-hidden />
                    )}
                    <span className="min-w-0 flex-1">
                      <span className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-semibold text-slate-100">{m.title}</span>
                        <span className="mono text-[11px] text-slate-500">{m.id}</span>
                        <Pill tone={m.id === "LOCAL_SIMULATOR" ? "allow" : "default"}>{m.badge}</Pill>
                        {sel && <span className="text-[11px] font-bold uppercase text-allow-ink">Selected</span>}
                      </span>
                      <span className="mt-0.5 block text-xs text-slate-400">{m.desc}</span>
                    </span>
                  </button>
                );
              })}
            </div>
          </Card>

          <Card title="Egress gate" subtitle="What must be true before anything leaves. Evaluated from the current session state.">
            <CheckList checks={gate} />
            <p className="mt-3 text-[11px] text-slate-500">
              These rows are a UI view of the gate. The authoritative egress decision belongs to the bridge backend; if it refuses, the
              reasons appear next to the response.
            </p>
          </Card>
        </div>

        <div className="space-y-6">
          <Card
            title="Outbound payload"
            subtitle="Exactly what would be sent: the safe copy. Nothing else."
            right={p.artifact ? <SourceTag source={p.artifact.source} /> : undefined}
          >
            {p.artifact && !blocked ? (
              <pre
                tabIndex={0}
                aria-label="Outbound safe copy"
                className="mono max-h-[220px] overflow-auto whitespace-pre-wrap break-words rounded-lg border border-allow/30 bg-allow/5 p-3 text-[12px] leading-5 text-slate-200"
              >
                {p.artifact.data.safe_copy_preview}
              </pre>
            ) : (
              <p className="rounded-lg border border-dashed border-navy-600 p-6 text-center text-sm text-slate-500">
                {blocked ? "Blocked — there is no payload to send." : "No safe copy yet. Analyze, review and approve a document first."}
              </p>
            )}
            <div className="mt-4 flex flex-wrap items-center gap-3">
              <button className="btn-primary px-5 py-2.5 text-[15px]" disabled={!canSend} onClick={() => void p.runAI()}>
                {p.busy === "run" ? <Spinner /> : <Play size={17} aria-hidden />} Run AI (Simulator)
              </button>
              {!p.approved && (
                <button className="btn-ghost" onClick={() => go({ section: "protect" })}>
                  <ShieldCheck size={15} aria-hidden /> Go to Protect Documents
                </button>
              )}
              {p.bridge && (
                <>
                  <button className="btn-ghost" onClick={() => go({ section: "assurance" })}>
                    Check AI Result <ArrowRight size={15} aria-hidden />
                  </button>
                  <button className="btn-ghost" onClick={() => void p.runAI()} disabled={!canSend}>
                    <Undo2 size={14} aria-hidden /> Re-run
                  </button>
                </>
              )}
            </div>
          </Card>

          <Card
            title="AI response"
            subtitle="Returned by the bridge for the safe copy above."
            right={p.bridge ? <SourceTag source={p.bridge.source} /> : undefined}
          >
            {p.bridge ? (
              <div className="relative">
                <div className="mb-2 flex flex-wrap items-center gap-2">
                  <span className="tag border border-approve/60 bg-approve/10 text-approve-ink">
                    <FlaskConical size={11} aria-hidden /> {p.bridge.data.mode}
                  </span>
                  {p.bridge.data.watermark && <span className="tag border border-navy-600 bg-white text-slate-300">Simulation watermark on</span>}
                </div>
                {p.bridge.data.egress_blocked_reasons && p.bridge.data.egress_blocked_reasons.length > 0 && (
                  <div role="alert" className="mb-3 rounded-lg border border-deny/40 bg-deny/10 p-3 text-sm text-deny-ink">
                    <b>Egress blocked for {p.providerMode}</b> — the bridge fell back to the local simulator. Reasons:
                    <ul className="mono mt-1 list-disc pl-5 text-xs">
                      {p.bridge.data.egress_blocked_reasons.map((r) => (
                        <li key={r}>{r}</li>
                      ))}
                    </ul>
                  </div>
                )}
                <div className="relative overflow-hidden rounded-lg border border-approve/40 bg-approve/5">
                  <span
                    aria-hidden
                    className="pointer-events-none absolute inset-0 flex select-none items-center justify-center text-5xl font-black uppercase tracking-[0.2em] text-approve/15"
                    style={{ transform: "rotate(-14deg)" }}
                  >
                    Simulation
                  </span>
                  <pre
                    tabIndex={0}
                    aria-label="Simulated AI response"
                    className="relative max-h-[260px] overflow-auto whitespace-pre-wrap break-words p-3 text-[13px] leading-6 text-slate-200"
                    style={{ fontFamily: "inherit" }}
                  >
                    {p.bridge.data.response}
                  </pre>
                </div>
              </div>
            ) : (
              <p className="rounded-lg border border-dashed border-navy-600 p-6 text-center text-sm text-slate-500">
                {p.busy === "run" ? "Running…" : "No response yet. Approve sharing, then press Run AI (Simulator)."}
              </p>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}
