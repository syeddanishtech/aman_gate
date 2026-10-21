import { AlertTriangle, ArrowRight, BadgeCheck, FileText, Lock, RotateCcw, Unlock } from "lucide-react";
import type { User } from "../api";
import { usePipeline } from "../pipeline";
import { CheckList, PageHeader, PrimaryButton, SourceTag, SubTabs } from "../components/common";
import { DecisionStrip, JourneyRail } from "../components/Journey";
import { SafeCopyCard } from "../components/SafeCopyCard";
import { verifySafeCopy, titleCase } from "../lib/contract";
import { Card, Pill } from "../ui";
import Documents from "./Documents";
import type { NavTarget } from "../nav";

type Sub = "shield" | "registry";

function sensitivityTone(s: string): string {
  return s === "restricted" ? "deny" : s === "confidential" ? "approve" : s === "public" ? "allow" : "default";
}

export default function ProtectDocuments({
  user,
  refreshKey,
  onChanged,
  go,
  sub,
  setSub,
}: {
  user: User;
  refreshKey: number;
  onChanged: () => void;
  go: (t: NavTarget) => void;
  sub: string | undefined;
  setSub: (s: string) => void;
}) {
  const active: Sub = sub === "registry" ? "registry" : "shield";
  return (
    <div>
      <PageHeader
        eyebrow="Privacy Shield"
        title="Protect Documents"
        subtitle="Find sensitive data, build a verified safe copy, and decide what an AI may see. The original never leaves this device."
      />
      <SubTabs
        label="Protect Documents views"
        value={active}
        onChange={setSub}
        tabs={[
          { id: "shield", label: "Privacy Shield" },
          { id: "registry", label: "Document registry & access" },
        ]}
      />
      {active === "shield" ? <Shield go={go} /> : <Documents user={user} refreshKey={refreshKey} onChanged={onChanged} />}
    </div>
  );
}

function Shield({ go }: { go: (t: NavTarget) => void }) {
  const p = usePipeline();
  const onPrimary = () => (p.primary.id === "result" ? go({ section: "assurance" }) : void p.runPrimary());
  const els = p.analysis?.data.disclosure.elements ?? [];
  const bySens = els.reduce<Record<string, number>>((m, e) => ((m[e.sensitivity] = (m[e.sensitivity] ?? 0) + 1), m), {});
  const byAction = els.reduce<Record<string, number>>((m, e) => ((m[e.action] = (m[e.action] ?? 0) + 1), m), {});

  return (
    <div className="space-y-6">
      <div className="card px-6 pb-4 pt-5">
        <JourneyRail steps={p.steps} />
        <div className="mt-4 flex flex-wrap items-center justify-center gap-3 border-t border-navy-700 pt-4">
          <PrimaryButton primary={p.primary} onClick={onPrimary} busy={!!p.busy} />
          {p.analysis && (
            <button className="btn-ghost" onClick={p.reset}>
              <RotateCcw size={14} aria-hidden /> Start over
            </button>
          )}
        </div>
      </div>

      {p.error && (
        <div role="alert" className="flex items-start gap-2 rounded-lg border border-deny/40 bg-deny/10 px-3 py-2.5 text-sm text-deny-ink">
          <AlertTriangle size={16} className="mt-0.5 shrink-0" aria-hidden /> {p.error}
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        {/* 1 — Upload / choose */}
        <Card
          title="1 · Upload — choose a document"
          subtitle="Documents come from the real registry and its per-user access control. A file-upload endpoint is not part of the provisional contract yet."
        >
          <div role="radiogroup" aria-label="Documents" className="max-h-[360px] space-y-2 overflow-auto pr-1">
            {!p.docs && <p className="text-sm text-slate-500">Loading registry…</p>}
            {(p.docs ?? []).map((d) => {
              const sel = d.document_id === p.documentId;
              return (
                <button
                  key={d.document_id}
                  role="radio"
                  aria-checked={sel}
                  disabled={!!p.busy}
                  onClick={() => p.selectDocument(d.document_id)}
                  className={`flex w-full items-start gap-3 rounded-lg border-2 px-3 py-2.5 text-left transition-colors ${
                    sel ? "border-allow bg-allow/5" : "border-navy-700 bg-white hover:border-navy-600"
                  }`}
                >
                  <FileText size={18} className={`mt-0.5 shrink-0 ${sel ? "text-allow-ink" : "text-slate-400"}`} aria-hidden />
                  <span className="min-w-0 flex-1">
                    <span className="flex flex-wrap items-center gap-2">
                      <span className="mono text-sm font-semibold text-slate-100">{d.document_id}</span>
                      <Pill tone={d.classification === "restricted" ? "deny" : "default"}>{d.classification}</Pill>
                      {d.readable ? (
                        <Pill tone="allow">
                          <Unlock size={11} aria-hidden /> readable
                        </Pill>
                      ) : (
                        <Pill tone="deny">
                          <Lock size={11} aria-hidden /> no access
                        </Pill>
                      )}
                      {sel && <span className="text-[11px] font-bold uppercase text-allow-ink">Selected</span>}
                    </span>
                    <span className="mt-0.5 block text-xs text-slate-400">{d.title}</span>
                  </span>
                </button>
              );
            })}
          </div>
        </Card>

        {/* 2 — Detect */}
        <Card
          title="2 · Detect sensitive data"
          subtitle="Disclosure elements the analysis found, with the action applied to each."
          right={p.analysis ? <SourceTag source={p.analysis.source} /> : undefined}
        >
          {!p.analysis ? (
            <p className="rounded-lg border border-dashed border-navy-600 p-6 text-center text-sm text-slate-500">
              Nothing analyzed yet. Choose a document and press <b className="text-slate-300">Analyze Document</b>.
            </p>
          ) : (
            <>
              <div className="mb-3 flex flex-wrap items-center gap-2">
                <span className="text-2xl font-bold tabular-nums text-slate-100">{p.analysis.data.disclosure.findings_count}</span>
                <span className="text-sm text-slate-400">finding(s)</span>
                {Object.entries(bySens).map(([k, v]) => (
                  <Pill key={k} tone={sensitivityTone(k)}>
                    {v} {k}
                  </Pill>
                ))}
                {Object.entries(byAction).map(([k, v]) => (
                  <Pill key={k}>
                    {v} {k}
                  </Pill>
                ))}
              </div>
              <div className="max-h-[300px] overflow-auto">
                <table className="w-full text-left text-xs">
                  <caption className="sr-only">Disclosure elements</caption>
                  <thead className="sticky top-0 bg-white text-[10px] uppercase tracking-wide text-slate-500">
                    <tr className="border-b border-navy-700">
                      <th scope="col" className="py-2 pr-2">ID</th>
                      <th scope="col" className="py-2 pr-2">Type</th>
                      <th scope="col" className="py-2 pr-2">Page</th>
                      <th scope="col" className="py-2 pr-2">Sensitivity</th>
                      <th scope="col" className="py-2 pr-2">Source trust</th>
                      <th scope="col" className="py-2">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {els.map((e) => (
                      <tr key={e.id} className="border-b border-navy-800">
                        <td className="mono py-1.5 pr-2 text-slate-500">{e.id}</td>
                        <td className="py-1.5 pr-2 font-medium text-slate-100">{titleCase(e.type)}</td>
                        <td className="py-1.5 pr-2 tabular-nums text-slate-400">{e.page}</td>
                        <td className="py-1.5 pr-2">
                          <Pill tone={sensitivityTone(e.sensitivity)}>{e.sensitivity}</Pill>
                        </td>
                        <td className="mono py-1.5 pr-2 text-slate-400">{e.source_trust}</td>
                        <td className="py-1.5">
                          <Pill>{e.action}</Pill>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {els.length === 0 && <p className="p-4 text-center text-sm text-slate-500">No disclosure elements reported.</p>}
              </div>
            </>
          )}
        </Card>
      </div>

      {/* 3 — Sanitize & verify */}
      <section aria-label="Sanitize and verify" className="space-y-4">
        <h2 className="text-sm font-semibold text-slate-100">3 · Sanitize & verify — original vs safe copy</h2>
        <DecisionStrip decision={p.decision} />
        <SafeCopyCard
          artifact={p.view.artifact}
          label={p.view.label}
          source={p.view.source}
          isSample={p.view.isSample}
          decision={p.decision}
          blockedReason={p.blockedReason}
        />
        {p.artifact && (
          <Card
            title="Verification of the safe copy"
            subtitle="A UI cross-check of the returned preview. The backend's independent second-extractor verification is not part of the provisional contract."
            right={<SourceTag source={p.artifact.source} />}
          >
            {p.reviewed ? (
              <CheckList checks={verifySafeCopy(p.artifact.data)} />
            ) : (
              <p className="text-sm text-slate-500">
                Press <b className="text-slate-300">Review Safe Copy</b> to run the cross-check and confirm you have read the safe copy.
              </p>
            )}
          </Card>
        )}
      </section>

      {/* 4 — Approve */}
      <Card
        title="4 · Approve AI access"
        subtitle="A human decides whether this safe copy may go to the AI provider. Only the safe copy is ever sent."
        right={<span className="tag border border-navy-600 bg-navy-800 text-slate-400">UI-only gate · the send is the audited action</span>}
      >
        <div className="flex flex-wrap items-center gap-3">
          {p.decision === "APPROVED" ? (
            <>
              <span className="tag border border-allow/40 bg-allow/10 text-allow-ink">
                <BadgeCheck size={12} aria-hidden /> Sharing approved
              </span>
              <button className="btn-primary" onClick={() => go({ section: "bridge" })}>
                Continue to Safe Cloud Bridge <ArrowRight size={15} aria-hidden />
              </button>
            </>
          ) : (
            <>
              <PrimaryButton primary={p.primary} onClick={onPrimary} busy={!!p.busy} size="md" />
              <span className="text-xs text-slate-500">
                {p.decision === "BLOCKED"
                  ? "Blocked — approval is not possible."
                  : !p.analysis
                  ? "Analyze a document first."
                  : !p.reviewed
                  ? "Review the safe copy first."
                  : "Ready to approve."}
              </span>
            </>
          )}
        </div>
        <p className="mt-3 text-[11px] text-slate-500">
          Honest limitation: this approval is held in the browser session only — the provisional contract has no approval endpoint, so it is
          not written to the AMAN 1.0 two-person approval queue or the audit chain.
        </p>
      </Card>
    </div>
  );
}
