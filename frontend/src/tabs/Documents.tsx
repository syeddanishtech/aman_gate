import { useEffect, useState } from "react";
import { FileLock2, Unlock, Lock, AlertTriangle, ShieldCheck } from "lucide-react";
import { api, type User } from "../api";
import { Card, Pill, Spinner, DecisionBadge } from "../ui";

export default function Documents({
  user,
  refreshKey,
  onChanged,
}: {
  user: User;
  refreshKey: number;
  onChanged: () => void;
}) {
  const [docs, setDocs] = useState<any[]>([]);
  const [open, setOpen] = useState<any>(null);
  const [denial, setDenial] = useState<any>(null);
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    api.documents().then((d) => setDocs(d.documents));
    setOpen(null);
    setDenial(null);
  }, [refreshKey]);

  async function openDoc(id: string) {
    setBusy(id);
    setOpen(null);
    setDenial(null);
    try {
      const res = await api.readDocument(id);
      setOpen(res);
    } catch (e: any) {
      setDenial({ id, ...e.detail });
    } finally {
      setBusy(null);
      onChanged();
    }
  }

  return (
    <div className="grid gap-4 lg:grid-cols-[1fr_1fr]">
      <Card
        title="Document registry"
        subtitle={`Server-side ACL for ${user.role.replace(/_/g, " ")}. 'Readable' reflects the real per-user grant, not a UI toggle.`}
      >
        <div className="space-y-2">
          {docs.length === 0 && <Spinner />}
          {docs.map((d) => (
            <div key={d.document_id} className="rounded-lg border border-navy-700 bg-navy-900/50 p-3">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <FileLock2 size={15} className="text-slate-500" />
                  <span className="mono text-sm font-semibold text-slate-100">{d.document_id}</span>
                  {d.readable ? (
                    <Pill tone="allow">
                      <Unlock size={11} /> readable
                    </Pill>
                  ) : (
                    <Pill tone="deny">
                      <Lock size={11} /> {d.acl_reason}
                    </Pill>
                  )}
                </div>
                <button
                  className="btn-ghost px-2.5 py-1 text-xs"
                  disabled={busy === d.document_id}
                  onClick={() => openDoc(d.document_id)}
                >
                  {busy === d.document_id ? <Spinner /> : "Open via gateway"}
                </button>
              </div>
              <div className="mt-1 text-xs text-slate-400">{d.title}</div>
              <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-[11px]">
                <Pill>{d.doc_type}</Pill>
                <Pill tone={d.classification === "restricted" ? "deny" : "default"}>{d.classification}</Pill>
                <span
                  className={`mono ${
                    d.trust_label === "untrusted_external" ? "text-approve" : "text-slate-500"
                  }`}
                >
                  {d.trust_label}
                </span>
                {d.lab_fixture && <span className="text-slate-600">· fixture</span>}
                <span className="mono ml-auto text-slate-600">sha {d.sha256.slice(0, 10)}…</span>
              </div>
            </div>
          ))}
        </div>
      </Card>

      <Card title="Gateway retrieval result" subtitle="Reads go through the same ACL path as tool calls.">
        {denial && (
          <div className="rounded-lg border border-deny/40 bg-deny/10 p-4">
            <div className="flex items-center gap-2">
              <AlertTriangle className="text-deny" size={16} />
              <DecisionBadge decision="DENY" />
              <span className="mono ml-auto text-[11px] text-slate-500">{denial.id}</span>
            </div>
            <p className="mt-2 text-sm text-slate-200">{denial.message}</p>
            <div className="mono mt-2 flex flex-wrap gap-1.5 text-[11px]">
              <span className="rounded bg-navy-800 px-1.5 py-0.5 text-slate-400">{denial.policy_id}</span>
              <span className="rounded bg-navy-800 px-1.5 py-0.5 text-deny">{denial.code}</span>
            </div>
            <p className="mono mt-2 text-[10px] text-slate-600">event {denial.event_id}</p>
          </div>
        )}
        {open && (
          <div>
            <div className="flex items-center gap-2">
              <ShieldCheck className="text-allow" size={16} />
              <DecisionBadge decision="ALLOW" />
              <span className="mono ml-auto text-[11px] text-slate-500">{open.document.document_id}</span>
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[11px]">
              <Pill>{open.document.classification}</Pill>
              <span className="mono text-approve">{open.document.trust_label}</span>
              <span className="text-slate-500">
                advisory risk: <b className={riskColor(open.risk.band)}>{open.risk.band}</b> (
                {open.risk.combined_score})
              </span>
            </div>
            {open.risk.heuristic.signals.length > 0 && (
              <div className="mt-2 rounded-lg border border-approve/30 bg-approve/5 p-2 text-[11px] text-slate-300">
                <b className="text-approve">Advisory signals (non-enforcing):</b>{" "}
                {open.risk.heuristic.signals.map((s: any) => s.signal).join(", ")}
                {open.risk.heuristic.evasion_markers.length > 0 && (
                  <> · evasion: {open.risk.heuristic.evasion_markers.join(", ")}</>
                )}
              </div>
            )}
            <pre className="mono mt-2 max-h-[420px] overflow-auto whitespace-pre-wrap rounded-lg border border-navy-700 bg-navy-950 p-3 text-[11px] leading-relaxed text-slate-300">
              {open.document.content}
            </pre>
          </div>
        )}
        {!open && !denial && (
          <p className="p-6 text-center text-sm text-slate-500">
            Open a document to see the gateway&apos;s allow/deny decision and advisory risk signals.
            Restricted content never appears in logs or audit records.
          </p>
        )}
      </Card>
    </div>
  );
}

function riskColor(band: string) {
  return band === "high" ? "text-deny" : band === "medium" ? "text-approve" : "text-slate-300";
}
