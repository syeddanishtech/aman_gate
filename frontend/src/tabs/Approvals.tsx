import { useEffect, useState } from "react";
import { Inbox, Send, FileText, Check, X, PlayCircle, Clock } from "lucide-react";
import { api, type User } from "../api";
import { Card, Pill, Spinner, DecisionBadge } from "../ui";

const ALLOWED_DESTS = ["finance-approvals@university.test", "procurement-records@university.test"];

export default function Approvals({
  user,
  refreshKey,
  onChanged,
}: {
  user: User;
  refreshKey: number;
  onChanged: () => void;
}) {
  const [approvals, setApprovals] = useState<any[]>([]);
  const [reports, setReports] = useState<any[]>([]);
  const [canDecide, setCanDecide] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [dest, setDest] = useState(ALLOWED_DESTS[0]);
  const [reportId, setReportId] = useState("");
  const [msg, setMsg] = useState<any>(null);

  function load() {
    api.approvals().then((d) => {
      setApprovals(d.approvals);
      setCanDecide(d.can_decide);
    });
    api.reports().then((d) => {
      setReports(d.reports);
      if (d.reports[0] && !reportId) setReportId(d.reports[0].report_id);
    });
  }
  useEffect(load, [refreshKey]);

  async function draft() {
    setBusy("draft");
    setMsg(null);
    try {
      const res = await api.invoke("draft_purchase_summary", { quote_ids: ["QUOTE-101", "QUOTE-103"] });
      if (res.output?.report_id) {
        setReportId(res.output.report_id);
        setMsg({ tone: "allow", text: `Drafted ${res.output.report_id} (classification internal).` });
      }
      load();
      onChanged();
    } finally {
      setBusy(null);
    }
  }

  async function requestSend() {
    setBusy("send");
    setMsg(null);
    try {
      const res = await api.invoke("send_report", { destination: dest, report_id: reportId });
      setMsg({
        tone: res.decision === "NEEDS_APPROVAL" ? "approve" : res.decision === "DENY" ? "deny" : "allow",
        text: `${res.decision}: ${res.explanation}`,
        decision: res.decision,
      });
      load();
      onChanged();
    } finally {
      setBusy(null);
    }
  }

  async function decide(id: string, approve: boolean) {
    setBusy(id + (approve ? "a" : "d"));
    try {
      await api.decideApproval(id, approve, approve ? "Approved via queue." : "Denied via queue.");
      load();
      onChanged();
    } catch (e: any) {
      setMsg({ tone: "deny", text: e?.detail?.message || e?.detail?.code || "Decision failed" });
    } finally {
      setBusy(null);
    }
  }

  async function execute(id: string) {
    setBusy(id + "x");
    try {
      const res = await api.executeApproval(id);
      setMsg({ tone: "allow", text: `Executed to local simulator (outbox #${res.outbox_id}).` });
      load();
      onChanged();
    } catch (e: any) {
      setMsg({ tone: "deny", text: e?.detail?.message || e?.detail?.code || "Execution failed" });
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="grid gap-4 lg:grid-cols-[380px_1fr]">
      <Card title="Request a report send" subtitle="draft_purchase_summary → send_report (two-person approval).">
        {(user.role === "procurement_officer" || user.role === "finance_manager") ? (
          <div className="space-y-3">
            <button className="btn-ghost w-full" disabled={busy === "draft"} onClick={draft}>
              {busy === "draft" ? <Spinner /> : <FileText size={14} />} Draft summary (QUOTE-101 + QUOTE-103)
            </button>
            <div>
              <label className="mb-1 block text-[11px] uppercase tracking-wide text-slate-500">Report</label>
              <select
                value={reportId}
                onChange={(e) => setReportId(e.target.value)}
                className="w-full rounded-lg border border-navy-700 bg-navy-900 px-3 py-2 text-sm text-slate-100 outline-none focus:border-allow/50"
              >
                {reports.map((r) => (
                  <option key={r.report_id} value={r.report_id}>
                    {r.report_id}
                  </option>
                ))}
                {reports.length === 0 && <option value="">(draft one first)</option>}
              </select>
            </div>
            <div>
              <label className="mb-1 block text-[11px] uppercase tracking-wide text-slate-500">
                Destination
              </label>
              <select
                value={dest}
                onChange={(e) => setDest(e.target.value)}
                className="w-full rounded-lg border border-navy-700 bg-navy-900 px-3 py-2 text-sm text-slate-100 outline-none focus:border-allow/50"
              >
                {ALLOWED_DESTS.map((d) => (
                  <option key={d} value={d}>
                    {d}
                  </option>
                ))}
                <option value="bids-review@example.test">bids-review@example.test (unapproved)</option>
              </select>
            </div>
            <button className="btn-primary w-full" disabled={busy === "send" || !reportId} onClick={requestSend}>
              {busy === "send" ? <Spinner /> : <Send size={14} />} Submit send request
            </button>
            {msg && (
              <div
                className={`rounded-lg border p-2.5 text-[11px] ${
                  msg.tone === "deny"
                    ? "border-deny/40 bg-deny/10 text-deny"
                    : msg.tone === "approve"
                    ? "border-approve/40 bg-approve/10 text-approve"
                    : "border-allow/40 bg-allow/10 text-allow"
                }`}
              >
                {msg.text}
              </div>
            )}
          </div>
        ) : (
          <p className="text-xs text-slate-500">
            Your role ({user.role.replace(/_/g, " ")}) cannot request sends. Finance managers decide them.
          </p>
        )}
      </Card>

      <Card
        title="Approval queue"
        subtitle={
          canDecide
            ? "You are a finance manager and may approve/deny (but never your own request)."
            : "Finance managers approve or deny these requests."
        }
        right={<Pill><Inbox size={12} /> {approvals.filter((a) => a.status === "pending").length} pending</Pill>}
      >
        <div className="space-y-2">
          {approvals.length === 0 && <p className="text-xs text-slate-500">No approval requests yet.</p>}
          {approvals.map((a) => (
            <div key={a.approval_id} className="rounded-lg border border-navy-700 bg-navy-900/50 p-3">
              <div className="flex items-center justify-between gap-2">
                <span className="mono text-xs font-semibold text-slate-100">{a.approval_id}</span>
                <StatusBadge status={a.status} />
              </div>
              <div className="mono mt-1.5 text-[11px] text-slate-400">
                {a.tool} → {a.args.destination} · {a.args.report_id}
              </div>
              <div className="mt-1 flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
                <span>requester {a.requester_user_id}</span>
                <span className="flex items-center gap-1">
                  <Clock size={11} /> expires {new Date(a.expires_at).toLocaleTimeString()}
                </span>
                {a.decided_by_user_id && <span>decided by {a.decided_by_user_id}</span>}
              </div>
              <div className="mt-2 flex flex-wrap gap-2">
                {canDecide && a.status === "pending" && (
                  <>
                    <button
                      className="btn bg-allow/90 px-2.5 py-1 text-xs text-navy-950 hover:bg-allow disabled:opacity-50"
                      disabled={busy === a.approval_id + "a" || a.requester_user_id === user.user_id}
                      title={a.requester_user_id === user.user_id ? "Cannot approve your own request" : ""}
                      onClick={() => decide(a.approval_id, true)}
                    >
                      <Check size={13} /> Approve
                    </button>
                    <button
                      className="btn border border-deny/40 bg-deny/10 px-2.5 py-1 text-xs text-deny hover:bg-deny/20 disabled:opacity-50"
                      disabled={busy === a.approval_id + "d"}
                      onClick={() => decide(a.approval_id, false)}
                    >
                      <X size={13} /> Deny
                    </button>
                  </>
                )}
                {a.status === "approved" && a.requester_user_id === user.user_id && (
                  <button
                    className="btn-primary px-2.5 py-1 text-xs"
                    disabled={busy === a.approval_id + "x"}
                    onClick={() => execute(a.approval_id)}
                  >
                    <PlayCircle size={13} /> Execute (local sim)
                  </button>
                )}
                {a.status === "executed" && <DecisionBadge decision="ALLOW" />}
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const tone =
    status === "approved" || status === "executed"
      ? "allow"
      : status === "denied" || status === "expired"
      ? "deny"
      : "approve";
  return <Pill tone={tone}>{status}</Pill>;
}
