import type { ReactNode } from "react";
import { ClipboardList, Clock, ScrollText, ShieldAlert, ShieldCheck, type LucideIcon } from "lucide-react";
import type { DataSource } from "../api";
import { SourceTag } from "./common";

function Kpi({
  label,
  value,
  hint,
  Icon,
  source,
  tone = "default",
}: {
  label: string;
  value: ReactNode;
  hint: string;
  Icon: LucideIcon;
  source?: DataSource | "none";
  tone?: "default" | "allow" | "deny" | "approve";
}) {
  const color = { default: "text-slate-100", allow: "text-allow-ink", deny: "text-deny-ink", approve: "text-approve-ink" }[tone];
  return (
    <div className="card flex flex-col gap-1 px-4 py-3">
      <div className="flex items-center gap-2">
        <Icon size={16} className="text-slate-400" aria-hidden />
        <span className="eyebrow">{label}</span>
        <span className="ml-auto">{source && source !== "none" ? <SourceTag source={source} /> : null}</span>
      </div>
      <div className={`text-[26px] font-bold leading-tight tabular-nums ${color}`}>{value}</div>
      <div className="text-xs text-slate-500">{hint}</div>
    </div>
  );
}

/**
 * Protected / Blocked / Pending / Audit.
 * Blocked, Pending and Audit are REAL values from GET /api/metrics (AMAN 1.0 gateway).
 * "Protected" has no backend counter yet: it counts safe copies produced IN THIS BROWSER SESSION and is
 * tagged Mock whenever any of them came from the mock fallback; "—" until one exists.
 */
export function KpiStrip({
  metrics,
  protectedCount,
  protectedAnyMock,
}: {
  metrics: any | null;
  protectedCount: number;
  protectedAnyMock: boolean;
}) {
  const m = metrics;
  return (
    <div className="grid grid-cols-2 gap-4 xl:grid-cols-4" aria-label="Key figures">
      <Kpi
        label="Protected"
        Icon={ShieldCheck}
        value={protectedCount > 0 ? protectedCount : "—"}
        hint={protectedCount > 0 ? "Safe copies made this session" : "No safe copy made yet this session"}
        source={protectedCount > 0 ? (protectedAnyMock ? "mock" : "live") : "none"}
        tone={protectedCount > 0 ? "allow" : "default"}
      />
      <Kpi
        label="Blocked"
        Icon={ShieldAlert}
        value={m ? m.denied_actions : "—"}
        hint={m ? "Agent actions denied by the gateway" : "Metrics unavailable"}
        source={m ? "live" : "none"}
        tone="deny"
      />
      <Kpi
        label="Pending"
        Icon={Clock}
        value={m ? m.pending_approvals : "—"}
        hint={m ? "Approvals awaiting a finance manager" : "Metrics unavailable"}
        source={m ? "live" : "none"}
        tone="approve"
      />
      <Kpi
        label="Audit"
        Icon={m ? ScrollText : ClipboardList}
        value={m ? (m.audit_integrity.valid ? "Verified" : "BROKEN") : "—"}
        hint={m ? `${m.audit_integrity.checked} event${m.audit_integrity.checked === 1 ? "" : "s"} hash-chained` : "Metrics unavailable"}
        source={m ? "live" : "none"}
        tone={m ? (m.audit_integrity.valid ? "allow" : "deny") : "default"}
      />
    </div>
  );
}
