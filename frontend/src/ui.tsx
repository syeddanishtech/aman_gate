import { Check, CircleSlash, Clock, Info, ShieldAlert } from "lucide-react";
import type { ReactNode } from "react";

export type DecisionKind = "ALLOW" | "DENY" | "NEEDS_APPROVAL" | string;

export function decisionStyle(d: DecisionKind) {
  if (d === "ALLOW") return { text: "text-allow-ink", bg: "bg-allow/10", border: "border-allow/40", Icon: Check };
  if (d === "DENY") return { text: "text-deny-ink", bg: "bg-deny/10", border: "border-deny/40", Icon: CircleSlash };
  if (d === "NEEDS_APPROVAL")
    return { text: "text-approve-ink", bg: "bg-approve/10", border: "border-approve/40", Icon: Clock };
  if (d === "BASELINE_NO_ENFORCEMENT" || d === "EXECUTED_NO_CHECK")
    return { text: "text-deny-ink", bg: "bg-deny/10", border: "border-deny/40", Icon: ShieldAlert };
  return { text: "text-slate-300", bg: "bg-navy-700/40", border: "border-navy-600", Icon: Info };
}

export function DecisionBadge({ decision, className = "" }: { decision: DecisionKind; className?: string }) {
  const s = decisionStyle(decision);
  const label =
    decision === "NEEDS_APPROVAL" ? "NEEDS APPROVAL" : String(decision).replace(/_/g, " ");
  return (
    <span className={`tag border ${s.bg} ${s.text} ${s.border} ${className}`}>
      <s.Icon size={12} /> {label}
    </span>
  );
}

export function Card({
  title,
  subtitle,
  right,
  children,
  className = "",
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`card p-4 ${className}`}>
      {(title || right) && (
        <header className="mb-3 flex items-start justify-between gap-3">
          <div>
            {title && <h3 className="text-sm font-semibold text-slate-100">{title}</h3>}
            {subtitle && <p className="mt-0.5 text-xs text-slate-400">{subtitle}</p>}
          </div>
          {right}
        </header>
      )}
      {children}
    </section>
  );
}

export function Stat({
  label,
  value,
  tone = "default",
  hint,
}: {
  label: string;
  value: ReactNode;
  tone?: "default" | "allow" | "deny" | "approve";
  hint?: string;
}) {
  const toneCls =
    tone === "deny"
      ? "text-deny-ink"
      : tone === "approve"
      ? "text-approve-ink"
      : tone === "allow"
      ? "text-allow-ink"
      : "text-slate-100";
  return (
    <div className="card px-4 py-3" title={hint}>
      <div className="text-[11px] font-medium uppercase tracking-wide text-slate-400">{label}</div>
      <div className={`mt-1 text-2xl font-bold tabular-nums ${toneCls}`}>{value}</div>
    </div>
  );
}

export function RoleBadge({ role }: { role: string }) {
  return (
    <span className="tag border border-navy-600 bg-navy-800 text-slate-300">{role.replace(/_/g, " ")}</span>
  );
}

export function Pill({ children, tone = "default" }: { children: ReactNode; tone?: string }) {
  const map: Record<string, string> = {
    default: "border-navy-600 bg-navy-800 text-slate-300",
    allow: "border-allow/40 bg-allow/10 text-allow-ink",
    deny: "border-deny/40 bg-deny/10 text-deny-ink",
    approve: "border-approve/40 bg-approve/10 text-approve-ink",
  };
  return <span className={`tag border ${map[tone] || map.default}`}>{children}</span>;
}

export function Spinner() {
  return (
    <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-slate-500 border-t-allow" />
  );
}
