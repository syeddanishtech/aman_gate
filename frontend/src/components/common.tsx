import type { ReactNode } from "react";
import {
  Ban,
  BadgeCheck,
  CheckCircle2,
  ClipboardCheck,
  Eye,
  FlaskConical,
  MinusCircle,
  Play,
  Radio,
  ScanSearch,
  XCircle,
  type LucideIcon,
} from "lucide-react";
import type { DataSource } from "../api";
import type { Check } from "../lib/contract";
import type { PrimaryAction, PrimaryId } from "../pipeline";
import { Spinner } from "../ui";

/** LIVE = came from a real backend response. MOCK = labelled sample data from src/mock.ts. */
export function SourceTag({ source, className = "" }: { source: DataSource; className?: string }) {
  return source === "live" ? (
    <span className={`tag border border-allow/40 bg-allow/10 text-allow-ink ${className}`} title="Returned by a real backend endpoint">
      <Radio size={11} aria-hidden /> Live
    </span>
  ) : (
    <span
      className={`tag border border-approve/60 bg-approve/10 text-approve-ink ${className}`}
      title="Sample data generated in the browser — the backend endpoint is not available"
    >
      <FlaskConical size={11} aria-hidden /> Mock
    </span>
  );
}

/** Persistent "Simulation" watermark. Rendered on every view that shows mock data or the local simulator. */
export function SimulationWatermark() {
  return (
    <div aria-hidden="true" className="pointer-events-none fixed inset-0 z-40 select-none overflow-hidden">
      <div className="absolute inset-0 flex items-center justify-center">
        <span className="-rotate-[22deg] whitespace-nowrap text-[clamp(88px,15vw,240px)] font-black uppercase tracking-[0.18em] text-ink/[0.05]">
          Simulation
        </span>
      </div>
    </div>
  );
}

export function SimulationChip({ reasons }: { reasons: string[] }) {
  return (
    <span
      role="status"
      className="tag border border-approve/60 bg-approve/10 text-approve-ink"
      title={reasons.join(" · ")}
    >
      <FlaskConical size={12} aria-hidden /> Simulation · {reasons[0] ?? "local simulator"}
    </span>
  );
}

export function PageHeader({
  eyebrow,
  title,
  subtitle,
  right,
}: {
  eyebrow?: string;
  title: ReactNode;
  subtitle?: ReactNode;
  right?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        {eyebrow && <div className="eyebrow mb-1">{eyebrow}</div>}
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">{title}</h1>
        {subtitle && <p className="mt-1 max-w-3xl text-sm text-slate-400">{subtitle}</p>}
      </div>
      {right && <div className="flex flex-wrap items-center gap-2">{right}</div>}
    </div>
  );
}

export function SubTabs<T extends string>({
  tabs,
  value,
  onChange,
  label,
}: {
  tabs: { id: T; label: string }[];
  value: T;
  onChange: (t: T) => void;
  label: string;
}) {
  return (
    <div role="tablist" aria-label={label} className="mb-5 flex flex-wrap gap-1 border-b border-navy-700">
      {tabs.map((t) => (
        <button
          key={t.id}
          role="tab"
          aria-selected={value === t.id}
          onClick={() => onChange(t.id)}
          className={`-mb-px border-b-2 px-4 py-2.5 text-sm font-semibold transition-colors ${
            value === t.id
              ? "border-allow text-allow-ink"
              : "border-transparent text-slate-400 hover:border-navy-600 hover:text-slate-100"
          }`}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

/** Pass / fail / not-applicable rows. Icon + word carry the state, not colour alone. */
export function CheckList({ checks }: { checks: Check[] }) {
  return (
    <ul className="space-y-1.5">
      {checks.map((c) => {
        const Icon = c.ok === true ? CheckCircle2 : c.ok === false ? XCircle : MinusCircle;
        const tone = c.ok === true ? "text-allow-ink" : c.ok === false ? "text-deny-ink" : "text-slate-500";
        const word = c.ok === true ? "Pass" : c.ok === false ? "Fail" : "n/a";
        return (
          <li key={c.label} className="flex items-start gap-2 text-sm">
            <Icon size={16} className={`mt-0.5 shrink-0 ${tone}`} aria-hidden />
            <span className="text-slate-200">
              <span className={`mr-1.5 text-[11px] font-bold uppercase ${tone}`}>{word}</span>
              {c.label}
              <span className="ml-1.5 text-xs text-slate-500">— {c.detail}</span>
            </span>
          </li>
        );
      })}
    </ul>
  );
}

const PRIMARY_ICON: Record<PrimaryId, LucideIcon> = {
  analyze: ScanSearch,
  review: Eye,
  approve: BadgeCheck,
  run: Play,
  result: ClipboardCheck,
  blocked: Ban,
};

/** The single stage-aware primary button:
 *  Analyze Document → Review Safe Copy → Approve Sharing → Run AI (Simulator) → Check AI Result. */
export function PrimaryButton({
  primary,
  onClick,
  busy,
  size = "lg",
}: {
  primary: PrimaryAction;
  onClick: () => void;
  busy?: boolean;
  size?: "md" | "lg";
}) {
  const Icon = PRIMARY_ICON[primary.id];
  return (
    <button
      className={`btn-primary ${size === "lg" ? "px-5 py-2.5 text-[15px]" : ""}`}
      onClick={onClick}
      disabled={primary.disabled}
      title={primary.hint}
    >
      {busy ? <Spinner /> : <Icon size={size === "lg" ? 18 : 15} aria-hidden />} {primary.label}
    </button>
  );
}
