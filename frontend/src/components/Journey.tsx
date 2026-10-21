import { Ban, BadgeCheck, Check, ClipboardCheck, Eye, Lock, ScanSearch, ShieldCheck, Upload, type LucideIcon } from "lucide-react";
import type { Decision } from "../lib/contract";
import { DECISION_LABEL } from "../lib/contract";
import type { JourneyStep } from "../pipeline";

const STEP_ICON: Record<JourneyStep["id"], LucideIcon> = {
  upload: Upload,
  detect: ScanSearch,
  sanitize: ShieldCheck,
  approve: BadgeCheck,
  check: ClipboardCheck,
};

const STATUS_WORD: Record<JourneyStep["status"], string> = {
  done: "Completed",
  current: "Current step",
  todo: "Upcoming",
  blocked: "Blocked",
};

/** 5-step journey rail. State is conveyed by icon + visible word + aria, never by colour alone. */
export function JourneyRail({ steps }: { steps: JourneyStep[] }) {
  return (
    <ol className="grid grid-cols-5" aria-label="Document protection journey">
      {steps.map((s, i) => {
        const Icon = s.status === "done" ? Check : s.status === "blocked" ? Ban : STEP_ICON[s.id];
        const circle =
          s.status === "done"
            ? "border-allow bg-allow text-white"
            : s.status === "current"
            ? "border-allow bg-white text-allow-ink ring-4 ring-allow/15"
            : s.status === "blocked"
            ? "border-deny bg-deny/10 text-deny-ink"
            : "border-navy-600 bg-white text-slate-500";
        return (
          <li key={s.id} aria-current={s.status === "current" ? "step" : undefined} className="relative flex flex-col items-center px-1 text-center">
            {i < steps.length - 1 && (
              <span
                aria-hidden
                className={`absolute left-1/2 top-[19px] h-0.5 w-full ${s.status === "done" ? "bg-allow" : "bg-navy-700"}`}
              />
            )}
            <span className={`relative z-10 flex h-10 w-10 items-center justify-center rounded-full border-2 ${circle}`}>
              <Icon size={18} aria-hidden />
            </span>
            <span className="eyebrow mt-2">Step {i + 1}</span>
            <span className="mt-0.5 text-[13px] font-semibold leading-tight text-slate-100 sm:text-sm">{s.label}</span>
            <span className="mt-0.5 hidden text-xs text-slate-500 md:block">{s.detail}</span>
            <span className={`mt-1 text-[11px] font-semibold ${s.status === "current" ? "text-allow-ink" : s.status === "blocked" ? "text-deny-ink" : "text-slate-500"}`}>
              {STATUS_WORD[s.status]}
            </span>
          </li>
        );
      })}
    </ol>
  );
}

const STRIP: { key: Decision; Icon: LucideIcon; caption: string; active: string }[] = [
  { key: "NOT_SHARED", Icon: Lock, caption: "Nothing has left this device", active: "border-ink bg-navy-800 text-ink" },
  { key: "READY_FOR_REVIEW", Icon: Eye, caption: "Safe copy awaits human review", active: "border-approve bg-approve/10 text-approve-ink" },
  { key: "BLOCKED", Icon: Ban, caption: "Policy refused to share", active: "border-deny bg-deny/10 text-deny-ink" },
  { key: "APPROVED", Icon: ShieldCheck, caption: "Safe copy may go to the simulator", active: "border-allow bg-allow/10 text-allow-ink" },
];

/** Security decision strip: exactly one of NOT SHARED / READY FOR REVIEW / BLOCKED / APPROVED is active. */
export function DecisionStrip({ decision }: { decision: Decision }) {
  return (
    <div role="group" aria-label="Security decision" className="grid grid-cols-2 gap-2 lg:grid-cols-4">
      {STRIP.map(({ key, Icon, caption, active }) => {
        const on = key === decision;
        return (
          <div
            key={key}
            aria-current={on ? "true" : undefined}
            className={`flex items-start gap-2.5 rounded-lg border-2 px-3 py-2.5 ${on ? active : "border-navy-700 bg-white text-slate-500"}`}
          >
            <Icon size={18} className="mt-0.5 shrink-0" aria-hidden />
            <div className="min-w-0">
              <div className={`flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-[13px] leading-tight ${on ? "font-bold" : "font-semibold"}`}>
                {DECISION_LABEL[key]}
                {on && <span className="rounded bg-white/70 px-1 py-px text-[10px] font-bold uppercase tracking-wide">Current</span>}
              </div>
              <div className={`mt-0.5 text-xs leading-snug ${on ? "opacity-90" : "text-slate-500"}`}>{caption}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
