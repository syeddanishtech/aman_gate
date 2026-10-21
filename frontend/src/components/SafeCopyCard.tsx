import { Fragment } from "react";
import { ArrowRight, Ban, HardDrive, Lock, ShieldCheck } from "lucide-react";
import type { ArtifactResponse, DataSource } from "../api";
import { locate, titleCase, type Decision, type Range } from "../lib/contract";
import { SourceTag } from "./common";

const STRONG = new Set(["redact", "omit", "deny"]);

function Highlighted({ text, ranges, side }: { text: string; ranges: Range[]; side: "original" | "safe" }) {
  const out: JSX.Element[] = [];
  let at = 0;
  ranges.forEach((r) => {
    if (r.start > at) out.push(<Fragment key={`t${at}`}>{text.slice(at, r.start)}</Fragment>);
    const strong = STRONG.has(String(r.finding.action));
    const cls =
      side === "safe"
        ? "border-allow/50 bg-allow/10 text-allow-ink"
        : strong
        ? "border-deny/60 bg-deny/10 text-ink decoration-deny"
        : "border-approve/70 bg-approve/15 text-ink";
    out.push(
      <mark
        key={`m${r.start}`}
        className={`rounded-sm border-b-2 px-0.5 font-medium ${cls} ${side === "safe" ? "" : strong ? "underline decoration-wavy decoration-1 underline-offset-2" : "underline decoration-dotted decoration-1 underline-offset-2"}`}
        title={`${titleCase(r.finding.type)} · ${r.finding.action ?? "handled"}`}
      >
        {text.slice(r.start, r.end)}
        <sup className="ml-px text-[9px] font-bold">{r.index + 1}</sup>
      </mark>,
    );
    at = r.end;
  });
  if (at < text.length) out.push(<Fragment key="tail">{text.slice(at)}</Fragment>);
  return <>{out}</>;
}

/**
 * The centerpiece: ORIGINAL — STAYS LOCAL  vs  SAFE COPY — WHAT AI CAN SEE, with findings highlighted and
 * numbered (number + underline style + legend, so meaning never depends on colour alone).
 */
export function SafeCopyCard({
  artifact,
  label,
  source,
  isSample,
  decision,
  blockedReason,
}: {
  artifact: ArtifactResponse;
  label: string;
  source: DataSource;
  isSample: boolean;
  decision: Decision;
  blockedReason?: string | null;
}) {
  const blocked = decision === "BLOCKED";
  const origRanges = locate(artifact.original_preview, artifact.findings, "original");
  const safeRanges = blocked ? [] : locate(artifact.safe_copy_preview, artifact.findings, "safe");

  return (
    <section className="card overflow-hidden" aria-label="Original document versus safe copy">
      <header className="flex flex-wrap items-center gap-2 border-b border-navy-700 bg-navy-900 px-4 py-2.5">
        <span className="text-sm font-semibold text-slate-100">{label}</span>
        <SourceTag source={source} />
        {isSample && (
          <span className="tag border border-navy-600 bg-white text-slate-300" title="No document analyzed yet — this is built-in synthetic sample text">
            Sample preview — not your document
          </span>
        )}
        <span className="ml-auto text-xs text-slate-500">
          {artifact.findings.length} finding{artifact.findings.length === 1 ? "" : "s"} highlighted
        </span>
      </header>

      <div className="grid gap-0 lg:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)]">
        {/* ORIGINAL */}
        <div className="min-w-0 border-b border-navy-700 p-4 lg:border-b-0">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <Lock size={16} className="text-ink" aria-hidden />
            <h3 className="text-[13px] font-bold uppercase tracking-wide text-ink">Original — stays local</h3>
            <span className="tag ml-auto border border-navy-600 bg-white text-slate-300">
              <HardDrive size={11} aria-hidden /> Never leaves this device
            </span>
          </div>
          <div
            tabIndex={0}
            role="region"
            aria-label="Original document text"
            className="max-h-[300px] overflow-auto whitespace-pre-wrap break-words rounded-lg border border-navy-700 bg-navy-900 p-3 text-[13px] leading-6 text-slate-200"
          >
            {artifact.original_preview ? (
              <Highlighted text={artifact.original_preview} ranges={origRanges} side="original" />
            ) : (
              <span className="text-slate-500">No original text available to preview.</span>
            )}
          </div>
        </div>

        {/* transformation arrow */}
        <div className="hidden items-center justify-center px-1 lg:flex" aria-hidden>
          <span className="flex h-9 w-9 items-center justify-center rounded-full border border-navy-600 bg-white text-slate-400 shadow-card">
            <ArrowRight size={16} />
          </span>
        </div>

        {/* SAFE COPY */}
        <div className="min-w-0 p-4">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            {blocked ? <Ban size={16} className="text-deny-ink" aria-hidden /> : <ShieldCheck size={16} className="text-allow-ink" aria-hidden />}
            <h3 className="text-[13px] font-bold uppercase tracking-wide text-ink">Safe copy — what AI can see</h3>
            <span className={`tag ml-auto border ${blocked ? "border-deny/40 bg-deny/10 text-deny-ink" : "border-allow/40 bg-allow/10 text-allow-ink"}`}>
              {blocked ? "Nothing shareable" : "Only this would be shared"}
            </span>
          </div>
          <div
            tabIndex={0}
            role="region"
            aria-label="Safe copy text"
            className={`max-h-[300px] overflow-auto whitespace-pre-wrap break-words rounded-lg border p-3 text-[13px] leading-6 text-slate-200 ${
              blocked ? "border-deny/30 bg-deny/5" : "border-allow/30 bg-allow/5"
            }`}
          >
            {blocked ? (
              <span className="flex items-start gap-2 text-deny-ink">
                <Ban size={16} className="mt-1 shrink-0" aria-hidden />
                <span>
                  <b>No safe copy was produced.</b> {blockedReason}
                </span>
              </span>
            ) : artifact.safe_copy_preview ? (
              <Highlighted text={artifact.safe_copy_preview} ranges={safeRanges} side="safe" />
            ) : (
              <span className="text-slate-500">Safe copy is empty.</span>
            )}
          </div>
        </div>
      </div>

      {artifact.findings.length > 0 && (
        <footer className="border-t border-navy-700 bg-navy-900 px-4 py-3">
          <div className="eyebrow mb-2">Findings legend — number · type · action → replacement</div>
          <ul className="flex flex-wrap gap-1.5">
            {artifact.findings.map((f, i) => (
              <li
                key={f.id ?? i}
                className="inline-flex items-center gap-1.5 rounded-md border border-navy-700 bg-white px-2 py-1 text-xs text-slate-300"
              >
                <span className="flex h-4 min-w-4 items-center justify-center rounded bg-ink px-1 text-[10px] font-bold text-white">{i + 1}</span>
                <span className="font-semibold text-slate-100">{titleCase(f.type)}</span>
                <span className="text-slate-500">{f.action ?? "handled"}</span>
                {f.replacement && !blocked && (
                  <>
                    <ArrowRight size={11} className="text-slate-400" aria-hidden />
                    <span className="mono text-[11px] text-allow-ink">{f.replacement}</span>
                  </>
                )}
              </li>
            ))}
          </ul>
        </footer>
      )}
    </section>
  );
}
