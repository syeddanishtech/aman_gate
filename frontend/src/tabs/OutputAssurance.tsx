import { useEffect, useState, type ReactNode } from "react";
import { AlertTriangle, CheckCircle2, ClipboardCheck, Eye, EyeOff, Flag, KeyRound, ListChecks, ShieldAlert, Undo2, XCircle } from "lucide-react";
import { usePipeline } from "../pipeline";
import { PageHeader, SourceTag } from "../components/common";
import { describeItem, readIntegrity } from "../lib/contract";
import { Card, Pill, Spinner } from "../ui";

type Verdict = "PASS" | "REVIEW" | "FAIL";

export default function OutputAssurance() {
  const p = usePipeline();
  const [text, setText] = useState(p.assuranceInput);
  const [reveal, setReveal] = useState(false);

  useEffect(() => {
    setText(p.assuranceInput);
  }, [p.assuranceInput]);
  useEffect(() => setReveal(false), [p.assurance]);

  const a = p.assurance?.data;
  const integrity = a ? readIntegrity(a.placeholder_integrity) : null;
  const leaks = a?.leaks ?? [];
  const flags = a?.flags ?? [];
  const verdict: Verdict | null = !a ? null : leaks.length > 0 ? "FAIL" : integrity?.ok === false || flags.length > 0 ? "REVIEW" : "PASS";

  // Demo helper: append a real original value from the analyzed artifact (or the lab canary) to the text.
  function injectLeak() {
    const f = p.artifact?.data.findings.find((x) => x.original && x.action !== "generalize");
    setText((t) => `${t}${t.endsWith("\n") || !t ? "" : "\n"}Reminder: the original value is ${f?.original ?? "LAB-CANARY-7731"}.`);
  }

  return (
    <div>
      <PageHeader
        eyebrow="Workstream C"
        title="Output Assurance"
        subtitle="Check what comes back before anyone relies on it: placeholders intact, nothing leaked, restoration kept local."
        right={<span className="tag border border-navy-600 bg-white text-slate-300">Advisory checks — never an access boundary</span>}
      />

      {p.error && (
        <div role="alert" className="mb-4 flex items-start gap-2 rounded-lg border border-deny/40 bg-deny/10 px-3 py-2.5 text-sm text-deny-ink">
          <AlertTriangle size={16} className="mt-0.5 shrink-0" aria-hidden /> {p.error}
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <Card
          title="AI response to check"
          subtitle="Filled automatically from the bridge. You can edit it to see how the checks react."
          right={p.bridge ? <SourceTag source={p.bridge.source} /> : undefined}
        >
          <label htmlFor="oa-text" className="sr-only">
            AI response text
          </label>
          <textarea
            id="oa-text"
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={11}
            placeholder="Run the AI from the Overview or Safe Cloud Bridge, or paste a response here…"
            className="w-full resize-y rounded-lg border bg-white p-3 text-[13px] leading-6 text-slate-200 outline-none"
          />
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <button className="btn-primary" disabled={!text.trim() || !!p.busy} onClick={() => void p.checkResponse(text)}>
              {p.busy === "check" ? <Spinner /> : <ClipboardCheck size={15} aria-hidden />} Run assurance check
            </button>
            <button className="btn-ghost" disabled={!p.bridge} onClick={() => setText(p.bridge?.data.response ?? "")} title="Restore the bridge response">
              <Undo2 size={14} aria-hidden /> Use simulator response
            </button>
            <button className="btn-ghost" disabled={!text} onClick={injectLeak} title="Demo only: append an original sensitive value to the text">
              <ShieldAlert size={14} aria-hidden /> Insert test leak (demo)
            </button>
          </div>
          {!p.bridge && (
            <p className="mt-3 text-[11px] text-slate-500">
              No AI response yet in this session — you can still paste any text above and run the checks.
            </p>
          )}
        </Card>

        <div className="space-y-6">
          {verdict ? (
            <VerdictBanner verdict={verdict} leaks={leaks.length} flags={flags.length} integrityOk={integrity?.ok ?? null} source={p.assurance!.source} />
          ) : (
            <div className="card flex items-center gap-3 border-dashed p-5 text-sm text-slate-500">
              <ListChecks size={18} aria-hidden /> No check run yet. Press <b className="text-slate-300">Run assurance check</b>.
            </div>
          )}

          <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
            <Result title="Placeholder integrity" Icon={ListChecks} source={p.assurance?.source}>
              {integrity ? (
                <>
                  <StatusLine ok={integrity.ok} okText="Placeholders intact" badText="Placeholder problem" naText="Not determined" />
                  <dl className="mt-2 space-y-1 text-xs">
                    {integrity.rows.map(([k, v]) => (
                      <div key={k} className="flex gap-2">
                        <dt className="w-24 shrink-0 capitalize text-slate-500">{k}</dt>
                        <dd className="mono break-all text-slate-300">{v}</dd>
                      </div>
                    ))}
                  </dl>
                </>
              ) : (
                <Empty />
              )}
            </Result>

            <Result title="Leak scan" Icon={ShieldAlert} source={p.assurance?.source}>
              {a ? (
                <>
                  <StatusLine ok={leaks.length === 0} okText="No leaks found" badText={`${leaks.length} leak(s) found`} />
                  <ul className="mt-2 space-y-1.5 text-xs">
                    {leaks.map((l, i) => (
                      <li key={i} className="rounded-md border border-deny/40 bg-deny/5 px-2 py-1.5 text-deny-ink">
                        {describeItem(l)}
                      </li>
                    ))}
                  </ul>
                </>
              ) : (
                <Empty />
              )}
            </Result>

            <Result title="Review flags" Icon={Flag} source={p.assurance?.source}>
              {a ? (
                <>
                  <StatusLine ok={flags.length === 0} okText="No flags" badText={`${flags.length} flag(s) to review`} warn />
                  <ul className="mt-2 space-y-1.5 text-xs">
                    {flags.map((f, i) => (
                      <li key={i} className="rounded-md border border-approve/50 bg-approve/10 px-2 py-1.5 text-approve-ink">
                        {describeItem(f)}
                      </li>
                    ))}
                  </ul>
                </>
              ) : (
                <Empty />
              )}
            </Result>

            <Result title="Local rehydration" Icon={KeyRound} source={p.assurance?.source}>
              {a ? (
                typeof a.rehydrated === "string" ? (
                  <>
                    <p className="text-xs text-slate-400">Placeholders restored from the local vault. This view never leaves the device.</p>
                    <button className="btn-ghost mt-2 px-2.5 py-1 text-xs" onClick={() => setReveal((r) => !r)} aria-pressed={reveal}>
                      {reveal ? <EyeOff size={13} aria-hidden /> : <Eye size={13} aria-hidden />} {reveal ? "Hide" : "Reveal locally"}
                    </button>
                    {reveal && (
                      <pre
                        tabIndex={0}
                        className="mt-2 max-h-[180px] overflow-auto whitespace-pre-wrap break-words rounded-lg border border-navy-700 bg-navy-900 p-2.5 text-[12px] leading-5 text-slate-200"
                        style={{ fontFamily: "inherit" }}
                      >
                        {a.rehydrated}
                      </pre>
                    )}
                  </>
                ) : (
                  <p className="text-xs text-slate-400">
                    Rehydration not available for this request (<Pill>{String(a.rehydrated)}</Pill>). The backend decides by role and purpose.
                  </p>
                )
              ) : (
                <Empty />
              )}
            </Result>
          </div>
        </div>
      </div>
    </div>
  );
}

function Empty() {
  return <p className="text-xs text-slate-500">Waiting for a check.</p>;
}

function Result({ title, Icon, source, children }: { title: string; Icon: typeof Flag; source?: "live" | "mock"; children: ReactNode }) {
  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          <Icon size={15} className="text-slate-400" aria-hidden /> {title}
        </span>
      }
      right={source ? <SourceTag source={source} /> : undefined}
    >
      {children}
    </Card>
  );
}

function StatusLine({ ok, okText, badText, naText, warn }: { ok: boolean | null; okText: string; badText: string; naText?: string; warn?: boolean }) {
  if (ok === null)
    return <p className="text-sm font-semibold text-slate-300">{naText ?? "Not determined"}</p>;
  const Icon = ok ? CheckCircle2 : warn ? AlertTriangle : XCircle;
  const tone = ok ? "text-allow-ink" : warn ? "text-approve-ink" : "text-deny-ink";
  return (
    <p className={`flex items-center gap-1.5 text-sm font-semibold ${tone}`}>
      <Icon size={16} aria-hidden /> {ok ? okText : badText}
    </p>
  );
}

function VerdictBanner({ verdict, leaks, flags, integrityOk, source }: { verdict: Verdict; leaks: number; flags: number; integrityOk: boolean | null; source: "live" | "mock" }) {
  const cfg = {
    PASS: { Icon: CheckCircle2, cls: "border-allow bg-allow/10 text-allow-ink", msg: "Safe to show: no leaks, placeholders intact, nothing flagged." },
    REVIEW: { Icon: AlertTriangle, cls: "border-approve bg-approve/10 text-approve-ink", msg: "Needs a human look before use." },
    FAIL: { Icon: XCircle, cls: "border-deny bg-deny/10 text-deny-ink", msg: "Do not use: sensitive data appears in the AI output." },
  }[verdict];
  return (
    <div role="status" className={`flex flex-wrap items-center gap-3 rounded-xl border-2 px-5 py-4 ${cfg.cls}`}>
      <cfg.Icon size={26} aria-hidden />
      <div>
        <div className="text-lg font-bold tracking-wide">{verdict}</div>
        <div className="text-sm">{cfg.msg}</div>
        <div className="mt-0.5 text-xs opacity-80">
          {leaks} leak(s) · {flags} flag(s) · placeholders {integrityOk === null ? "not determined" : integrityOk ? "intact" : "broken"}
        </div>
      </div>
      <span className="ml-auto">
        <SourceTag source={source} />
      </span>
    </div>
  );
}
