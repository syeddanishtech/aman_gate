import { useState } from "react";
import { FlaskConical, RefreshCw } from "lucide-react";
import { CONTRACT_ROWS, USE_MOCK, getEndpointStatus, getMockMode, setMockMode, type MockMode, type User } from "../api";
import { PageHeader } from "../components/common";
import { Card, Pill, RoleBadge, Spinner } from "../ui";

const MODES: { id: MockMode; title: string; desc: string }[] = [
  { id: "auto", title: "Auto (recommended)", desc: "Call the real endpoint. Use labelled sample data only if the route does not exist (404/405)." },
  { id: "force", title: "Always simulate", desc: "Never call the Privacy / Bridge / Assurance endpoints. Every value is labelled Mock." },
  { id: "off", title: "Live only", desc: "No sample data. A missing endpoint is shown as an error." },
];

export default function Settings({
  user,
  onReset,
  resetting,
  onModeChanged,
}: {
  user: User;
  onReset: () => void;
  resetting: boolean;
  onModeChanged: () => void;
}) {
  const [mode, setMode] = useState<MockMode>(getMockMode());
  const status = getEndpointStatus();

  return (
    <div>
      <PageHeader eyebrow="Configuration" title="Settings" subtitle="Session, data source and the provisional API contract." />
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <Card title="Signed in">
          <div className="flex flex-wrap items-center gap-3">
            <div>
              <div className="text-sm font-semibold text-slate-100">{user.display_name}</div>
              <div className="mono text-xs text-slate-500">
                {user.username} · tenant {user.tenant_id}
              </div>
            </div>
            <RoleBadge role={user.role} />
          </div>
          {user.role === "security_analyst" ? (
            <button className="btn-ghost mt-4" onClick={onReset} disabled={resetting}>
              {resetting ? <Spinner /> : <FlaskConical size={14} aria-hidden />} Reset demo data
            </button>
          ) : (
            <p className="mt-4 text-xs text-slate-500">Resetting demo data is limited to the security analyst role.</p>
          )}
        </Card>

        <Card title="Data source for the 2.0 tabs" subtitle="Applies to Protect Documents, Safe Cloud Bridge, Output Assurance and the Overview hero.">
          {!USE_MOCK && <p className="mb-2 text-xs text-deny-ink">The mock fallback is disabled at build time (USE_MOCK = false).</p>}
          <div role="radiogroup" aria-label="Data source mode" className="space-y-2">
            {MODES.map((m) => (
              <button
                key={m.id}
                role="radio"
                aria-checked={mode === m.id}
                disabled={!USE_MOCK && m.id !== "off"}
                onClick={() => {
                  setMockMode(m.id);
                  setMode(m.id);
                  onModeChanged();
                }}
                className={`w-full rounded-lg border-2 px-3 py-2.5 text-left transition-colors ${
                  mode === m.id ? "border-allow bg-allow/5" : "border-navy-700 bg-white hover:border-navy-600"
                }`}
              >
                <span className="flex items-center gap-2 text-sm font-semibold text-slate-100">
                  {m.title}
                  {mode === m.id && <span className="text-[11px] font-bold uppercase text-allow-ink">Selected</span>}
                </span>
                <span className="mt-0.5 block text-xs text-slate-400">{m.desc}</span>
              </button>
            ))}
          </div>
          <p className="mt-3 text-[11px] text-slate-500">Changing this applies to the next call; press Start over on the Overview to re-run with it.</p>
        </Card>

        <Card
          title="Provisional API contract"
          subtitle="Endpoints the 2.0 tabs expect. Re-point them in one place: frontend/src/api.ts → ENDPOINTS."
          className="xl:col-span-2"
          right={
            <button className="btn-ghost px-2.5 py-1 text-xs" onClick={onModeChanged}>
              <RefreshCw size={12} aria-hidden /> Refresh status
            </button>
          }
        >
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">Contract endpoints and the last data source observed</caption>
              <thead className="text-[10px] uppercase tracking-wide text-slate-500">
                <tr className="border-b border-navy-700">
                  <th scope="col" className="py-2 pr-3">Method</th>
                  <th scope="col" className="py-2 pr-3">Path</th>
                  <th scope="col" className="py-2 pr-3">Last seen</th>
                  <th scope="col" className="py-2">Note</th>
                </tr>
              </thead>
              <tbody>
                {CONTRACT_ROWS.map((r) => {
                  const s = status[r.key];
                  return (
                    <tr key={r.key} className="border-b border-navy-800">
                      <td className="mono py-2 pr-3 text-xs text-slate-400">{r.method}</td>
                      <td className="mono py-2 pr-3 text-xs text-slate-100">{r.path}</td>
                      <td className="py-2 pr-3">
                        {!s ? <Pill>not called yet</Pill> : s.source === "live" ? <Pill tone="allow">live</Pill> : s.source === "mock" ? <Pill tone="approve">mock</Pill> : <Pill tone="deny">error</Pill>}
                      </td>
                      <td className="py-2 text-xs text-slate-500">{s?.note ?? ""}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <p className="mt-3 text-[11px] text-slate-500">
            Existing AMAN 1.0 endpoints (documents, metrics, scenarios, approvals, audit …) are always called live — they are never mocked.
          </p>
        </Card>
      </div>
    </div>
  );
}
