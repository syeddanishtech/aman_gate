import { useEffect, useState } from "react";
import { ScrollText, Wrench, Mail } from "lucide-react";
import { api } from "../api";
import { Card, Pill, Spinner } from "../ui";

export default function Policies({ refreshKey }: { refreshKey: number }) {
  const [data, setData] = useState<any>(null);
  useEffect(() => {
    api.policies().then(setData);
  }, [refreshKey]);
  if (!data)
    return (
      <div className="flex justify-center p-10">
        <Spinner />
      </div>
    );

  const sens: Record<string, string> = { low: "default", medium: "approve", high: "deny", forbidden: "deny" };

  return (
    <div className="space-y-4">
      <Card
        title="Tool gateway catalog"
        subtitle={`Only these tools exist. Policy version ${data.policy_version}. Any other tool name is denied.`}
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-[11px] uppercase tracking-wide text-slate-500">
              <tr className="border-b border-navy-700">
                <th className="py-2 pr-4">Tool</th>
                <th className="py-2 pr-4">Allowed roles</th>
                <th className="py-2 pr-4">Sensitivity</th>
                <th className="py-2 pr-4">Approval</th>
                <th className="py-2">Description</th>
              </tr>
            </thead>
            <tbody>
              {data.tools.map((t: any) => (
                <tr key={t.name} className="border-b border-navy-800 align-top">
                  <td className="py-2.5 pr-4">
                    <span className="mono flex items-center gap-1.5 font-semibold text-slate-100">
                      <Wrench size={13} className="text-slate-500" />
                      {t.name}
                    </span>
                  </td>
                  <td className="py-2.5 pr-4">
                    <div className="flex flex-wrap gap-1">
                      {t.roles.length ? (
                        t.roles.map((r: string) => <Pill key={r}>{r.replace(/_/g, " ")}</Pill>)
                      ) : (
                        <Pill tone="deny">none</Pill>
                      )}
                    </div>
                  </td>
                  <td className="py-2.5 pr-4">
                    <Pill tone={sens[t.sensitivity]}>{t.sensitivity}</Pill>
                  </td>
                  <td className="py-2.5 pr-4 text-slate-300">{t.requires_approval ? "required" : "—"}</td>
                  <td className="py-2.5 text-xs text-slate-400">{t.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="Destination allowlist" subtitle="Reports may only reach these local-simulator recipients. example.test is explicitly unapproved.">
        <div className="flex flex-wrap gap-2">
          {Object.entries(data.allowed_destinations).map(([dest, label]) => (
            <span key={dest} className="tag border border-allow/30 bg-allow/10 text-allow">
              <Mail size={12} /> {dest} — {String(label)}
            </span>
          ))}
        </div>
      </Card>

      <div className="grid gap-3 md:grid-cols-2">
        {data.policies.map((p: any) => (
          <div key={p.policy_id} className="card p-4">
            <div className="flex items-center gap-2">
              <ScrollText size={15} className="text-allow" />
              <h3 className="text-sm font-semibold text-slate-100">{p.title}</h3>
              <span className="mono ml-auto text-[10px] text-slate-600">{p.policy_id}</span>
            </div>
            <p className="mt-1.5 text-xs text-slate-400">{p.rule}</p>
            {p.matrix && (
              <div className="mono mt-2 space-y-0.5 text-[11px] text-slate-500">
                {Object.entries(p.matrix).map(([tool, roles]: any) => (
                  <div key={tool}>
                    {tool}: {roles.length ? roles.join(", ") : "(no role)"}
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
