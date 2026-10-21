import { useEffect, useState } from "react";
import { ShieldCheck, FlaskConical } from "lucide-react";
import { api, setToken, type User } from "./api";
import { RoleBadge, Spinner } from "./ui";

export default function Login({ onLogin }: { onLogin: (u: User) => void }) {
  const [users, setUsers] = useState<any[]>([]);
  const [password, setPassword] = useState("");
  const [username, setUsername] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .demoUsers()
      .then((d) => {
        setUsers(d.users);
        setPassword(d.password);
      })
      .catch(() => setUsers([]));
  }, []);

  async function doLogin(u: string) {
    setBusy(true);
    setError(null);
    try {
      const res = await api.login(u, password);
      setToken(res.access_token);
      onLogin(res.user);
    } catch (e: any) {
      setError(e?.detail?.code || "Login failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="mb-6 text-center">
          <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-xl bg-allow/10 ring-1 ring-allow/40">
            <ShieldCheck className="text-allow-ink" />
          </div>
          <h1 className="text-xl font-bold text-slate-100">AMAN Gate</h1>
          <p className="text-sm text-slate-400">Sovereign AI Agent Security Gateway</p>
          <p className="mt-1 text-xs text-slate-500">Trust the task. Verify every action.</p>
        </div>

        <div className="card p-5">
          <div className="mb-3 flex items-center gap-2 rounded-lg border border-approve/30 bg-approve/5 px-3 py-2 text-xs text-approve-ink">
            <FlaskConical size={14} /> Nonproduction demo accounts — synthetic data only.
          </div>

          <p className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-400">
            Quick login (Northbridge University)
          </p>
          <div className="space-y-2">
            {users.map((u) => (
              <button
                key={u.username}
                disabled={busy}
                onClick={() => doLogin(u.username)}
                className="flex w-full items-center justify-between rounded-lg border border-navy-700 bg-navy-800 px-3 py-2.5 text-left transition-colors hover:border-allow/40 hover:bg-navy-700 disabled:opacity-50"
              >
                <div>
                  <div className="text-sm font-medium text-slate-100">{u.display_name}</div>
                  <div className="mono text-[11px] text-slate-500">{u.username}</div>
                </div>
                <RoleBadge role={u.role} />
              </button>
            ))}
            {users.length === 0 && (
              <p className="text-xs text-slate-500">
                Backend unreachable. Start the API, then reload.
              </p>
            )}
          </div>

          <div className="my-4 h-px bg-navy-700" />
          <p className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-400">
            Manual login
          </p>
          <div className="flex gap-2">
            <input
              className="min-w-0 flex-1 rounded-lg border border-navy-700 bg-navy-900 px-3 py-2 text-sm text-slate-100 outline-none focus:border-allow/50"
              placeholder="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
            <button className="btn-primary" disabled={busy || !username} onClick={() => doLogin(username)}>
              {busy ? <Spinner /> : "Sign in"}
            </button>
          </div>
          {error && <p className="mt-2 text-xs text-deny-ink">{error}</p>}
          <p className="mt-3 mono text-[11px] text-slate-600">demo password: {password || "…"}</p>
        </div>
      </div>
    </div>
  );
}
