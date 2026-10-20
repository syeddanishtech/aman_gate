import { useCallback, useEffect, useState } from "react";
import {
  ShieldCheck,
  LayoutDashboard,
  PlayCircle,
  ScrollText,
  FileLock2,
  Inbox,
  FileSearch,
  LogOut,
  RefreshCw,
  FlaskConical,
} from "lucide-react";
import { api, getToken, setToken, type User } from "./api";
import { Spinner, RoleBadge } from "./ui";
import Login from "./Login";
import Home from "./tabs/Home";
import Replay from "./tabs/Replay";
import Policies from "./tabs/Policies";
import Documents from "./tabs/Documents";
import Approvals from "./tabs/Approvals";
import Audit from "./tabs/Audit";

type TabId = "home" | "replay" | "policies" | "documents" | "approvals" | "audit";

const TABS: { id: TabId; label: string; Icon: any }[] = [
  { id: "home", label: "Command Center", Icon: LayoutDashboard },
  { id: "replay", label: "Scenario Replay", Icon: PlayCircle },
  { id: "policies", label: "Policies", Icon: ScrollText },
  { id: "documents", label: "Document Access", Icon: FileLock2 },
  { id: "approvals", label: "Approval Queue", Icon: Inbox },
  { id: "audit", label: "Audit & Evidence", Icon: FileSearch },
];

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [tab, setTab] = useState<TabId>("home");
  const [loading, setLoading] = useState(true);
  const [refreshKey, setRefreshKey] = useState(0);
  const [resetting, setResetting] = useState(false);

  const refresh = useCallback(() => setRefreshKey((k) => k + 1), []);

  useEffect(() => {
    if (!getToken()) {
      setLoading(false);
      return;
    }
    api
      .me()
      .then(setUser)
      .catch(() => setToken(null))
      .finally(() => setLoading(false));
  }, []);

  function logout() {
    setToken(null);
    setUser(null);
  }

  async function resetDemo() {
    if (user?.role !== "security_analyst") return;
    setResetting(true);
    try {
      await api.reset();
      refresh();
    } finally {
      setResetting(false);
    }
  }

  if (loading)
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Spinner />
      </div>
    );
  if (!user) return <Login onLogin={setUser} />;

  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-20 border-b border-navy-700 bg-navy-950/90 backdrop-blur">
        <div className="mx-auto flex max-w-[1680px] items-center gap-4 px-5 py-3">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-allow/10 ring-1 ring-allow/40">
              <ShieldCheck className="text-allow" size={20} />
            </div>
            <div>
              <div className="text-sm font-bold leading-tight text-slate-100">AMAN Gate</div>
              <div className="text-[11px] leading-tight text-slate-500">
                Trust the task. Verify every action.
              </div>
            </div>
          </div>

          <span className="tag border border-approve/30 bg-approve/5 text-approve">
            <FlaskConical size={12} /> Synthetic data — Local-only security demonstration
          </span>

          <div className="ml-auto flex items-center gap-3">
            <button className="btn-ghost" onClick={refresh} title="Refresh data">
              <RefreshCw size={14} /> Refresh
            </button>
            {user.role === "security_analyst" && (
              <button className="btn-ghost" onClick={resetDemo} disabled={resetting} title="Reset demo data">
                {resetting ? <Spinner /> : <FlaskConical size={14} />} Reset demo
              </button>
            )}
            <div className="flex items-center gap-2 border-l border-navy-700 pl-3">
              <div className="text-right">
                <div className="text-xs font-medium text-slate-200">{user.display_name.split(" (")[0]}</div>
                <div className="text-[11px] text-slate-500">{user.username}</div>
              </div>
              <RoleBadge role={user.role} />
              <button className="btn-ghost px-2" onClick={logout} title="Sign out">
                <LogOut size={14} />
              </button>
            </div>
          </div>
        </div>

        <nav className="mx-auto flex max-w-[1680px] gap-1 overflow-x-auto px-4">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-2 border-b-2 px-3.5 py-2.5 text-sm font-medium transition-colors ${
                tab === t.id
                  ? "border-allow text-allow"
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              <t.Icon size={15} /> {t.label}
            </button>
          ))}
        </nav>
      </header>

      <main className="mx-auto max-w-[1680px] px-5 py-5">
        {tab === "home" && <Home refreshKey={refreshKey} goTo={setTab} onChanged={refresh} />}
        {tab === "replay" && <Replay refreshKey={refreshKey} onChanged={refresh} />}
        {tab === "policies" && <Policies refreshKey={refreshKey} />}
        {tab === "documents" && <Documents user={user} refreshKey={refreshKey} onChanged={refresh} />}
        {tab === "approvals" && <Approvals user={user} refreshKey={refreshKey} onChanged={refresh} />}
        {tab === "audit" && <Audit refreshKey={refreshKey} />}
      </main>

      <footer className="mx-auto max-w-[1680px] px-5 pb-8 pt-2 text-center text-[11px] text-slate-600">
        AMAN Gate · Northbridge University (fictional) · Synthetic data · Not connected to any network ·
        Enforcement is server-side and independent of the AI assistant.
      </footer>
    </div>
  );
}
