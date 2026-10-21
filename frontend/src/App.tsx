import { useCallback, useEffect, useState } from "react";
import {
  ClipboardCheck,
  Cloud,
  FileLock2,
  FileSearch,
  FlaskConical,
  LayoutDashboard,
  LogOut,
  Presentation,
  RefreshCw,
  Settings as SettingsIcon,
  ShieldCheck,
  ShieldHalf,
  type LucideIcon,
} from "lucide-react";
import { api, getToken, setToken, type User } from "./api";
import { Spinner, RoleBadge } from "./ui";
import Login from "./Login";
import { PipelineProvider, usePipeline } from "./pipeline";
import { SimulationChip, SimulationWatermark } from "./components/common";
import type { NavTarget, SectionId } from "./nav";
import Overview from "./tabs/Overview";
import ProtectDocuments from "./tabs/ProtectDocuments";
import Firewall from "./tabs/Firewall";
import SafeBridge from "./tabs/SafeBridge";
import OutputAssurance from "./tabs/OutputAssurance";
import Evidence from "./tabs/Evidence";
import Settings from "./tabs/Settings";
import JudgeDemo from "./tabs/JudgeDemo";

const NAV: { id: SectionId; label: string; Icon: LucideIcon }[] = [
  { id: "overview", label: "Overview", Icon: LayoutDashboard },
  { id: "protect", label: "Protect Documents", Icon: FileLock2 },
  { id: "firewall", label: "AI Agent Firewall", Icon: ShieldHalf },
  { id: "bridge", label: "Safe Cloud Bridge", Icon: Cloud },
  { id: "assurance", label: "Output Assurance", Icon: ClipboardCheck },
  { id: "evidence", label: "Evidence & Research", Icon: FileSearch },
  { id: "settings", label: "Settings", Icon: SettingsIcon },
];

const SECTIONS = new Set<string>([...NAV.map((n) => n.id), "judge"]);

function parseHash(): NavTarget {
  const [section, sub] = window.location.hash.replace(/^#\/?/, "").split("/");
  return SECTIONS.has(section) ? { section: section as SectionId, sub: sub || undefined } : { section: "overview" };
}

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshKey, setRefreshKey] = useState(0);

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

  if (loading)
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Spinner />
      </div>
    );
  if (!user) return <Login onLogin={setUser} />;

  return (
    <PipelineProvider refreshKey={refreshKey}>
      <Shell
        user={user}
        refreshKey={refreshKey}
        refresh={() => setRefreshKey((k) => k + 1)}
        logout={() => {
          setToken(null);
          setUser(null);
        }}
      />
    </PipelineProvider>
  );
}

function Shell({ user, refreshKey, refresh, logout }: { user: User; refreshKey: number; refresh: () => void; logout: () => void }) {
  const p = usePipeline();
  const [nav, setNav] = useState<NavTarget>(parseHash);
  const [resetting, setResetting] = useState(false);

  useEffect(() => {
    const onHash = () => setNav(parseHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const go = useCallback((t: NavTarget) => {
    window.location.hash = `/${t.section}${t.sub ? `/${t.sub}` : ""}`;
    setNav(t);
    window.scrollTo({ top: 0 });
  }, []);
  const setSub = (sub: string) => go({ section: nav.section, sub });

  async function resetDemo() {
    if (user.role !== "security_analyst") return;
    setResetting(true);
    try {
      await api.reset();
      p.reset();
      refresh();
    } finally {
      setResetting(false);
    }
  }

  // Sections that render mock data or the local simulator carry the persistent Simulation watermark.
  const simulated =
    ["overview", "bridge", "assurance", "judge"].includes(nav.section) || (nav.section === "protect" && nav.sub !== "registry");
  const reasons = p.simulationReasons.length ? p.simulationReasons : ["Local simulator"];

  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[248px_minmax(0,1fr)]">
      <button
        className="sr-only z-50 rounded bg-white px-3 py-2 text-sm font-semibold text-ink shadow-lift focus:not-sr-only focus:fixed focus:left-3 focus:top-3"
        onClick={() => document.getElementById("main")?.focus()}
      >
        Skip to main content
      </button>
      {simulated && <SimulationWatermark />}

      {/* Sidebar */}
      <aside className="flex flex-col gap-4 border-b border-navy-700 bg-white p-4 lg:sticky lg:top-0 lg:h-screen lg:overflow-y-auto lg:border-b-0 lg:border-r">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-allow text-white shadow-card">
            <ShieldCheck size={22} aria-hidden />
          </div>
          <div className="min-w-0">
            <div className="text-base font-bold leading-tight text-slate-100">AMAN Gate</div>
            <div className="text-[11px] leading-tight text-slate-500">Protect documents before AI sees them</div>
          </div>
        </div>

        <button
          onClick={() => go({ section: "judge" })}
          aria-current={nav.section === "judge" ? "page" : undefined}
          className={`flex items-center gap-2.5 rounded-lg border-2 px-3 py-2.5 text-left transition-colors ${
            nav.section === "judge" ? "border-allow bg-allow text-white" : "border-allow bg-white text-allow-ink hover:bg-allow/5"
          }`}
        >
          <Presentation size={18} aria-hidden />
          <span>
            <span className="block text-sm font-bold leading-tight">Judge Demo</span>
            <span className={`block text-[11px] leading-tight ${nav.section === "judge" ? "text-white/90" : "text-slate-500"}`}>Guided tour · about 1 minute</span>
          </span>
        </button>

        <nav aria-label="Primary" className="flex flex-wrap gap-1 lg:flex-col">
          {NAV.map(({ id, label, Icon }) => {
            const on = nav.section === id;
            return (
              <button
                key={id}
                onClick={() => go({ section: id })}
                aria-current={on ? "page" : undefined}
                className={`flex items-center gap-2.5 rounded-lg px-3 py-2 text-left text-sm font-medium transition-colors ${
                  on ? "bg-allow/10 font-semibold text-allow-ink" : "text-slate-300 hover:bg-navy-800"
                }`}
              >
                <Icon size={17} aria-hidden /> {label}
              </button>
            );
          })}
        </nav>

        <div className="mt-auto hidden space-y-3 lg:block">
          <span className="tag border border-approve/50 bg-approve/10 text-approve-ink">
            <FlaskConical size={12} aria-hidden /> Synthetic data · local only
          </span>
          <div className="flex items-center gap-2 border-t border-navy-700 pt-3">
            <div className="min-w-0 flex-1">
              <div className="truncate text-xs font-semibold text-slate-100">{user.display_name.split(" (")[0]}</div>
              <div className="mt-0.5">
                <RoleBadge role={user.role} />
              </div>
            </div>
            <button className="btn-ghost px-2" onClick={logout} title="Sign out" aria-label="Sign out">
              <LogOut size={14} aria-hidden />
            </button>
          </div>
        </div>
      </aside>

      {/* Content column */}
      <div className="flex min-w-0 flex-col">
        <header className="sticky top-0 z-30 flex flex-wrap items-center gap-3 border-b border-navy-700 bg-page/95 px-6 py-2.5 backdrop-blur xl:px-8">
          <span className="tag border border-navy-600 bg-white text-slate-300 lg:hidden">
            <FlaskConical size={12} aria-hidden /> Synthetic data
          </span>
          {simulated && <SimulationChip reasons={reasons} />}
          <div className="ml-auto flex items-center gap-2">
            <button className="btn-ghost px-3 py-1.5" onClick={refresh} title="Refresh data">
              <RefreshCw size={14} aria-hidden /> Refresh
            </button>
            {user.role === "security_analyst" && (
              <button className="btn-ghost px-3 py-1.5" onClick={resetDemo} disabled={resetting} title="Reset demo data">
                {resetting ? <Spinner /> : <FlaskConical size={14} aria-hidden />} Reset demo
              </button>
            )}
            <button className="btn-ghost px-3 py-1.5 lg:hidden" onClick={logout} aria-label="Sign out">
              <LogOut size={14} aria-hidden />
            </button>
          </div>
        </header>

        <main id="main" tabIndex={-1} className="mx-auto w-full max-w-[1480px] flex-1 px-6 py-6 outline-none xl:px-8">
          {nav.section === "overview" && <Overview refreshKey={refreshKey} go={go} />}
          {nav.section === "protect" && (
            <ProtectDocuments user={user} refreshKey={refreshKey} onChanged={refresh} go={go} sub={nav.sub} setSub={setSub} />
          )}
          {nav.section === "firewall" && (
            <Firewall user={user} refreshKey={refreshKey} onChanged={refresh} go={go} sub={nav.sub} setSub={setSub} />
          )}
          {nav.section === "bridge" && <SafeBridge go={go} />}
          {nav.section === "assurance" && <OutputAssurance />}
          {nav.section === "evidence" && <Evidence refreshKey={refreshKey} />}
          {nav.section === "settings" && <Settings user={user} onReset={resetDemo} resetting={resetting} onModeChanged={refresh} />}
          {nav.section === "judge" && <JudgeDemo go={go} />}
        </main>

        <footer className="mx-auto w-full max-w-[1480px] px-6 pb-8 pt-2 text-center text-[11px] text-slate-500 xl:px-8">
          AMAN Gate · Northbridge University (fictional) · Synthetic data · Not connected to any network · Enforcement is server-side and
          independent of the AI assistant.
        </footer>
      </div>
    </div>
  );
}
