import { PageHeader, SubTabs } from "../components/common";
import type { User } from "../api";
import Home from "./Home";
import Replay from "./Replay";
import Policies from "./Policies";
import Approvals from "./Approvals";
import type { NavTarget } from "../nav";

type Sub = "live" | "replay" | "policies" | "approvals";

/** AI Agent Firewall = the AMAN 1.0 product, unchanged and fed by REAL endpoints: the old Command Center
 *  (live scenario demo), Scenario Replay, Policies and the Approval Queue. */
export default function Firewall({
  user,
  refreshKey,
  onChanged,
  go,
  sub,
  setSub,
}: {
  user: User;
  refreshKey: number;
  onChanged: () => void;
  go: (t: NavTarget) => void;
  sub: string | undefined;
  setSub: (s: string) => void;
}) {
  const active: Sub = sub === "replay" || sub === "policies" || sub === "approvals" ? sub : "live";
  return (
    <div>
      <PageHeader
        eyebrow="AMAN Gate 1.0 · server-side enforcement"
        title="AI Agent Firewall"
        subtitle="Every tool call an AI agent proposes is allowed, denied or held for approval by the gateway — independent of the AI. All figures here come from the real backend."
      />
      <SubTabs
        label="AI Agent Firewall views"
        value={active}
        onChange={setSub}
        tabs={[
          { id: "live", label: "Live demo" },
          { id: "replay", label: "Scenario replay" },
          { id: "policies", label: "Policies" },
          { id: "approvals", label: "Approval queue" },
        ]}
      />
      {active === "live" && (
        <Home
          refreshKey={refreshKey}
          onChanged={onChanged}
          goTo={(t: string) =>
            go(
              t === "replay" || t === "policies" || t === "approvals"
                ? { section: "firewall", sub: t }
                : t === "documents"
                ? { section: "protect", sub: "registry" }
                : t === "audit"
                ? { section: "evidence" }
                : { section: "firewall", sub: "live" },
            )
          }
        />
      )}
      {active === "replay" && <Replay refreshKey={refreshKey} onChanged={onChanged} />}
      {active === "policies" && <Policies refreshKey={refreshKey} />}
      {active === "approvals" && <Approvals user={user} refreshKey={refreshKey} onChanged={onChanged} />}
    </div>
  );
}
