# AMAN Gate — Sovereign AI Agent Security Gateway

**Trust the task. Verify every action.**

A runnable, offline-capable **lab prototype** that stops an AI procurement assistant from reading
unauthorized private records or executing unauthorized tool actions — even when the instructions to do so
are hidden inside untrusted supplier documents (indirect prompt injection).

> ⚠️ **Synthetic data — local-only security demonstration.** Everything here is fictional
> (*Northbridge University*) and synthetic. The app opens **no network sockets**; "external" destinations
> and sinks are local simulators. `*.test` domains are non-routable placeholders. Built for the
> Pakistan Cybersecurity Challenge 2026.

---

## View it live on GitHub (Codespaces) — one click

Run the **real** app (FastAPI backend + the 2.0 UI) in the cloud, no local setup:

1. On this repo, click **`Code ▾` → `Codespaces` → `Create codespace on main`**.
2. First time only, wait ~2–3 min while it installs the pinned deps, trains the advisory model and builds
   the UI (progress shows in the terminal).
3. A browser tab opens automatically on the forwarded **port 8000** (or open it from the **Ports** tab).
   Pick a quick-login (e.g. *Ayesha Khan — Procurement Officer*) and try **Protect Documents → PR-2026-118**.

This is the full system with real server-side enforcement — not a mock. The Codespace is private to your
GitHub account and uses synthetic data only. (GitHub Pages can't host this: the security lives in the Python
backend, which Pages cannot run.)

---

## The one idea

An AI assistant's *decisions cannot be trusted* once it has read attacker-controlled content. AMAN Gate
therefore enforces access control **in backend middleware on every retrieval and every tool call** —
independently of the model, of any UI toggle, and of any prompt-injection detector. The assistant may be
fully "convinced" by an injected instruction; the gateway still denies the unauthorized action because the
caller's **server-side role and the document's ACL** do not permit it.

Injection *detection* (an offline ML classifier) is present but **advisory only** — it is shown to analysts
and never changes an allow/deny decision.

---

## Quick start (3 commands)

Prerequisites: **Python 3.12** (or [`uv`](https://docs.astral.sh/uv/)) and **Node.js 18+**.

### Windows (PowerShell)
```powershell
git clone <this-repo> ; cd "AMAN Gate"
./scripts/setup.ps1      # venv + pinned deps + train model + build UI
./scripts/run.ps1        # serve at http://127.0.0.1:8000/
```

### Linux / macOS
```bash
git clone <this-repo> && cd "AMAN Gate"
chmod +x scripts/*.sh
./scripts/setup.sh && ./scripts/run.sh   # http://127.0.0.1:8000/
```

### Docker (optional)
```bash
docker compose up --build    # http://127.0.0.1:8000/
```

Open **http://127.0.0.1:8000/**, click a quick-login (e.g. *Ayesha Khan — Procurement Officer*), and press
**Run with AMAN Gate** on the Command Center. Demo password is shown on the login screen
(`Lab-Only-Demo-2026!`, nonproduction).

---

## What you can do

- **Command Center** — top strip (Demo Status, Runs, Denied Actions, Pending Approvals, Audit Integrity)
  and the split **AI Procurement Assistant** vs **AMAN Gate Security Decision** story.
- **Scenario Replay** — 10 selectable scenarios; identical input run through the baseline lab and through
  AMAN Gate side by side, with persisted run IDs and reason codes.
- **Policies** — the live tool allowlist, role matrix, destination allowlist and policy catalogue.
- **Document Access** — per-user ACL registry; open a document through the gateway and see allow/deny +
  advisory risk signals.
- **Approval Queue** — draft a summary, request a send, have a *different* finance manager approve, then
  execute once (replay refused).
- **Audit & Evidence** — HMAC-chain verification, the ML holdout metrics, a filterable event timeline, and a
  one-click evidence report (CSV/JSON export).

---

## Run the tests, benchmark and evidence yourself

From `backend/` with the venv active (`.venv\Scripts\python.exe` on Windows, `.venv/bin/python` on Linux):

```bash
python -m pytest                     # 83 security tests (ACL, IDOR, JWT, approvals, audit, injection, no-network)
python -m scripts.train_model        # train advisory classifier, writes ml_artifacts/metrics.json
python -m scripts.benchmark --calls 200   # latency, writes reports/benchmark_report.json
python -m scripts.generate_evidence  # runs all scenarios, writes reports/evidence_report.json + audit_chain.json
```

Real artifacts from this machine are committed under [`reports/`](reports/) and
[`backend/ml_artifacts/`](backend/ml_artifacts/). See [`docs/benchmark.md`](docs/benchmark.md) for the
measured numbers and the exact commands/commit.

---

## Roles & data

| Role | Can do | Cannot do |
|---|---|---|
| `procurement_officer` | read quotations, compare, draft, request send | read `BUDGET-SECRET-01` |
| `junior_clerk` | read quotations, compare | draft, send, read budget |
| `finance_manager` | everything above **+ read budget + approve sends** | approve its own request |
| `security_analyst` | read quotations/policy, view audit, reset demo | compare/draft/send |

Documents: `QUOTE-101` (clean), `QUOTE-102` (hidden injection), `BUDGET-SECRET-01` (restricted),
`POLICY-01` (workflow policy), plus fixtures `QUOTE-103..106` for encoded/Roman-Urdu and forbidden-tool
scenarios.

---

## Offline notes & limitations

- **Fully offline for the demo.** After setup, no internet is required; the app makes no outbound calls and
  a pytest guard (`tests/test_no_network.py`) fails if any non-local socket is opened.
- The only network access is **during setup** (downloading pinned Python/Node packages). For an air-gapped
  install, see [`docs/offline_packaging.md`](docs/offline_packaging.md).
- The ML classifier is **advisory** and trained on **synthetic** data; its perfect holdout score reflects
  templated synthetic separability and is **not** a real-world detection guarantee. The gateway never relies
  on it.
- Exact known limitations and the next-stage roadmap:
  [`docs/limitations_and_roadmap.md`](docs/limitations_and_roadmap.md).

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — security architecture & trust boundaries
- [`docs/threat_model.md`](docs/threat_model.md) — STRIDE-style threat model & mitigations
- [`DEMO_RUNBOOK.md`](DEMO_RUNBOOK.md) — 2-minute live demo / screen-capture sequence
- [`policy_examples/`](policy_examples/) — exported, enforced policies
- [`docs/deployment_checklist.md`](docs/deployment_checklist.md) — production hardening checklist

## License / usage

Educational security demonstration. Synthetic data only. Not for production use as-is.
