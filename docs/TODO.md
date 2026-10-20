# AMAN Gate — Build checklist (final)

Status: `[x]` done and verified by running code.

## Environment observed (2026-10-20)
- Windows 11 Pro, Intel i7-1065G7, 8 logical CPUs, 15.8 GB RAM
- Python 3.12.13 (uv-managed); Node.js 24.20.0 (winget); Docker 29.8.1

## Phases
- [x] Phase 0 — architecture + trust boundaries documented; checklist written
- [x] Phase 1 — backend seed, auth (JWT), ACL, tool policy, approval state machine, HMAC audit chain
- [x] Phase 2 — polished React UI wired to backend (6 tabs, split demo view)
- [x] Phase 3 — 10 replay scenarios, baseline-vs-gated runner, persisted events/runs, metrics, reports
- [x] Phase 4 — 83 pytest security tests (all pass), scenario parity, UI visual QA
- [x] Phase 5 — demo artifacts generated from real runs (evidence, benchmark, audit chain, ML metrics)

## Verification evidence
- `python -m pytest` → **83 passed** (`backend/tests/`)
- `python -m scripts.train_model` → leakage-free holdout (n=156), metrics in `backend/ml_artifacts/`
- `python -m scripts.benchmark --calls 200` → `reports/benchmark_report.json` (policy p50 1.64 ms)
- `python -m scripts.generate_evidence` → attack-block 10/10, chain valid (43), `reports/`
- UI verified in-browser: Command Center split demo, Audit chain VERIFIED, Approval two-person flow

## Deliverables map
1. Source — `backend/`, `frontend/`
2. Docker + env + pinned deps — `Dockerfile`, `docker-compose.yml`, `.env.example`,
   `backend/uv.lock`, `backend/requirements*.txt`, `frontend/package-lock.json`
3. README (3-command start, Win/Linux, offline) — `README.md`, `docs/offline_packaging.md`
4. Security architecture — `docs/architecture.md`
5. Threat model — `docs/threat_model.md`
6. Policy examples — `policy_examples/`
7. Seeded data — `backend/app/seed.py`
8. Test suite — `backend/tests/`
9. Benchmark report (command/commit) — `docs/benchmark.md`, `reports/`
10. Demo runbook — `DEMO_RUNBOOK.md`
11. Deployment checklist — `docs/deployment_checklist.md`
12. Known limitations & roadmap — `docs/limitations_and_roadmap.md`
