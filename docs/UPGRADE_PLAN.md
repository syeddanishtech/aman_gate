# AMAN Gate 2.0 — Upgrade Plan (Phase 0 checkpoint)

**Date:** 2026-10-21 · **Baseline commit:** `b9315f9` (main) · **Baseline tests:** 83 passed (exit 0),
re-run 2026-10-21, unchanged. · **Product promise:** "Secure the data. Govern the AI. Verify every action."

This plan is **non-destructive**. Nothing in AMAN 1.0 is removed; 2.0 adds workstreams behind feature flags
and preserves every existing competition requirement and passing test.

## 1. Baseline inventory (what already exists and is tested)

| Capability | Where | Tested |
|---|---|---|
| Backend-enforced identity (JWT, role/tenant from DB) | `backend/app/security.py` | `test_auth.py` |
| Per-document ACL on every retrieval + tool path | `app/policy.py`, `app/gateway.py` | `test_access_control.py` |
| Tool allowlist, strict Pydantic schemas, RBAC | `app/policy.py`, `app/gateway.py` | `test_tool_gateway.py` |
| Destination allowlist (university.test only) | `app/policy.py` | `test_tool_gateway.py` |
| Approval state machine (2-person, expiry, idempotency, replay, race) | `app/gateway.py` | `test_approvals.py` |
| Append-only HMAC-chained audit log + verify | `app/audit.py` | `test_audit_chain.py` |
| Advisory injection classifier (TF-IDF+LogReg, leakage-free) | `app/ml/` | `test_ml_classifier.py` |
| 10 replay scenarios, baseline-vs-gated, persisted runs | `app/scenarios.py` | `test_scenarios_and_injection.py` |
| No-outbound-socket guarantee | — | `test_no_network.py` |
| React UI (6 tabs, split demo) | `frontend/src/` | `docs/ui_manual_checklist.md` |

**Gap vs 2.0 promise:** AMAN 1.0 governs *access and actions* but does **not** yet (a) sanitize a document
before an AI sees it, (b) offer a safe cloud-bridge with a local simulator, or (c) verify/clean model output.
These are the three new workstreams.

## 2. What 2.0 adds (behind flags; defaults preserve 1.0 + offline)
- **Workstream A — Document Privacy Shield:** local multimodal detection + a *new verified safe-export
  artifact* (text + redacted images), original stays local. Deterministic policy, advisory ML assist.
- **Workstream B — Safe Cloud Bridge:** `LOCAL_SIMULATOR` default (zero external calls), optional
  `LOCAL_LLM`, optional opt-in `REAL_CLOUD`; egress default-deny + outbound payload inspection; local-only,
  role+purpose-scoped rehydration from an encrypted token vault.
- **Workstream C — Lineage + output assurance:** taint labels from source→prompt→response→share; reviewable
  output checks (leak/groundedness/toxicity) — advisory, never an access boundary.
- **Workstream D — Crypto scope:** AES-256-GCM token vault at rest + HKDF-SHA256 (P1); optional hybrid
  X25519+ML-KEM-768 gateway handoff (P3 stretch only).

## 3. Phased work packages (Sonnet-ready, vertical slices, isolated)

> **Delegation note (honesty):** This session runs on a single Opus model. Independent "Sonnet 5.5" routing
> was **not** performed automatically. Each package below is written so it can be handed to a Sonnet
> implementer (separate session/worktree) or implemented directly; the Boss (Opus) reviews/merges. Packages
> that touch the same files run one-at-a-time.

### Phase 1 — Competition MVP
- **WP1 (P1): PBDG core + text/PDF/DOCX sanitizer (deterministic).** New `app/privacy/` module: disclosure
  graph model, sensitivity labels, deterministic detectors (regex PII + institution vocab), transformations
  (omit/generalize/pseudonymize/redact/deny), **new safe-export artifact**, independent second-extractor
  verification. Files: `app/privacy/*`, `app/models.py` (+tables), new tests. *No overlap with gateway.py.*
- **WP2 (P1): Safe Cloud Bridge + local simulator.** New `app/bridge/` connector: `LOCAL_SIMULATOR` default,
  egress default-deny, outbound schema + payload inspection, dry-run capture, `Simulation` watermark. Files:
  `app/bridge/*`, routes in `app/main.py`. Depends on WP1 artifact.
- **WP3 (P1): Output assurance + local rehydration vault.** Placeholder integrity, re-scan before display,
  AES-256-GCM token vault (HKDF-derived keys). Files: `app/privacy/vault.py`, `app/assurance/*`, tests.
- **WP4 (P1): UI — Protect Documents + Safe Cloud Bridge + Output Assurance tabs** + the two-pane
  "ORIGINAL — STAYS LOCAL / SAFE COPY — WHAT AI CAN SEE" hero and Judge Demo. Files: `frontend/src/tabs/*`.
- **WP5 (P1): Security QA** — egress dry-run, raw-PDF-after-redaction, hidden-DOCX, metadata/EXIF, canary,
  vault auth, rehydration authz, false-positive controls. Files: new `backend/tests/*`.

### Phase 2 — Research quality
- WP6 provenance graph + taint lineage end-to-end; WP7 task-conditioned minimization; WP8 image/OCR + logo
  review (local reference match/classifier + bounding-box review); WP9 responsible-output assurance
  (groundedness/toxicity, reviewable); WP10 multilingual eval + synthetic dataset (100+ docs) + benchmark
  harness + `research/RESEARCH_PLAN.md`.

### Phase 3 — Stretch
- WP11 hybrid X25519+ML-KEM-768 authenticated gateway handoff; WP12 optional real provider connector
  (opt-in, vaulted creds, egress constraints).

## 4. Exact first minimal implementation slice (WP1-slice-1)
**Goal:** a deterministic text sanitizer + disclosure record, end-to-end and tested, with **zero** UI/cloud
dependencies — the smallest honest increment that proves the PBDG approach.
1. `app/privacy/graph.py` — `DisclosureElement` (id, type, span, sensitivity, source_trust, provenance) and
   `DisclosureGraph`.
2. `app/privacy/detectors.py` — deterministic detectors for the synthetic corpus: emails, phones,
   CNIC-like synthetic IDs, account numbers, institution keywords, and the `LAB-CANARY-7731` canary.
3. `app/privacy/sanitize.py` — `sanitize_text(doc, task, role, destination, policy) -> SafeArtifact` applying
   omit/pseudonymize/redact/deny deterministically; returns artifact + versioned decision record + digest.
4. `app/privacy/verify.py` — independent second pass asserting no forbidden element survives in the artifact
   (fail-closed).
5. `backend/tests/test_privacy_sanitize.py` — canary never survives; benign finance text preserved; residual
   re-scan catches a planted secret; deterministic/replayable.

**Acceptance:** new tests pass **and** all 83 existing tests still pass; no network; no change to existing
files beyond additive model tables behind a migration/flag.

## 5. Integration gates (every slice)
Diff + executable tests + (for UI) screenshots + honest limitations → Opus red-team review → full regression
(`pytest`) → merge behind flag. No fabricated metrics; every UI number from persisted state. Default config
stays **offline** and preserves the AMAN 1.0 demo.
