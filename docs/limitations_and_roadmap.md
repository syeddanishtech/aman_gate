# AMAN Gate — Known Limitations & Roadmap

## Known limitations (explicit and honest)

1. **No real LLM is wired in.** `agent_sim.py` is a deterministic, scripted planner that models a *naive,
   vulnerable* tool-using assistant. This is intentional: it proves the protection does not depend on model
   behaviour. It does **not** prove anything about a specific commercial model's susceptibility.
2. **Injection detection is advisory and synthetic-trained.** The TF-IDF + logistic-regression classifier
   scores a leakage-free holdout of *templated synthetic* data perfectly; this reflects synthetic
   separability, **not** real-world accuracy. It is never load-bearing for an access decision. We make **no
   claim of universal injection detection.**
3. **Hash-chaining is tamper-evident, not tamper-proof.** An attacker holding the HMAC key *and* database
   write access could forge a consistent chain. Production needs a KMS-held key and external append-only
   (WORM) log shipping.
4. **SQLite + single-process serialization.** The audit chain uses an in-process lock; horizontal scaling
   needs a DB-level advisory lock (provided for PostgreSQL) and group-commit. The ~36 ms end-to-end latency
   is dominated by synchronous durable writes on a laptop, not by policy logic (~1.6 ms).
5. **Demo auth.** Seed users share a clearly-labelled nonproduction password and quick-login; there is no
   real IdP, MFA, password rotation or lockout. The app refuses these in `production` mode.
6. **No upload pipeline hardening beyond the demo.** Uploads are optional and size/type-limited; a
   production deployment needs AV scanning, content sandboxing and stronger parsing limits.
7. **Scope.** All data is synthetic and fictional; no real institution, supplier, person, SMTP, domain or
   exfiltration endpoint is involved. `*.test` is non-routable.

## Roadmap (next stages)

**Stage 1 — Production identity & storage**
- OIDC/SSO + MFA; per-user credentials; token revocation/rotation.
- PostgreSQL + Alembic migrations; KMS-held HMAC key; WORM audit shipping with periodic external
  verification.

**Stage 2 — Real agent integration**
- Adapter so an actual LLM/tool-runner proposes calls; the gateway stays the sole authority. Contract tests
  that fuzz model output against the enforcement boundary.
- Capability scoping / per-session least-privilege tokens for tools.

**Stage 3 — Detection maturity (still advisory)**
- Retrain on representative, human-labelled multilingual data with drift monitoring and calibrated
  thresholds; publish only held-out, leakage-checked metrics with confidence intervals.
- Add provenance/typed-content tagging so the gateway can apply stricter policy to text that originated in
  untrusted documents.

**Stage 4 — Enterprise operations**
- SIEM integration, anomaly alerting on denials/approvals/chain-verify, dashboards from the event store.
- Multi-tenant policy management UI (server-side, audited), approval workflows with delegation and
  escalation, and signed evidence exports.

**Stage 5 — Assurance**
- Independent pen-test of the direct API; threat-model refresh; formalise the policy as testable invariants;
  supply-chain hardening (hash-pinned builds, SBOM).
