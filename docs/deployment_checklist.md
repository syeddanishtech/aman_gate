# AMAN Gate — Deployment Checklist (demo → hardened)

This prototype is a **local lab demo**. Before any non-demo use, complete every item below. The app already
refuses to start in `AMAN_ENV=production` with demo secrets or quick-login/baseline enabled.

## Secrets & identity
- [ ] Set `AMAN_ENV=production`.
- [ ] Set `AMAN_JWT_SECRET` and `AMAN_AUDIT_HMAC_KEY` to unique random values ≥ 32 chars, from a **KMS/HSM**
      — never the committed demo defaults (the app enforces this).
- [ ] Replace seed users + the shared demo password with a real IdP / SSO (OIDC) and per-user credentials;
      remove `/api/auth/demo-users` (auto-disabled when quick-login is off).
- [ ] Shorten `AMAN_JWT_TTL_SECONDS`; add refresh/rotation and token revocation.

## Data & storage
- [ ] Point `AMAN_DATABASE_URL` at PostgreSQL; run migrations (Alembic) instead of `create_all`.
- [ ] Apply the append-only audit controls for PostgreSQL (`REVOKE UPDATE,DELETE` / rules; see
      `docs/architecture.md §7`) and ship audit events to **external append-only/WORM storage**.
- [ ] Back up and test restore of the audit chain; store the HMAC key separately from the DB.

## Network & isolation
- [ ] Terminate TLS at a reverse proxy; set strict CORS to the real origin (demo allows localhost:5173).
- [ ] Enforce **egress controls** at the network layer (the app opens no sockets, but defence in depth).
- [ ] Rate-limit auth and tool endpoints; add request-size limits at the proxy.

## Policy & tools
- [ ] Re-derive the tool allowlist, role matrix, ACLs and destination allowlist for the real environment;
      keep them in the server-side policy store, never user-editable.
- [ ] Review the approval TTL and the two-person rule against real segregation-of-duties requirements.
- [ ] If a real LLM is integrated, keep its output as *untrusted input* to the gateway — no change to the
      enforcement boundary.

## Observability & ops
- [ ] Ship structured decision events to a SIEM; alert on DENY spikes, chain-verify failures, approval
      anomalies and repeated schema rejections.
- [ ] Add health/readiness probes and a `verify_chain` cron with alerting.
- [ ] Pen-test the direct API (not just the UI); re-run `pytest` in CI on every change.

## ML (optional, advisory)
- [ ] Treat the classifier as advisory only; do not let any score gate access.
- [ ] If used, retrain on representative (non-synthetic) labelled data with a held-out, leakage-checked set
      and monitor drift; never publish synthetic-holdout numbers as production accuracy.

## Build integrity
- [ ] Pin and verify dependencies (hashes); build from a clean checkout; record the commit in the evidence
      report (`docs/benchmark.md`).
