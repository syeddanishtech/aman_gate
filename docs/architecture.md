# AMAN Gate — Security Architecture

## 1. Goal and principle

Prevent an AI assistant from accessing unauthorized records or executing unauthorized tool actions in
response to malicious instructions embedded in untrusted content.

**Core principle:** *the model's output is untrusted input to the gateway.* Authorization is decided by
deterministic backend middleware using a **server-side trusted identity** and **server-side ACLs/policies**,
on **every** retrieval and **every** tool execution. No LLM decision, no frontend toggle, and no
injection-detection score is ever load-bearing for an access decision.

## 2. Components

```
  React UI (Vite/TS)            ── all state comes from backend decisions; renders only
      │  bearer JWT (proves user id only)
      ▼
  FastAPI app  (backend/app/main.py)
      │
      ├─ security.py   Auth: JWT verify (alg pinned HS256), role/tenant RE-READ from DB each request
      ├─ gateway.py    Enforcement core: execute_tool() — allowlist→RBAC→schema→ACL/dest/owner→approval→effect
      │                 approval state machine (requested/pending/approved/denied/expired/executed)
      ├─ policy.py     Deterministic policy: tool specs, strict Pydantic arg models, ACL/destination checks
      ├─ agent_sim.py  Scripted (non-LLM) planner that models a naive tool-using assistant
      ├─ scenarios.py  Baseline-lab (no enforcement, safe/local) vs gated runner; persisted runs
      ├─ audit.py      Append-only, HMAC-SHA256-chained event log; verify_chain()
      ├─ ml/           Advisory risk: TF-IDF + LogisticRegression + interpretable heuristics (non-enforcing)
      └─ metrics.py    Evidence from persisted events/runs (honest denominators)
      │
      ▼
  SQLite (demo) / PostgreSQL-ready  — ACLs, approvals, runs, local outbox & sink simulators, audit chain
```

## 3. Trust boundaries

| # | Boundary | Trust | Control |
|---|---|---|---|
| B1 | UI → API | UI is untrusted | Every request authenticated; UI never carries an authorization bit |
| B2 | JWT → authorization | token proves **user id** only | Role & tenant re-read from DB; `role_hint` claim is display-only |
| B3 | Document content → agent | **untrusted_external** | Instructions inside documents are never executed; gateway re-checks every proposed call |
| B4 | Agent → tool gateway | agent is untrusted | `execute_tool` decides; agent cannot enforce or bypass |
| B5 | Gateway → side effects | — | Effects only to local `sim_outbox` / `sim_sink` tables; no sockets |
| B6 | Audit store | integrity-critical | Append-only (DB triggers) + HMAC chain; key from environment |

## 4. Enforcement order (fails closed)

`execute_tool()` applies, in order and short-circuiting on the first failure:

1. **Tool allowlist** — only 4 callable tools; `simulated_external_sink` is registered but always denied;
   any other name → `UNKNOWN_TOOL`. No free-form tool execution.
2. **RBAC** — `identity.role` (from DB) must be in the tool's allowed roles.
3. **Strict schema** — Pydantic v2 `strict=True, extra='forbid'`, canonical id regexes, JSON depth ≤ 4 and
   size ≤ 8 KiB (checked *before* parsing). Blocks traversal ids, nested-payload abuse, type confusion.
4. **Resource checks** — per-document ACL (canonical resource id; cross-tenant == not-found), destination
   allowlist, report ownership + classification.
5. **Approval gate** — `send_report` never executes inline; it creates a `pending` approval bound to a hash
   of the exact arguments.
6. **Side effect** — only now, and only against a local simulator.

The advisory risk score is computed **after** the decision (for evidence) and cannot alter it.

## 5. Identity & authorization

- JWT signed HS256, `algorithms=["HS256"]` pinned (rejects `alg=none` and algorithm confusion), with
  `iss`/`aud`/`exp` required and verified.
- The token's `sub` (user id) is the *only* trusted claim. `role`, `tenant`, and permissions are looked up
  from the `users` table on every request, so a forged/extra claim cannot escalate privilege.
- ACLs live in a dedicated `document_acl` table keyed by `role:<role>` / `user:<id>` principals. Document
  metadata supplied by users (e.g. uploads) can never add ACL grants.

## 6. Approval state machine

```
 requested/pending ──approve(diff finance_manager)──▶ approved ──execute(requester, once)──▶ executed
        │                                                  │
        ├── deny ───────────────▶ denied                  └── replay/2nd execute ─▶ 409 ALREADY_EXECUTED
        └── TTL elapsed ────────▶ expired                 (compare-and-set UPDATE … WHERE status='approved')
```

- **Two-person rule:** the requester cannot approve their own send (`SELF_APPROVAL_BLOCKED`).
- **Idempotency:** identical (requester, args) returns the existing pending approval — no duplicates.
- **Replay/race safety:** execution is an atomic compare-and-set; concurrent executes yield exactly one
  success (test: `test_concurrent_execute_only_one_succeeds`).
- **Background safety:** a denied/expired approval has no `approved` row to transition, so no task can later
  perform it.

## 7. Audit trail

- Append-only `audit_events` table (SQLite `BEFORE UPDATE/DELETE` triggers; the PostgreSQL equivalent is a
  revoke + rule, see below).
- Each row stores a canonical JSON of the signed fields plus `prev_hash`, and `record_hmac =
  HMAC-SHA256(key, canonical(record))`. `prev_hash` chains to the previous row's HMAC (genesis = 64 zeros).
- `verify_chain()` recomputes every HMAC and checks `prev_hash` linkage and sequence continuity; it reports
  the first bad sequence on tamper.
- **No protected content is ever logged.** Audit records store resource **ids**, reason codes and hashes —
  never document bodies. A test asserts the budget canary never appears in any export.
- **Honest scope:** the chain is *tamper-evident* against row edits/deletes/reordering by anyone without the
  HMAC key. It is **not** a substitute for external WORM storage, an HSM/KMS-protected key, or off-host log
  shipping. In production the key lives in a KMS and events are mirrored to append-only storage.

PostgreSQL append-only equivalent:
```sql
REVOKE UPDATE, DELETE ON audit_events FROM app_role;
-- or a rule: CREATE RULE audit_no_update AS ON UPDATE TO audit_events DO INSTEAD NOTHING;
-- chain serialization: SELECT pg_advisory_xact_lock(hashtext('aman_audit'));
```

## 8. Advisory ML risk (non-enforcing)

- TF-IDF (word 1–2gram + char_wb 3–5gram) → LogisticRegression, trained on a **versioned synthetic** dataset
  with a **group-aware, leakage-free** train/holdout split (template variants never cross the split).
- Normalisation undoes evasion (NFKC, zero-width/bidi stripping, dash & homoglyph folding, base64 decoding)
  so detectors and the naive agent see the same text.
- Interpretable heuristics (override phrases, AI-addressing, tool-invocation, restricted-resource mentions,
  external destinations, secrecy, encoding markers) supplement the model in English/Urdu/Roman-Urdu.
- Output is a band (low/medium/high) + signals, surfaced in the UI and audit `risk` field. It **never**
  changes a decision — proven by `test_risk_is_advisory_only_never_enforces`.

## 9. The baseline lab (why it is safe)

The baseline is a deliberately **insufficient** authorization simulation used only to show risk inside a
sandbox: it reads documents with no ACL, "sends" to a local outbox and records to a local sink. It opens no
sockets, touches no real files, and never emits restricted content (sink previews are redacted, canary
stripped). The protected (gated) path only ever calls `execute_tool` / the approval lifecycle, so it can
never inherit a baseline bypass.

## 10. Data model (tables)

`tenants, users, documents, document_acl, reports, approvals, idempotency, sim_outbox, sim_sink, runs,
audit_events`. SQLite for the demo; all access is through portable SQLAlchemy ORM so a PostgreSQL URL works
unchanged (`AMAN_DATABASE_URL`).
