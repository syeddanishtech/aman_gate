# AMAN Gate — Threat Model

Scope: a tool-using AI procurement assistant operating over untrusted supplier documents, fronted by the
AMAN Gate enforcement middleware. All data is synthetic; the system is local-only.

## Assets
- **A1** Restricted internal records (e.g. `BUDGET-SECRET-01`, procurement ceiling / canary).
- **A2** Integrity of tool actions (no unauthorized send/exfiltration/command).
- **A3** Audit evidence (trustworthy, tamper-evident decision log).
- **A4** Identity/authorization integrity (roles, tenants, approvals).

## Actors / entry points
- Authenticated users (4 roles) via the API.
- **Untrusted document content** reaching the assistant (the primary attack surface — indirect injection).
- Direct API clients (bypassing the UI).
- A malicious insider attempting privilege escalation or self-approval.

## Trust assumptions
- The HMAC key and JWT secret are secret (in the demo they are clearly-marked nonproduction defaults; the
  app refuses to start in `production` with demo secrets or <32-char keys).
- The host and database are not already fully compromised (if an attacker holds the HMAC key and DB write
  access, tamper-evidence degrades to detection-by-external-copy — see A3 residual risk).

## STRIDE analysis

### Spoofing
- **T-S1 Forged/ްunsigned JWT, alg=none, algorithm confusion.** → HS256 pinned, signature + `iss/aud/exp`
  required. Tests: `test_alg_none_forgery_rejected`, `test_wrong_secret_forgery_rejected`.
- **T-S2 Token with elevated `role` claim.** → Role is re-read from DB; token role is display-only. Test:
  `test_role_claim_in_token_does_not_escalate`.

### Tampering
- **T-T1 Malicious tool arguments** (SQLi-ish ids, path traversal, type confusion, extra fields, deeply
  nested / oversized JSON). → Strict Pydantic schemas + depth/size caps *before* parsing. Tests in
  `test_tool_gateway.py`, `test_access_control.py`.
- **T-T2 Audit log edited/deleted/reordered.** → Append-only triggers + HMAC chain; `verify_chain` detects
  it. Tests: `test_mutation_detected`, `test_deletion_detected`, `test_append_only_trigger_blocks_update`.
- **T-T3 ACL escalation via user-supplied document metadata.** → ACLs live in a separate server-only table;
  uploads/metadata never grant access.

### Repudiation
- **T-R1 "I didn't do that".** → Every decision (allow/deny/approval/execute) is an immutable audit event
  with actor, role, resource ids, policy id, reason codes, timestamp and chained HMAC.

### Information disclosure
- **T-I1 Indirect prompt injection**: a quote tells the assistant to read the budget and email it out
  (`QUOTE-102`, `QUOTE-105`, `QUOTE-106`). → The assistant may comply, but the gateway denies the budget
  read (ACL) and the external send (destination allowlist). Scenarios S2/S8/S9; tests
  `test_injection_scenarios_block_every_injected_call`.
- **T-I2 IDOR / cross-tenant read.** → Canonical resource ids; cross-tenant == not-found
  (`RESOURCE_NOT_ACCESSIBLE`). Test: `test_idor_cross_tenant_document_hidden`.
- **T-I3 Direct unauthorized retrieval** (officer/clerk reads budget). → ACL denies on both the UI route and
  the tool path. Tests: `test_officer_cannot_read_budget`, `test_clerk_cannot_read_budget`.
- **T-I4 Content leakage into logs / tool output.** → Audit stores ids/hashes only; generic tool output
  strips content; sink previews are redacted and the canary is scrubbed. Tests:
  `test_no_restricted_content_in_audit`, `test_tool_output_never_contains_document_content`.
- **T-I5 Exfiltration to a disallowed destination.** → Destination allowlist (university.test only);
  `example.test` explicitly unapproved. Scenario S4; `test_send_to_unapproved_destination_denied`.

### Denial of service / abuse
- **T-D1 Oversized/nested payloads.** → Size (8 KiB) and depth (4) caps reject before heavy parsing.
- **T-D2 Approval expiry / replay / race.** → TTL expiry, idempotency, atomic single execution. Tests in
  `test_approvals.py`.

### Elevation of privilege
- **T-E1 Role switch without privilege** (clerk attempts budget). → Server-side role check. Scenario S7.
- **T-E2 Self-approval of a sensitive send.** → Two-person rule. Test: `test_requester_cannot_self_approve`.
- **T-E3 Forbidden-tool invocation from a compromised doc** (`simulated_external_sink`,
  `run_shell_command`). → Sink always denied; unknown tool names denied; no free-form execution. Scenario
  S9; `test_external_sink_always_forbidden`, `test_unknown_tool_denied`.

## Explicitly out of scope / residual risk
- A real LLM is **not** integrated; `agent_sim.py` deterministically models a *vulnerable* assistant to
  demonstrate that enforcement does not depend on model behaviour. Integrating a real model does not change
  the trust boundary (its output stays untrusted input to the gateway).
- Injection **detection** is advisory and synthetic-trained; it is not relied upon and makes no universal
  accuracy claim (`docs/limitations_and_roadmap.md`).
- Hash-chaining is tamper-**evident**, not tamper-**proof**: an attacker with the HMAC key *and* DB write
  access could forge a consistent chain. Mitigation in production: KMS-held key + append-only external log
  shipping (WORM). Stated in `docs/architecture.md §7`.
- Network egress is prevented by design in the demo (local simulators) and asserted by
  `tests/test_no_network.py`; a production deployment would additionally enforce egress controls at the
  network layer.

## Non-security-but-honesty notes
- No fabricated metrics. Every badge/number in the UI derives from persisted decision events or runs; the
  evidence report states denominators and the evaluation machine. "Attack-block %" counts ground-truth
  attack attempts (injected tool calls + unauthorized-by-design user requests) actually executed.
