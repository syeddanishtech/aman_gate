# Policy examples

`policies.json` in this folder is **exported directly from the running policy engine**
(`backend/app/policy.py` via `python -m scripts.generate_evidence` / the `/api/policies` endpoint), so
it can never drift from what is actually enforced. The code is authoritative; this file is a readable
snapshot for reviewers.

## How a request is evaluated (fixed order, fails closed)

```
request (tool, args, server-side identity)
  │
  1. Tool allowlist ........ tool ∈ {read_document, compare_quotations, draft_purchase_summary,
  │                                  send_report}  else DENY UNKNOWN_TOOL
  │                          simulated_external_sink -> DENY TOOL_FORBIDDEN (never callable)
  2. RBAC .................. identity.role (read from DB) ∈ tool.allowed_roles  else DENY ROLE_NOT_PERMITTED
  3. Strict schema ......... Pydantic strict, extra=forbid, id patterns, depth/size caps  else DENY SCHEMA_INVALID
  4. Resource checks ....... per-document ACL / destination allowlist / report ownership   else DENY
  5. Approval gate ......... send_report -> NEEDS_APPROVAL (pending, bound to exact args)
  6. Side effect ........... only now, and only to a LOCAL simulator
```

The advisory ML + heuristic risk score is computed for evidence **after** the decision and never changes
it (`ADVISORY-RISK-v1`).

## Role → tool matrix

| Tool | procurement_officer | junior_clerk | finance_manager | security_analyst | Approval |
|---|---|---|---|---|---|
| `read_document` | ✓ (ACL) | ✓ (ACL) | ✓ (ACL) | ✓ (ACL) | — |
| `compare_quotations` | ✓ | ✓ | ✓ | — | — |
| `draft_purchase_summary` | ✓ | — | ✓ | — | — |
| `send_report` | ✓ | — | ✓ | — | finance_manager (two-person) |
| `simulated_external_sink` | — | — | — | — | always denied |

"✓ (ACL)" means the tool is permitted for the role, but each individual document is still checked against
its own ACL (e.g. only `finance_manager` has a read grant on `BUDGET-SECRET-01`).

## Document ACLs (server-side, not user-supplied)

| Document | Classification | Trust | Read grant |
|---|---|---|---|
| `QUOTE-101`, `QUOTE-102` (+ fixtures `QUOTE-103..106`) | supplier | untrusted_external | all four roles |
| `BUDGET-SECRET-01` | restricted | trusted_internal | finance_manager only |
| `POLICY-01` | internal | trusted_internal | all four roles |

## Destination allowlist

Only `finance-approvals@university.test` and `procurement-records@university.test` (local simulator).
`example.test` is **explicitly unapproved** and additionally flagged `DEST_EXPLICITLY_UNAPPROVED_DOMAIN`.
