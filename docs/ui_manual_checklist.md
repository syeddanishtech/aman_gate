# AMAN Gate — UI Manual QA Checklist

Playwright E2E is not bundled (to keep the demo dependency-light and offline-friendly). Use this checklist
for manual UI verification; the backend behaviours it exercises are **also** covered by `pytest`
(`backend/tests/`). To add Playwright later: `npm i -D @playwright/test` and script the same steps.

## Setup
- [ ] `./scripts/run.ps1` (or `.sh`) running; open `http://127.0.0.1:8000/`.
- [ ] Login page shows the amber "Synthetic data — nonproduction" notice and 5 quick-login accounts.

## Auth & session
- [ ] Quick-login as Procurement Officer → lands on Command Center; header shows name + role chip.
- [ ] Sign out returns to login; refreshing the page keeps you logged in (session token).

## Command Center (the headline)
- [ ] Top strip shows Demo Status=Lab Data, Runs, Denied Actions (red), Pending Approvals (amber), Audit
      Integrity=Verified (teal).
- [ ] Select **S2-indirect-injection** → **Run with AMAN Gate**: right panel shows ALLOW (compare) + 2×DENY
      (budget read, send) with reason codes and event IDs.
- [ ] **Run controlled baseline**: left panel shows the assistant following the injection and exposing
      BUDGET-SECRET-01, with the red "insufficient authorization" banner.

## Scenario Replay
- [ ] All 10 scenarios listed; clicking one runs baseline+gated and shows the parity summary.
- [ ] S10-benign-ignore → gated shows **ALLOW** only (the word "ignore" does not trigger a denial).
- [ ] S7-role-switch → gated shows **DENY** (role re-checked server-side).

## Policies
- [ ] Tool table lists exactly 5 tools; `simulated_external_sink` has **no** allowed roles and sensitivity
      "forbidden".
- [ ] Destination allowlist shows the two `university.test` recipients only.

## Document Access
- [ ] As Procurement Officer: QUOTE-101/102 show "readable"; BUDGET-SECRET-01 shows a red ACL lock.
- [ ] Open QUOTE-102 → content shows the untrusted note; advisory risk band = high with signals listed.
- [ ] Open BUDGET-SECRET-01 → **DENY** card with `ACL_DENIED`, policy id and event id (no content shown).
- [ ] Log in as Finance Manager → BUDGET-SECRET-01 opens (ALLOW) and shows content.

## Approval Queue
- [ ] As Procurement Officer: **Draft summary** → a report id appears; **Submit send request** to a
      university.test address → **NEEDS APPROVAL**; pending item appears.
- [ ] Try destination `bids-review@example.test` → **DENY** message (unapproved destination).
- [ ] As Finance Manager (different user): **Approve** the pending item.
- [ ] Back as the requester: **Execute (local sim)** succeeds once; the item becomes executed.

## Audit & Evidence
- [ ] Chain integrity shows **VERIFIED** with event count and head HMAC.
- [ ] ML classifier panel shows precision/recall/FPR/F1 with the "advisory, leakage-free" note.
- [ ] Timeline filters (ALL/ALLOW/DENY/NEEDS APPROVAL + mode selector) change the rows.
- [ ] **Evidence report** button downloads JSON and shows attack-block %, false-allows=0, latency, machine.

## Responsiveness / visual
- [ ] At 1366 / 1440 / 1920 widths there is no horizontal page scroll; the split panels stack on narrow
      widths.
- [ ] Dark navy theme; teal=allow, amber=approval, red=deny are used consistently.
