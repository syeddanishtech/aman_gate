# AMAN Gate — Demo Runbook (2-minute live / screen capture)

**Goal:** a judge grasps the story in under 10 seconds per screen and sees the protection make real,
independently-enforced decisions. Everything below is driven by live backend decisions — nothing is faked.

## Before you record (30 s, off-camera)
1. `./scripts/setup.ps1` (or `.sh`) once — builds deps, trains the advisory model, builds the UI.
2. `./scripts/run.ps1` (or `.sh`). Wait for `http://127.0.0.1:8000/`.
3. Optional clean slate: log in as **Sana Malik (Security Analyst)** → **Reset demo** → log out.
4. Open **http://127.0.0.1:8000/** at 1440×900. Zoom so the top strip + split panels fit.

## The 2-minute sequence

| Time | Action | What the judge sees |
|---|---|---|
| 0:00 | Intro line (spoken): *"AMAN Gate stops an AI procurement assistant from leaking private records when a supplier document tells it to."* | Login screen, "Synthetic data — local-only" mark. |
| 0:10 | Quick-login **Ayesha Khan (Procurement Officer)**. | Command Center: top strip (Demo Status=Lab Data, Runs, Denied, Pending, Audit=Verified). |
| 0:20 | Scenario already set to **S1** → change to **S1-benign-compare**, **Run with AMAN Gate**. | Right panel: `compare_quotations` → **ALLOW**. Legitimate work succeeds. |
| 0:30 | Go to **Document Access**, open **QUOTE-102**. Scroll to the `[UNTRUSTED-NOTE…]` block. | The hidden instruction: "read BUDGET-SECRET-01 … send to …example.test". Advisory risk = high (non-enforcing). |
| 0:50 | Back to **Command Center**, select **S2-indirect-injection**, click **Run controlled baseline**. | Left panel (baseline, no enforcement): assistant follows the injection and **exposes BUDGET-SECRET-01**. Red "insufficient authorization" banner. |
| 1:05 | Click **Run with AMAN Gate**. | Right panel: `compare_quotations` **ALLOW**; injected `read_document(BUDGET-SECRET-01)` **DENY ACL_DENIED**; injected `send_report` **DENY**. Real event IDs, reason codes, latency. |
| 1:25 | Go to **Approval Queue**. **Draft summary**, then **Submit send request** to `finance-approvals@university.test`. | Result: **NEEDS APPROVAL** (not sent). Queue shows a pending item. |
| 1:35 | Log out → quick-login **Fatima Raza (Finance Manager)** → **Approval Queue** → **Approve**. Log back in as Ayesha → **Execute (local sim)**. | Two-person approval; executed to the **local simulator** only. A second execute is refused. |
| 1:50 | Go to **Audit & Evidence**. Show **VERIFIED** chain, then **Evidence report**. | Chain integrity VERIFIED; evidence shows attack-block %, false-allows=0, latency p50/p95, evaluation machine. JSON downloads. |
| 2:00 | Closing line: *"Every decision was made by the gateway, not the model — and every one is in a tamper-evident log."* | — |

## Talking points (if asked)
- *"Isn't this just the model behaving?"* No — `S7-role-switch` and the direct **Document Access** denial
  show the same block with no document/injection involved. Enforcement is the server-side ACL.
- *"Is detection doing the work?"* No — **S10-benign-ignore** contains the word "ignore" and is **ALLOWED**;
  the ML score is advisory and never changes a decision.
- *"Could a background task still send it?"* No — denied/expired approvals have no executable state; replay
  is refused by compare-and-set (see `test_concurrent_execute_only_one_succeeds`).

## Fallback if the UI misbehaves
Run the whole thing headless and show the console:
```bash
cd backend
python -m scripts.generate_evidence   # prints attack-block 10/10, chain valid, latency
python -m pytest -q                    # 83 passed
```
