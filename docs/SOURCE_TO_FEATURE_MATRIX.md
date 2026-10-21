# AMAN Gate 2.0 — Source → Feature Matrix

**Status:** Phase 0, 2026-10-21. Maps the three supplied sources to proposed features, priority and test.

**Note on the two PDF scans:** `llm security issues … .pdf` (13 pp) and `20 essential llm guardrails … .pdf`
(21 pp) are **image scans**. Content below is taken from the submitter's enumerated description and spot
verification; per the brief, **page 3 of the security scan is a promotional AI-interview page, not a control,
and is excluded.** The **guardrail list is a feature-idea catalogue, not evidence any filter guarantees
safety**; none is treated as an access boundary. Exact per-page OCR is a Phase-1 task if finer citation is
needed.

Priority: **P1** = competition MVP (Phase 1); **P2** = research quality (Phase 2); **P3** = stretch (Phase 3).
Status: **exists** (AMAN 1.0) / **new** / **partial**.

## Source 1 — "LLM security issues" (13 pp scan)

| Topic (source) | Proposed role in AMAN 2.0 | Priority | Status | Test |
|---|---|---|---|---|
| Direct prompt injection | Untrusted-content handling; advisory risk; deterministic policy unaffected | P1 | exists | `test_scenarios_and_injection.py` |
| Indirect injection (in documents/RAG) | PBDG taint on document content; action enforcement independent of model | P1 | exists→extend | S2/S8/S9 + new doc-sanitize tests |
| Data exfiltration | Destination allowlist + egress default-deny + outbound payload inspection | P1 | exists→extend | `test_tool_gateway.py`, new egress dry-run test |
| Jailbreak | Advisory detection only; never an access boundary | P2 | partial | risk tests |
| Unsafe tools / excessive agency | Tool allowlist, strict schema, RBAC, approvals | P1 | exists | `test_tool_gateway.py`, `test_approvals.py` |
| Training-data leakage | Out of scope (we don't train on real data); documented | P3 | n/a | — |
| Insecure output handling | Workstream B output assurance: re-scan model reply before display/export | P1 | new | new `test_output_assurance.py` |
| Retrieval poisoning | Taint on retrieved docs; provenance edges; action re-check | P2 | partial | new provenance tests |
| Model denial of service | Token/time budgets, circuit breaker, queue limits on connector | P2 | new | new connector tests |
| (p.3 AI-interview promo) | **Excluded — not a security control** | — | — | — |

## Source 2 — "20 essential LLM guardrails" (21 pp scan) — *idea catalogue only*

| Guardrail idea | Proposed role | Priority | Status | Test |
|---|---|---|---|---|
| Anti-injection | Advisory signal; policy is the boundary | P1 | exists | risk tests |
| PII detection | Workstream A detector component (Presidio + deterministic patterns + local NER) | P1 | new | `test_pii_detection.py` |
| Grounding / fact-check | Workstream B: flag ungrounded claims; require citations where possible | P2 | new | output-assurance tests |
| Toxicity / inappropriate content | Configurable, reviewable output check (not arbitrary censorship) | P2 | new | output-assurance tests |
| Contextual relevance / intent | Task-conditioning input to PBDG disclosure selection | P2 | new | disclosure tests |
| SQL/DB policy | N/A for procurement demo; documented as out-of-scope | P3 | n/a | — |
| Link / URL verification | Outbound + inbound link allowlist; no auto-fetch of doc links | P1 | new | egress tests |
| JSON schema | Already enforced on tool args (Pydantic strict) | P1 | exists | `test_tool_gateway.py` |
| Multilingual review | EN/Urdu/Roman-Urdu detectors + review (already in classifier) | P1 | partial | injection tests |
| Consistency / output quality | Output-assurance re-scan + placeholder integrity | P2 | new | output-assurance tests |
| **"Competitor shield"** | **Explicitly NOT implemented** — honesty over suppression (per brief) | — | — | — |

## Source 3 — "QSA_Algorithms_Explained.pptx" (6 slides) — crypto scope

| Slide | Content | Proposed role | Priority | Status |
|---|---|---|---|---|
| 1 | QSA intro: ML-KEM / HKDF / AES-GCM | Context only | — | — |
| 2 | Pipeline: agree secret → derive keys → encrypt | **At-rest token-vault encryption** = AES-256-GCM via vetted lib; HKDF-SHA256 for purpose-scoped keys | P1 | new |
| 3 | ML-KEM-768 key encapsulation (FIPS 203) | **Optional** gateway-to-gateway hybrid X25519+ML-KEM handshake | P3 | stretch |
| 4 | HKDF + AES-GCM (nonce rules, auth tag) | Enforce unique-nonce, per-purpose keys in the local vault | P1 | new |
| 5 | ML-KEM vs RSA/ECDH comparison | Justification doc for the optional PQC handoff | P3 | doc |
| 6 | Abbreviations (incl. DICOM/HL7 — medical origin) | Note: deck is medical-imaging-origin; reuse crypto *principles* only | — | — |

**Crypto honesty rule (from brief):** adding ML-KEM to *local storage* does **not** make prompts sent to a
public LLM "quantum-safe"; KEM alone does not authenticate peers. The competition-critical path uses standard
TLS 1.3 + AES-256-GCM at rest; the PQC handoff is a clearly-labelled Phase-3 stretch.

## PCC-26 submission materials (Downloads kit) — already drafted, keep honest
- `PCC26_AMAN_Gate_Abstract_500_Words.txt`, `…_Form_Answers.md`: conservative, no fabricated metrics.
  **2.0 must extend these without contradicting them** — the abstract already says "no benchmark results are
  claimed until tests have been executed and archived." Any new privacy-shield claim follows the same rule.
