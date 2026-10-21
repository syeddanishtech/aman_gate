# AMAN Gate 2.0 — Prior Art & Novelty Analysis

**Status:** Phase 0 analysis, 2026-10-21. Honest working document. A web/literature search does **not**
establish patentability; this file exists to prevent over-claiming. Where evidence contradicts a novelty
claim, the claim is revised here rather than hidden.

## Method

Reviewed primary sources (arXiv abstracts/PDFs and official docs) with dates, plus the three supplied
scans/deck. Each competing method is summarised with what it *does* and what it *does not* cover, then
mapped to the proposed AMAN Gate 2.0 contribution (the Policy-Bound Disclosure Graph, "PBDG").

## Competing work (verified)

| Work | Date / venue | What it does | What it does **not** do |
|---|---|---|---|
| **Microsoft Presidio** | Mature OSS SDK | Text PII detection + anonymization; **image** PII via OCR+Tesseract (incl. DICOM); structured (pandas/JSON); has de-anonymization tools. Relies on ML — "no guarantee it finds all" (its own FAQ). | No **logo/emblem** detection; no **task-conditioning**; no provenance graph; no agent-action policy; not a release-decision engine. |
| **Casper** (arXiv:2408.07004, Aug 2024, NJIT) | CSCloud 2025 | Browser-extension, on-device 3-layer sanitizer (rules + NER + local-LLM topic); later version pseudonymizes. Text prompts. | Client-side extension, not a server-enforced gateway; text only; no multimodal/logo; no agent-tool enforcement; no provenance/rehydration vault with role checks. |
| **PAPILLON** (arXiv:2410.17127, NAACL 2025) | Columbia/Stanford/Databricks | "Privacy-Conscious Delegation": local model rewrites query → remote LLM → local adapts reply. 85.5% quality / 7.5% leakage on its **PUPA** benchmark. | Text only; redaction/delegation, not entity-consistent reversible pseudonyms; no document-level multimodal sanitization; no agent-action coupling. |
| **LOPSIDED** (arXiv:2510.27016, Oct 2025) | Serenari & Lee | Semantically-aware local pseudonymization: swaps entities for context-fitting pseudonyms, stores originals locally, reverses in output. ~5× semantic-utility improvement. | Conversational text (ShareGPT); no multimodal/logo; no provenance graph; no deterministic agent-action enforcement; no destination/approval control plane. |
| **CaMeL** (arXiv:2503.18813, Mar/Jun 2025, Google/DeepMind/ETH) | — | "Defeating Prompt Injections by Design": separates control/data flow; **capabilities track provenance** and enforce policy at tool calls via a custom interpreter. AgentDojo 77% w/ provable security vs 84% undefended. | Focused on injection-safe **tool use**, not document disclosure for cloud prompting; no multimodal document sanitization; no PII minimal-disclosure/rehydration. |
| **AgentDojo** (arXiv:2406.13352, 2024, ETH/Invariant) | — | Benchmark: 97 tasks / 629 security cases; stateful tool-use injection with formal state checks. | An evaluation framework, not a defense; not about document privacy/disclosure. |
| Commercial guardrails: **Prompt Shields** (Azure), **Bedrock Guardrails** (AWS), **NeMo Guardrails** (NVIDIA), **Lakera** | Productized | Injection/jailbreak detection, PII filters, topic/denied-topic controls, groundedness checks. | **Detection/filtering**, not independently-enforced ACL/tool authorization; generally cloud-coupled; not a provenance-carrying disclosure engine; detection scores are advisory, not an access boundary. |
| Standards: **OWASP LLM Top-10 2025**, **NIST AI RMF / AI 600-1**, **NIST FIPS 203** (ML-KEM) | — | Risk taxonomies & the PQC KEM standard. | Frameworks/standards, not a system; mapping tools, not certifications. |

## Known Already (we must NOT claim as novel)
- Local-sanitize-before-cloud-LLM with reversible pseudonyms recovered locally (Casper, PAPILLON, LOPSIDED).
- Text + image PII detection and de-anonymization primitives (Presidio).
- Provenance/capability-based injection defense that enforces policy at tool calls (CaMeL).
- Injection detection / guardrail filtering as advisory signals (commercial guardrails).
- Role-based access control, approval workflows, tamper-evident logs (classic security; already in AMAN 1.0).

## Proposed Combination (AMAN Gate 2.0)
A single **on-premises gateway** that unifies three strands that the literature treats separately:
1. **Multimodal, task-conditioned minimal disclosure** over a *document* (text spans, tables/cells, image/
   logo regions, metadata, hidden OCR/annotations) — not just a chat prompt — producing a *new* safe-export
   artifact verified by an independent second extractor.
2. **Provenance-carrying disclosure graph (PBDG)**: every element keeps a sensitivity label, source-trust,
   owner and provenance edges; the **same** taint labels flow into
3. **Deterministic agent-action enforcement** (ACL/tool/destination/approval) and **local-only,
   permission-bound rehydration** (role+purpose-scoped, encrypted token vault, no fuzzy recovery).

## Genuinely Testable Research Contribution (the honest claim)
> Does coupling (a) task-conditioned, provenance-carrying, **cross-format (incl. visual/logo)** minimal
> disclosure with (b) local-only permission-bound rehydration and (c) a **shared provenance/taint layer that
> also governs agent actions**, measurably reduce end-to-end document-privacy leakage **and** injection-driven
> exfiltration, versus (i) regex redaction, (ii) Presidio-style PII masking, (iii) PAPILLON/LOPSIDED-style
> text delegation, and (iv) detection-only guardrails — without unacceptable loss of legitimate task utility?

This is an **integration + measurement** contribution, evaluated on an open, reproducible, multimodal
benchmark. It is *not* claimed to be first-in-world, nor mathematically private, nor patentable on the basis
of this search.

## Overlap Risk (explicit)
- **High** overlap with LOPSIDED/PAPILLON/Casper on the reversible-pseudonym cloud-prompting idea → our
  differentiator must be the **multimodal + provenance + action-coupling + document-artifact verification**,
  not the pseudonym idea itself.
- **High** overlap with CaMeL on provenance-for-action → we reuse the principle and cite it; our addition is
  binding the same provenance to **disclosure decisions**, not only tool calls.
- **Medium** overlap with Presidio on detection primitives → we *use* Presidio-class detectors as components
  and must not rebrand them as novel AI.

## Evidence
arXiv abstracts/PDFs: [Presidio FAQ](https://microsoft.github.io/presidio/faq/),
[Casper](https://arxiv.org/abs/2408.07004), [PAPILLON](https://arxiv.org/abs/2410.17127),
[LOPSIDED](https://arxiv.org/abs/2510.27016), [CaMeL](https://arxiv.org/abs/2503.18813),
[AgentDojo](https://arxiv.org/abs/2406.13352), [OWASP LLM Top-10 2025](https://genai.owasp.org/llm-top-10/),
[NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final).

## Remaining Novelty Search (to do before any paper claim)
- Systematic search for "multimodal minimal disclosure" / "document release policy graph" / "provenance +
  rehydration" combinations (ACL Anthology, IEEE S&P, USENIX Security, PoPETs, 2024–2026).
- Patent search (USPTO/Espacenet) for disclosure-graph / policy-bound redaction before any IP claim.
- Confirm no existing system already couples document disclosure provenance with agent-action enforcement.
