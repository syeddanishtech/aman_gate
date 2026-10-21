"""End-to-end entry points: extract -> sanitize -> independent verification, fail closed.

Callers that hand text to an AI should use protect_text / protect_document, not sanitize_text alone: the
returned artifact is EXPORT_ALLOWED only if the verifier also passed. Verification failure turns the
artifact into EXPORT_BLOCKED (empty text) and records the verifier's findings.
"""
from __future__ import annotations

from dataclasses import replace

from .extract import extract_document
from .graph import BODY_KIND
from .policy import DEFAULT_POLICY, EXPORT_BLOCKED, PrivacyPolicy
from .sanitize import EMPTY_SHA256, SafeArtifact, blocked_artifact, sanitize_segments, sanitize_text
from .verify import verify_artifact


def finalize(artifact: SafeArtifact, policy: PrivacyPolicy = DEFAULT_POLICY) -> SafeArtifact:
    """Run the independent verifier over a sanitized artifact and fold its verdict into the record."""
    if not artifact.export_allowed:
        return artifact
    result = verify_artifact(artifact, artifact.source_graph, policy)
    rec = {**artifact.decision_record, "verification": result.to_record()}
    if result.passed:
        return replace(artifact, decision_record=rec)
    rec["export_status"] = EXPORT_BLOCKED
    rec["block_reasons"] = [*rec["block_reasons"], "VERIFICATION_FAILED"]
    rec["blocking_element_ids"] = sorted({f.element_id for f in result.findings if f.element_id})
    rec["artifact"] = {"sha256": EMPTY_SHA256, "chars": 0}
    return SafeArtifact(EXPORT_BLOCKED, "", EMPTY_SHA256, rec, source_graph=artifact.source_graph)


def protect_text(text: str, *, task: str, role: str, destination: str, policy: PrivacyPolicy = DEFAULT_POLICY,
                 locator: str = BODY_KIND, source_trust: str = "unknown") -> SafeArtifact:
    art = sanitize_text(text, task=task, role=role, destination=destination, policy=policy, locator=locator,
                        source_trust=source_trust)
    return finalize(art, policy)


def protect_document(data: bytes, filename: str | None = None, *, task: str, role: str, destination: str,
                     policy: PrivacyPolicy = DEFAULT_POLICY) -> SafeArtifact:
    """Local extraction of a .txt / .pdf / .docx, then sanitize and verify. Uploaded files are untrusted."""
    doc = extract_document(data, filename)
    if doc.review_required:
        return blocked_artifact(["EXTRACTION_REVIEW_REQUIRED"], task=task, role=role, destination=destination,
                                policy=policy, source_sha256=doc.source_sha256, extraction=doc.to_record())
    art = sanitize_segments(list(doc.segments),
                            task=task, role=role, destination=destination, policy=policy,
                            source_sha256=doc.source_sha256, source_trust="untrusted_external",
                            extraction=doc.to_record())
    return finalize(art, policy)


__all__ = ["finalize", "protect_text", "protect_document"]
