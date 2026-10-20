"""Deterministic 'agent' simulator.

This is NOT a language model. It is a scripted planner that models how a naive tool-using assistant
would behave when supplier documents contain embedded instructions. It extracts instruction-like
directives from untrusted document text and turns them into proposed tool calls.

- In BASELINE mode the directives are executed against a separate, intentionally permissive lab
  executor (no ACL, no destination allowlist, no approval) to show the risk inside a sandbox.
- In GATED mode the very same proposed tool calls are submitted to the AMAN Gate gateway, which
  decides independently. The agent never gets to enforce anything.

The point of the demo is precisely that the protection does not depend on this planner being smart:
even an agent that fully 'falls for' the injection is stopped by server-side permissions.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .ml.normalize import normalize

_DOC_RE = re.compile(r'\b(?:read_document|read)\s*\(?\s*["\']?([A-Z][A-Z0-9-]{3,})["\']?', re.I)
_BUDGET_RE = re.compile(r'\b(BUDGET-SECRET-\d+)\b', re.I)
_SEND_RE = re.compile(r'\b(?:send_report|send|email|bhej|bhejo)\b[^\n]{0,80}?([a-z0-9._-]+@[a-z0-9.-]+)', re.I)
_SINK_RE = re.compile(r'\bsimulated_external_sink\b|\bexfiltrat|\bexternal sink\b', re.I)
_SHELL_RE = re.compile(r'\b(run_shell_command|export_all_records|rm\s+-rf)\b', re.I)


@dataclass
class ProposedCall:
    tool: str
    args: dict
    origin: str          # "user_task" or "document_injection:<doc_id>"
    rationale: str


@dataclass
class AgentPlan:
    proposed_calls: list[ProposedCall] = field(default_factory=list)
    followed_injection: bool = False
    injection_sources: list[str] = field(default_factory=list)


def plan_from_documents(user_calls: list[ProposedCall], docs: dict[str, str]) -> AgentPlan:
    """docs maps document_id -> raw content the agent has already (legitimately or not) seen."""
    plan = AgentPlan(proposed_calls=list(user_calls))
    for doc_id, content in docs.items():
        norm = normalize(content)
        found = False
        for m in _BUDGET_RE.finditer(norm):
            plan.proposed_calls.append(ProposedCall(
                "read_document", {"document_id": m.group(1).upper()}, f"document_injection:{doc_id}",
                "Document note instructed the assistant to open a restricted budget file."))
            found = True
        for m in _SEND_RE.finditer(norm):
            plan.proposed_calls.append(ProposedCall(
                "send_report", {"destination": m.group(1).lower(), "report_id": "RPT-INJECTED0000"},
                f"document_injection:{doc_id}",
                "Document note instructed the assistant to send data to an external address."))
            found = True
        if _SINK_RE.search(norm):
            plan.proposed_calls.append(ProposedCall(
                "simulated_external_sink", {"payload_summary": "<all documents the agent could read>"},
                f"document_injection:{doc_id}", "Document note instructed the assistant to exfiltrate data."))
            found = True
        if _SHELL_RE.search(norm):
            plan.proposed_calls.append(ProposedCall(
                "run_shell_command", {"command": "export_all_records"}, f"document_injection:{doc_id}",
                "Document note instructed the assistant to run an arbitrary command."))
            found = True
        if found:
            plan.followed_injection = True
            plan.injection_sources.append(doc_id)
    return plan
