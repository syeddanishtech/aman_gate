"""Privacy-shield policy: which transformation each finding gets. Deterministic, table-driven, fail closed.

Nothing here consults a model or the advisory risk score. The rules, in the order they are applied:

  1. R-DENY-TYPE        element type in `deny_types` (the canary tripwire)      -> DENY (export blocked)
  2. R-RESTRICTED-*     sensitivity RESTRICTED: LOCAL destination -> REDACT;
                        EXTERNAL or unknown destination -> DENY. RESTRICTED is never pseudonymized,
                        generalized or kept, whatever `type_actions` says.
  3. R-TYPE-<TYPE>      per-type override from `type_actions`
  4. R-SENS-<LEVEL>     default per sensitivity from `sensitivity_actions`
  5. R-UNKNOWN-FAILCLOSED  anything not covered above                           -> DENY

Pseudonymization replaces a finding with a stable per-document token such as [PERSON_01]. It is
reversible through a local table, so the output remains linkable personal data: it is a privacy
control, not a guarantee that no individual can be recognized. REDACT is irreversible: no table is kept.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Mapping

from .detectors import DEFAULT_VOCABULARY, DETECTOR_SET_VERSION, InstitutionVocabulary
from .graph import DisclosureElement

PRIVACY_POLICY_ID = "POL-PRIVACY-SHIELD-v1"
PRIVACY_POLICY_VERSION = "2026.10-wp1"
DECISION_RECORD_VERSION = "aman-privacy-decision-v1"

EXPORT_ALLOWED = "EXPORT_ALLOWED"
EXPORT_BLOCKED = "EXPORT_BLOCKED"

# Destinations that never leave the machine. Everything else (including unknown names) is EXTERNAL.
LOCAL_DESTINATIONS = frozenset({"local_simulator", "local_llm"})
# Same roles as app.policy.TOOLS; a role outside this set fails closed.
KNOWN_ROLES = frozenset({"procurement_officer", "junior_clerk", "finance_manager", "security_analyst"})

MAX_TEXT_CHARS = 2_000_000
MAX_TASK_CHARS = 200


class Action(str, Enum):
    KEEP = "KEEP"  # PUBLIC only
    OMIT = "OMIT"  # delete the span; leave no placeholder
    GENERALIZE = "GENERALIZE"  # replace by a category label: no identity, no linkage
    PSEUDONYMIZE = "PSEUDONYMIZE"  # type-preserving stable token, e.g. [ORG_01]; reversible locally
    REDACT = "REDACT"  # irreversible [REDACTED:TYPE]; nothing retained
    DENY = "DENY"  # block the whole export


# Token class used in [CLASS_NN]. Types not listed use the type name without underscores.
PSEUDONYM_CLASS: Mapping[str, str] = MappingProxyType({
    "EMAIL": "EMAIL", "PHONE": "PHONE", "NATIONAL_ID": "ID", "ACCOUNT_NUMBER": "ACCOUNT",
    "ORG": "ORG", "PERSON": "PERSON",
})

# Wording used by GENERALIZE. Types not listed use "[<type in lower case, spaces>]".
GENERALIZED_LABEL: Mapping[str, str] = MappingProxyType({
    "EMAIL": "[email address]", "PHONE": "[phone number]", "NATIONAL_ID": "[national id]",
    "ACCOUNT_NUMBER": "[account number]", "ORG": "[organization]", "PERSON": "[person]",
    "TOKEN_LOOKALIKE": "[placeholder-like text removed]",
})

_DEFAULT_TYPE_ACTIONS: Mapping[str, Action] = MappingProxyType({
    "PHONE": Action.GENERALIZE,  # phone numbers rarely matter to the task; linkage across them is a re-id aid
    "TOKEN_LOOKALIKE": Action.GENERALIZE,
})
_DEFAULT_SENSITIVITY_ACTIONS: Mapping[str, Action] = MappingProxyType({
    "PUBLIC": Action.KEEP,
    "INTERNAL": Action.PSEUDONYMIZE,
    "CONFIDENTIAL": Action.PSEUDONYMIZE,
})
# Segment kinds that are not part of the visible document. They are scanned, then omitted.
HIDDEN_CONTENT_KINDS = frozenset({"comments", "tracked_deletions", "hidden_text", "field_codes", "annotations",
                                  "custom_xml", "form_fields"})


def destination_class(destination: str) -> str:
    return "LOCAL" if isinstance(destination, str) and destination.strip().lower() in LOCAL_DESTINATIONS else "EXTERNAL"


@dataclass(frozen=True)
class PrivacyPolicy:
    policy_id: str = PRIVACY_POLICY_ID
    version: str = PRIVACY_POLICY_VERSION
    vocabulary: InstitutionVocabulary = DEFAULT_VOCABULARY
    type_actions: Mapping[str, Action] = field(default_factory=lambda: _DEFAULT_TYPE_ACTIONS)
    sensitivity_actions: Mapping[str, Action] = field(default_factory=lambda: _DEFAULT_SENSITIVITY_ACTIONS)
    deny_types: frozenset[str] = frozenset({"CANARY"})
    known_roles: frozenset[str] = KNOWN_ROLES
    block_on_hidden_content: bool = False  # True: comments / tracked deletions / hidden text -> EXPORT_BLOCKED
    max_chars: int = MAX_TEXT_CHARS

    def action_for(self, element: DisclosureElement, *, destination_class: str) -> tuple[Action, str]:
        """(action, rule id) for one finding. Total function: unknown inputs resolve to DENY."""
        if element.element_type in self.deny_types:
            return Action.DENY, "R-DENY-TYPE"
        if element.sensitivity == "RESTRICTED":
            if destination_class == "LOCAL":
                return Action.REDACT, "R-RESTRICTED-REDACT"
            return Action.DENY, "R-RESTRICTED-EXTERNAL"
        override = self.type_actions.get(element.element_type)
        if override is not None:
            return override, f"R-TYPE-{element.element_type}"
        default = self.sensitivity_actions.get(element.sensitivity)
        if default is not None:
            return default, f"R-SENS-{element.sensitivity}"
        return Action.DENY, "R-UNKNOWN-FAILCLOSED"

    def describe(self) -> dict:
        """Static description for records and docs. Contains no vocabulary terms."""
        return {
            "policy_id": self.policy_id,
            "policy_version": self.version,
            "detector_set": DETECTOR_SET_VERSION,
            "deny_types": sorted(self.deny_types),
            "type_actions": {k: v.value for k, v in sorted(self.type_actions.items())},
            "sensitivity_actions": {k: v.value for k, v in sorted(self.sensitivity_actions.items())},
            "restricted": {"LOCAL": Action.REDACT.value, "EXTERNAL": Action.DENY.value},
            "block_on_hidden_content": self.block_on_hidden_content,
        }


DEFAULT_POLICY = PrivacyPolicy()
