"""Provider connectors. LOCAL_SIMULATOR is the only one that produces output in this build.

  LOCAL_SIMULATOR  default. A deterministic responder inside this process (simulator.py). No socket, no file,
                   no model, no network library is imported anywhere in this package.
  LOCAL_LLM        optional on-device model. Stubbed off: it refuses, and no runtime is shipped.
  REAL_CLOUD       opt-in external provider. Disabled: it refuses, and no transport is shipped. Reaching it
                   would take (a) explicit configuration, (b) a destination on the exact-host allowlist
                   (egress.py), (c) an artifact prepared for an EXTERNAL destination, (d) a guard-approved
                   payload, and (e) someone writing and registering a transport in CONNECTORS. None of that
                   exists by default.

dispatch() is the only way to run a connector. It accepts nothing but an ApprovedPayload (issued by
guard.inspect_outbound), re-checks its digest, and refuses unless the egress decision allowed this exact mode.
A real transport registered here must still re-validate the destination against the allowlist at connect
time, pin the resolved address, refuse redirects, verify TLS and cap the response size.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from . import codes, simulator
from .config import ProviderMode
from .egress import EgressDecision
from .guard import ApprovedPayload


class ConnectorRefused(Exception):
    """The connector declined to run. `reasons` are reason codes, never content."""

    def __init__(self, reasons: Iterable[str]):
        self.reasons = tuple(dict.fromkeys(reasons))
        super().__init__(", ".join(self.reasons))


@dataclass(frozen=True)
class ConnectorResult:
    mode: ProviderMode
    response: str
    provider: str
    network: bool  # True if the answer came over a network
    watermark: bool = True  # the answer is AI-generated or simulated and unverified; the UI must say so


class Connector:
    mode: ProviderMode
    provider = "none"
    available = False  # whether this build can actually carry out the mode
    network = False

    def send(self, payload: ApprovedPayload, decision: EgressDecision) -> ConnectorResult:
        raise ConnectorRefused([codes.CONNECTOR_REFUSED])

    def describe(self) -> dict[str, object]:
        return {"mode": self.mode.value, "provider": self.provider, "available": self.available,
                "network": self.network}


class LocalSimulator(Connector):
    mode = ProviderMode.LOCAL_SIMULATOR
    provider = simulator.SIMULATOR_ID
    available = True

    def send(self, payload: ApprovedPayload, decision: EgressDecision) -> ConnectorResult:
        return ConnectorResult(self.mode, simulator.respond(payload.text), self.provider, network=False)


class LocalLLMStub(Connector):
    """Placeholder for an optional on-device model runtime. It always refuses."""

    mode = ProviderMode.LOCAL_LLM
    provider = "local-llm-stub"

    def send(self, payload: ApprovedPayload, decision: EgressDecision) -> ConnectorResult:
        raise ConnectorRefused([codes.LOCAL_LLM_RUNTIME_UNAVAILABLE])


class RealCloudStub(Connector):
    """Placeholder for the opt-in provider connector. It always refuses; this build has no transport."""

    mode = ProviderMode.REAL_CLOUD
    provider = "real-cloud-disabled"
    network = True

    def send(self, payload: ApprovedPayload, decision: EgressDecision) -> ConnectorResult:
        raise ConnectorRefused([codes.EGRESS_DEFAULT_DENY, codes.REAL_CLOUD_TRANSPORT_UNAVAILABLE])


CONNECTORS: dict[ProviderMode, Connector] = {
    ProviderMode.LOCAL_SIMULATOR: LocalSimulator(),
    ProviderMode.LOCAL_LLM: LocalLLMStub(),
    ProviderMode.REAL_CLOUD: RealCloudStub(),
}


def get_connector(mode: ProviderMode | str) -> Connector | None:
    try:
        return CONNECTORS.get(ProviderMode(mode))
    except ValueError:
        return None


def dispatch(payload: object, decision: EgressDecision) -> ConnectorResult:
    """Run the connector for an inspected payload under an allowing egress decision, or refuse."""
    if not isinstance(payload, ApprovedPayload):
        raise ConnectorRefused([codes.PAYLOAD_NOT_SAFE_ARTIFACT])
    if not payload.verify():
        raise ConnectorRefused([codes.ARTIFACT_DIGEST_MISMATCH])
    if not decision.allowed or decision.mode is not payload.mode:
        raise ConnectorRefused([codes.EGRESS_DEFAULT_DENY])
    connector = CONNECTORS.get(payload.mode)
    if connector is None or not connector.available:
        raise ConnectorRefused([codes.EGRESS_DEFAULT_DENY])
    return connector.send(payload, decision)
