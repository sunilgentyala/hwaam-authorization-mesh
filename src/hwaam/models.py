"""Data models used by the HWAAM authorization engine."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def parse_timestamp(value: str | datetime) -> datetime:
    """Parse an ISO 8601 timestamp and normalize it to UTC."""
    if isinstance(value, datetime):
        parsed = value
    else:
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class Principal:
    """A human, workload, service account, agent, or tool identity."""

    principal_id: str
    principal_type: str
    tenant_id: str
    roles: tuple[str, ...] = ()
    attributes: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Principal":
        return cls(
            principal_id=str(data["principal_id"]),
            principal_type=str(data["principal_type"]),
            tenant_id=str(data["tenant_id"]),
            roles=tuple(str(item) for item in data.get("roles", [])),
            attributes=dict(data.get("attributes", {})),
        )


@dataclass(frozen=True)
class Resource:
    """A protected object and its tenant ownership."""

    resource_id: str
    resource_type: str
    tenant_id: str
    attributes: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Resource":
        return cls(
            resource_id=str(data["resource_id"]),
            resource_type=str(data["resource_type"]),
            tenant_id=str(data["tenant_id"]),
            attributes=dict(data.get("attributes", {})),
        )


@dataclass(frozen=True)
class MissionEnvelope:
    """A bounded purpose and impact contract for delegated work."""

    mission_id: str
    tenant_id: str
    purpose: str
    allowed_actions: tuple[str, ...]
    denied_actions: tuple[str, ...]
    resource_patterns: tuple[str, ...]
    expires_at: datetime
    max_delegation_depth: int = 0
    max_changes: int = 1
    required_approvals: int = 0
    allowed_output_destinations: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MissionEnvelope":
        return cls(
            mission_id=str(data["mission_id"]),
            tenant_id=str(data["tenant_id"]),
            purpose=str(data["purpose"]),
            allowed_actions=tuple(str(item) for item in data.get("allowed_actions", [])),
            denied_actions=tuple(str(item) for item in data.get("denied_actions", [])),
            resource_patterns=tuple(str(item) for item in data.get("resource_patterns", [])),
            expires_at=parse_timestamp(data["expires_at"]),
            max_delegation_depth=int(data.get("max_delegation_depth", 0)),
            max_changes=int(data.get("max_changes", 1)),
            required_approvals=int(data.get("required_approvals", 0)),
            allowed_output_destinations=tuple(
                str(item) for item in data.get("allowed_output_destinations", [])
            ),
        )


@dataclass(frozen=True)
class AuthorizationRequest:
    """A normalized authorization request.

    ``delegation_chain`` and ``approvals`` carry signed envelopes (issued by a
    delegator or an approval system, not the requester) and ``security_context``
    carries a signed envelope from a trusted identity/device/risk system. None
    of the three are parsed into trusted objects here — that requires a shared
    secret, which only the engine has, so verification happens in
    ``AuthorizationEngine.evaluate``.
    """

    request_id: str
    principal: Principal
    action: str
    resource: Resource
    mission: MissionEnvelope
    delegation_chain: tuple[dict[str, Any], ...] = ()
    context: dict[str, Any] = field(default_factory=dict)
    approvals: tuple[dict[str, Any], ...] = ()
    security_context: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuthorizationRequest":
        return cls(
            request_id=str(data["request_id"]),
            principal=Principal.from_dict(data["principal"]),
            action=str(data["action"]),
            resource=Resource.from_dict(data["resource"]),
            mission=MissionEnvelope.from_dict(data["mission"]),
            delegation_chain=tuple(
                dict(item) for item in data.get("delegation_chain", [])
            ),
            context=dict(data.get("context", {})),
            approvals=tuple(dict(item) for item in data.get("approvals", [])),
            security_context=(
                dict(data["security_context"])
                if data.get("security_context") is not None
                else None
            ),
        )


@dataclass(frozen=True)
class Decision:
    """The result returned by the HWAAM decision engine."""

    effect: str
    reasons: tuple[str, ...]
    obligations: tuple[str, ...]
    policy_version: str
    evidence_id: str
    expires_at: datetime

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["reasons"] = list(self.reasons)
        data["obligations"] = list(self.obligations)
        data["expires_at"] = self.expires_at.isoformat()
        return data
