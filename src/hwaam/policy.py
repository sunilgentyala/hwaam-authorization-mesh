"""Policy bundle loading and validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import json


@dataclass(frozen=True)
class ActionRequirement:
    """Additional controls applied to one action."""

    required_roles: tuple[str, ...] = ()
    required_attributes: dict[str, Any] = field(default_factory=dict)
    required_relationship: str | None = None
    minimum_approvals: int = 0
    approver_roles: tuple[str, ...] = ()
    maximum_risk: int = 100
    obligations: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ActionRequirement":
        maximum_risk = int(data.get("maximum_risk", 100))
        if not 0 <= maximum_risk <= 100:
            raise ValueError("maximum_risk must be between 0 and 100")
        return cls(
            required_roles=tuple(str(item) for item in data.get("required_roles", [])),
            required_attributes=dict(data.get("required_attributes", {})),
            required_relationship=(
                str(data["required_relationship"])
                if data.get("required_relationship") is not None
                else None
            ),
            minimum_approvals=int(data.get("minimum_approvals", 0)),
            approver_roles=tuple(str(item) for item in data.get("approver_roles", [])),
            maximum_risk=maximum_risk,
            obligations=tuple(str(item) for item in data.get("obligations", [])),
        )


@dataclass(frozen=True)
class TenantTrustPolicy:
    """An explicit, narrowly-scoped grant of cross-tenant access.

    Cross-tenant access is never enabled by a global switch. Each entry names
    the exact source tenant, destination tenant, resource pattern, required
    relationship, and action it authorizes.
    """

    source_tenant_id: str
    destination_tenant_id: str
    resource_pattern: str
    relationship: str
    action: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TenantTrustPolicy":
        return cls(
            source_tenant_id=str(data["source_tenant_id"]),
            destination_tenant_id=str(data["destination_tenant_id"]),
            resource_pattern=str(data["resource_pattern"]),
            relationship=str(data["relationship"]),
            action=str(data["action"]),
        )


@dataclass(frozen=True)
class PolicyBundle:
    """A deterministic, versioned authorization policy bundle."""

    version: str
    default_effect: str
    role_permissions: dict[str, tuple[str, ...]]
    action_requirements: dict[str, ActionRequirement]
    cross_tenant_trust: tuple[TenantTrustPolicy, ...] = ()
    decision_ttl_seconds: int = 60

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PolicyBundle":
        default_effect = str(data.get("default_effect", "deny")).lower()
        if default_effect != "deny":
            raise ValueError("HWAAM reference policies must default to deny")

        ttl = int(data.get("decision_ttl_seconds", 60))
        if ttl <= 0 or ttl > 3600:
            raise ValueError("decision_ttl_seconds must be between 1 and 3600")

        role_permissions = {
            str(role): tuple(str(action) for action in actions)
            for role, actions in data.get("role_permissions", {}).items()
        }
        action_requirements = {
            str(action): ActionRequirement.from_dict(requirement)
            for action, requirement in data.get("action_requirements", {}).items()
        }
        cross_tenant_trust = tuple(
            TenantTrustPolicy.from_dict(item)
            for item in data.get("cross_tenant_trust", [])
        )
        return cls(
            version=str(data["version"]),
            default_effect=default_effect,
            role_permissions=role_permissions,
            action_requirements=action_requirements,
            cross_tenant_trust=cross_tenant_trust,
            decision_ttl_seconds=ttl,
        )

    @classmethod
    def from_json_file(cls, path: str | Path) -> "PolicyBundle":
        with Path(path).open("r", encoding="utf-8") as handle:
            return cls.from_dict(json.load(handle))
