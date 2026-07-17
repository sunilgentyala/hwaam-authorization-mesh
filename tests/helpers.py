from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone

from hwaam.models import AuthorizationRequest
from hwaam.policy import PolicyBundle
from hwaam.relationships import RelationshipGraph


def policy_data() -> dict:
    return {
        "version": "2026.07.16-test",
        "default_effect": "deny",
        "decision_ttl_seconds": 60,
        "allow_cross_tenant": False,
        "role_permissions": {
            "storage_operator": ["volume.read", "snapshot.create"],
            "storage_admin": [
                "volume.read",
                "snapshot.create",
                "volume.delete",
            ],
            "auditor": ["volume.read"],
        },
        "action_requirements": {
            "volume.read": {
                "required_roles": ["storage_operator", "storage_admin", "auditor"],
                "required_attributes": {"device_compliant": True},
                "required_relationship": "can_read",
                "minimum_approvals": 0,
                "maximum_risk": 80,
            },
            "snapshot.create": {
                "required_roles": ["storage_operator", "storage_admin"],
                "required_attributes": {"device_compliant": True},
                "required_relationship": "manages",
                "minimum_approvals": 0,
                "maximum_risk": 70,
            },
            "volume.delete": {
                "required_roles": ["storage_admin"],
                "required_attributes": {
                    "device_compliant": True,
                    "mfa": True,
                },
                "required_relationship": "manages",
                "minimum_approvals": 2,
                "maximum_risk": 30,
                "obligations": ["record_privileged_session"],
            },
        },
    }


def request_data() -> dict:
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    return {
        "request_id": "req-001",
        "principal": {
            "principal_id": "user:suresh",
            "principal_type": "human",
            "tenant_id": "tenant-a",
            "roles": ["storage_operator"],
            "attributes": {
                "device_compliant": True,
                "mfa": True,
            },
        },
        "action": "snapshot.create",
        "resource": {
            "resource_id": "volume:prod-db-01",
            "resource_type": "storage_volume",
            "tenant_id": "tenant-a",
            "attributes": {"environment": "production"},
        },
        "mission": {
            "mission_id": "mission-change-001",
            "tenant_id": "tenant-a",
            "purpose": "Create one approved protection snapshot",
            "allowed_actions": ["snapshot.create"],
            "denied_actions": ["volume.delete"],
            "resource_patterns": ["volume:prod-db-*"],
            "expires_at": expires.isoformat(),
            "max_delegation_depth": 1,
            "max_changes": 1,
            "required_approvals": 0,
            "allowed_output_destinations": ["internal-audit"],
        },
        "delegation_chain": [
            {
                "principal_id": "agent:change-assistant",
                "principal_type": "ai_agent",
                "allowed_actions": ["snapshot.create"],
                "resource_patterns": ["volume:prod-db-*"],
                "tenant_id": "tenant-a",
            }
        ],
        "context": {
            "risk_score": 20,
            "requested_changes": 1,
            "output_destination": "internal-audit",
        },
        "approvals": [],
    }


def build() -> tuple[PolicyBundle, RelationshipGraph, AuthorizationRequest]:
    policy = PolicyBundle.from_dict(policy_data())
    graph = RelationshipGraph()
    graph.add("user:suresh", "manages", "volume:prod-db-01", "tenant-a")
    graph.add("user:suresh", "can_read", "volume:prod-db-01", "tenant-a")
    request = AuthorizationRequest.from_dict(request_data())
    return policy, graph, request


def clone_request_data() -> dict:
    return deepcopy(request_data())
