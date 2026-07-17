from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone

from hwaam.models import AuthorizationRequest
from hwaam.policy import PolicyBundle
from hwaam.relationships import RelationshipGraph
from hwaam.trust import (
    Approval,
    DelegationHop,
    SecurityContext,
    sign_approval,
    sign_delegation_hop,
    sign_security_context,
)

ISSUER_SECRET = "test-issuer-secret"
TRUSTED_ISSUERS = ("identity-provider", "user:suresh", "approval-system")
ISSUED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)
FAR_FUTURE = datetime(2099, 12, 31, 23, 59, 59, tzinfo=timezone.utc)


def policy_data() -> dict:
    return {
        "version": "2026.07.16-test",
        "default_effect": "deny",
        "decision_ttl_seconds": 60,
        "cross_tenant_trust": [],
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
                "approver_roles": ["storage_admin"],
                "maximum_risk": 30,
                "obligations": ["record_privileged_session"],
            },
        },
    }


def signed_delegation_hop(
    *,
    issuer: str = "user:suresh",
    subject: str = "agent:change-assistant",
    principal_type: str = "ai_agent",
    tenant_id: str = "tenant-a",
    parent_delegation_id: str | None = None,
    delegation_id: str = "delegation-test-001",
    allowed_actions: tuple[str, ...] = ("snapshot.create",),
    resource_patterns: tuple[str, ...] = ("volume:prod-db-*",),
) -> dict:
    hop = DelegationHop(
        delegation_id=delegation_id,
        issuer=issuer,
        subject=subject,
        principal_type=principal_type,
        tenant_id=tenant_id,
        audience="hwaam-engine",
        parent_delegation_id=parent_delegation_id,
        allowed_actions=allowed_actions,
        resource_patterns=resource_patterns,
        issued_at=ISSUED_AT,
        expires_at=FAR_FUTURE,
        nonce=f"nonce-{delegation_id}",
    )
    return sign_delegation_hop(hop, ISSUER_SECRET)


def signed_security_context(
    *,
    subject_id: str = "user:suresh",
    risk_score: int = 20,
    device_compliant: bool = True,
    mfa: bool = True,
    issuer: str = "identity-provider",
    nonce: str = "nonce-context-001",
) -> dict:
    context = SecurityContext(
        subject_id=subject_id,
        issuer=issuer,
        risk_score=risk_score,
        device_compliant=device_compliant,
        mfa=mfa,
        issued_at=ISSUED_AT,
        expires_at=FAR_FUTURE,
        nonce=nonce,
    )
    return sign_security_context(context, ISSUER_SECRET)


def signed_approval(
    *,
    approver_id: str,
    approver_tenant_id: str = "tenant-a",
    approver_roles: tuple[str, ...] = ("storage_admin",),
    request_id: str = "req-001",
    action: str = "volume.delete",
    resource_id: str = "volume:prod-db-01",
    issuer: str = "approval-system",
    nonce: str | None = None,
) -> dict:
    approval = Approval(
        approver_id=approver_id,
        approver_tenant_id=approver_tenant_id,
        approver_roles=approver_roles,
        issuer=issuer,
        request_id=request_id,
        action=action,
        resource_id=resource_id,
        issued_at=ISSUED_AT,
        expires_at=FAR_FUTURE,
        nonce=nonce or f"nonce-approval-{approver_id}",
    )
    return sign_approval(approval, ISSUER_SECRET)


def request_data() -> dict:
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    return {
        "request_id": "req-001",
        "principal": {
            "principal_id": "user:suresh",
            "principal_type": "human",
            "tenant_id": "tenant-a",
            "roles": ["storage_operator"],
            "attributes": {},
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
        "delegation_chain": [signed_delegation_hop()],
        "context": {
            "requested_changes": 1,
            "output_destination": "internal-audit",
        },
        "security_context": signed_security_context(risk_score=20),
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
