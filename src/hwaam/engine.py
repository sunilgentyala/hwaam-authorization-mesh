"""Deterministic HWAAM authorization engine."""

from __future__ import annotations

from dataclasses import asdict
from datetime import timedelta
from fnmatch import fnmatch
import hashlib
import json
from typing import Any

from .models import AuthorizationRequest, Decision, utc_now
from .policy import PolicyBundle
from .relationships import RelationshipGraph
from .revocation import RevocationRegistry
from .receipts import sign_receipt


class AuthorizationEngine:
    """Evaluate resource, mission, delegation, and policy controls."""

    def __init__(
        self,
        policy: PolicyBundle,
        relationships: RelationshipGraph | None = None,
        revocations: RevocationRegistry | None = None,
    ) -> None:
        self.policy = policy
        self.relationships = relationships or RelationshipGraph()
        self.revocations = revocations or RevocationRegistry()

    def evaluate(
        self,
        request: AuthorizationRequest,
        receipt_secret: str,
    ) -> tuple[Decision, dict[str, Any]]:
        """Evaluate one request and return the decision and signed receipt."""
        now = utc_now()
        reasons: list[str] = []
        obligations: list[str] = []

        def deny(reason: str) -> tuple[Decision, dict[str, Any]]:
            reasons.append(reason)
            return self._finalize(
                request=request,
                effect="deny",
                reasons=reasons,
                obligations=obligations,
                now=now,
                receipt_secret=receipt_secret,
            )

        if self.revocations.is_principal_revoked(request.principal.principal_id):
            return deny("Principal is revoked")
        if self.revocations.is_mission_revoked(request.mission.mission_id):
            return deny("Mission is revoked")
        if self.revocations.is_resource_revoked(request.resource.resource_id):
            return deny("Resource is revoked")

        tenant_ids = {
            request.principal.tenant_id,
            request.resource.tenant_id,
            request.mission.tenant_id,
        }
        if len(tenant_ids) != 1 and not self.policy.allow_cross_tenant:
            return deny("Tenant closure check failed")

        if request.mission.expires_at <= now:
            return deny("Mission has expired")

        if request.action in request.mission.denied_actions:
            return deny("Action is explicitly denied by the mission")

        if request.action not in request.mission.allowed_actions:
            return deny("Action is outside the mission")

        if not any(
            fnmatch(request.resource.resource_id, pattern)
            for pattern in request.mission.resource_patterns
        ):
            return deny("Resource is outside the mission")

        if len(request.delegation_chain) > request.mission.max_delegation_depth:
            return deny("Delegation depth exceeds the mission limit")

        for hop in request.delegation_chain:
            if hop.tenant_id != request.mission.tenant_id:
                return deny("Delegation hop crosses the mission tenant")
            if request.action not in hop.allowed_actions:
                return deny("Delegation hop does not permit the action")
            if not any(
                fnmatch(request.resource.resource_id, pattern)
                for pattern in hop.resource_patterns
            ):
                return deny("Delegation hop does not permit the resource")

        requested_changes = int(request.context.get("requested_changes", 1))
        if requested_changes < 0:
            return deny("Requested change count cannot be negative")
        if requested_changes > request.mission.max_changes:
            return deny("Requested impact exceeds the mission limit")

        output_destination = request.context.get("output_destination")
        if output_destination is not None:
            if (
                request.mission.allowed_output_destinations
                and output_destination
                not in request.mission.allowed_output_destinations
            ):
                return deny("Output destination is outside the mission")

        if not self._role_allows(request.principal.roles, request.action):
            return deny("No assigned role grants the requested action")

        requirement = self.policy.action_requirements.get(request.action)
        if requirement is None:
            return deny("No action-specific policy is defined")

        if requirement.required_roles:
            if not set(requirement.required_roles).intersection(
                request.principal.roles
            ):
                return deny("Required action role is missing")

        for key, expected in requirement.required_attributes.items():
            actual = request.principal.attributes.get(key)
            if actual != expected:
                return deny(f"Required principal attribute failed: {key}")

        if requirement.required_relationship:
            if not self.relationships.check(
                request.principal.principal_id,
                requirement.required_relationship,
                request.resource.resource_id,
                request.resource.tenant_id,
            ):
                return deny("Required resource relationship is missing")

        approval_requirement = max(
            requirement.minimum_approvals,
            request.mission.required_approvals,
        )
        unique_approvals = {item for item in request.approvals if item}
        if len(unique_approvals) < approval_requirement:
            obligations.append(f"obtain_{approval_requirement}_approvals")

        risk_score = int(request.context.get("risk_score", 0))
        if risk_score < 0 or risk_score > 100:
            return deny("Risk score must be between 0 and 100")
        if risk_score > requirement.maximum_risk:
            obligations.append("step_up_authentication")

        obligations.extend(requirement.obligations)
        obligations = list(dict.fromkeys(obligations))

        if obligations:
            reasons.append("Mandatory controls passed, pending obligations")
            return self._finalize(
                request=request,
                effect="conditional_allow",
                reasons=reasons,
                obligations=obligations,
                now=now,
                receipt_secret=receipt_secret,
            )

        reasons.append("All mandatory authorization controls passed")
        return self._finalize(
            request=request,
            effect="allow",
            reasons=reasons,
            obligations=obligations,
            now=now,
            receipt_secret=receipt_secret,
        )

    def _role_allows(self, roles: tuple[str, ...], action: str) -> bool:
        for role in roles:
            permissions = self.policy.role_permissions.get(role, ())
            if action in permissions or "*" in permissions:
                return True
        return False

    def _finalize(
        self,
        request: AuthorizationRequest,
        effect: str,
        reasons: list[str],
        obligations: list[str],
        now,
        receipt_secret: str,
    ) -> tuple[Decision, dict[str, Any]]:
        expires_at = now + timedelta(seconds=self.policy.decision_ttl_seconds)
        digest_source = json.dumps(
            {
                "request_id": request.request_id,
                "principal_id": request.principal.principal_id,
                "action": request.action,
                "resource_id": request.resource.resource_id,
                "mission_id": request.mission.mission_id,
                "policy_version": self.policy.version,
                "timestamp": now.isoformat(),
            },
            sort_keys=True,
        ).encode("utf-8")
        evidence_id = hashlib.sha256(digest_source).hexdigest()[:24]

        decision = Decision(
            effect=effect,
            reasons=tuple(reasons),
            obligations=tuple(obligations),
            policy_version=self.policy.version,
            evidence_id=evidence_id,
            expires_at=expires_at,
        )

        receipt_payload = {
            "evidence_id": evidence_id,
            "request_id": request.request_id,
            "principal": {
                "principal_id": request.principal.principal_id,
                "principal_type": request.principal.principal_type,
                "tenant_id": request.principal.tenant_id,
            },
            "delegation_chain": [
                {
                    "principal_id": hop.principal_id,
                    "principal_type": hop.principal_type,
                    "tenant_id": hop.tenant_id,
                }
                for hop in request.delegation_chain
            ],
            "mission_id": request.mission.mission_id,
            "action": request.action,
            "resource_id": request.resource.resource_id,
            "resource_tenant": request.resource.tenant_id,
            "effect": effect,
            "reasons": list(reasons),
            "obligations": list(obligations),
            "policy_version": self.policy.version,
            "issued_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
        }
        return decision, sign_receipt(receipt_payload, receipt_secret)
