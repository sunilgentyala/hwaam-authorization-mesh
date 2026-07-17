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
from .trust import verify_approval, verify_delegation_hop, verify_security_context

ENGINE_AUDIENCE = "hwaam-engine"


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
        *,
        issuer_secret: str,
        trusted_issuers: tuple[str, ...] = (),
        receipt_key_id: str = "default",
    ) -> tuple[Decision, dict[str, Any]]:
        """Evaluate one request and return the decision and signed receipt.

        ``receipt_secret`` signs the engine's own output receipt.
        ``issuer_secret`` verifies signed objects the engine did not create
        itself (security context, approvals, delegation hops) — these come
        from external trusted issuers, so they use a separate key.
        """
        now = utc_now()
        reasons: list[str] = []
        obligations: list[str] = []
        verified_hops: list = []

        def deny(reason: str) -> tuple[Decision, dict[str, Any]]:
            reasons.append(reason)
            return self._finalize(
                request=request,
                effect="deny",
                reasons=reasons,
                obligations=obligations,
                verified_hops=verified_hops,
                now=now,
                receipt_secret=receipt_secret,
                receipt_key_id=receipt_key_id,
            )

        if self.revocations.is_principal_revoked(request.principal.principal_id):
            return deny("Principal is revoked")
        if self.revocations.is_mission_revoked(request.mission.mission_id):
            return deny("Mission is revoked")
        if self.revocations.is_resource_revoked(request.resource.resource_id):
            return deny("Resource is revoked")

        if request.mission.tenant_id != request.principal.tenant_id:
            return deny("Mission tenant does not match the principal tenant")
        if request.resource.tenant_id != request.principal.tenant_id:
            if not self._cross_tenant_authorized(request):
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

        previous_subject = request.principal.principal_id
        previous_delegation_id: str | None = None
        for envelope in request.delegation_chain:
            hop = verify_delegation_hop(
                envelope,
                issuer_secret,
                audience=ENGINE_AUDIENCE,
                trusted_issuers=trusted_issuers,
                now=now,
            )
            if hop is None:
                return deny(
                    "Delegation hop failed signature, freshness, or audience verification"
                )
            if self.revocations.is_delegation_revoked(hop.delegation_id):
                return deny("Delegation hop has been revoked")
            if hop.issuer != previous_subject:
                return deny("Delegation hop issuer does not match the prior delegator")
            if hop.parent_delegation_id != previous_delegation_id:
                return deny("Delegation hop does not chain to its parent")
            if hop.tenant_id != request.mission.tenant_id:
                return deny("Delegation hop crosses the mission tenant")
            if request.action not in hop.allowed_actions:
                return deny("Delegation hop does not permit the action")
            if not any(
                fnmatch(request.resource.resource_id, pattern)
                for pattern in hop.resource_patterns
            ):
                return deny("Delegation hop does not permit the resource")
            previous_subject = hop.subject
            previous_delegation_id = hop.delegation_id
            verified_hops.append(hop)

        requested_changes = int(request.context.get("requested_changes", 1))
        if requested_changes < 0:
            return deny("Requested change count cannot be negative")
        if requested_changes > request.mission.max_changes:
            return deny("Requested impact exceeds the mission limit")

        if request.mission.allowed_output_destinations:
            output_destination = request.context.get("output_destination")
            if (
                output_destination is None
                or output_destination not in request.mission.allowed_output_destinations
            ):
                return deny(
                    "Output destination is required and must be within the mission"
                )

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

        security_context = verify_security_context(
            request.security_context,
            issuer_secret,
            subject_id=request.principal.principal_id,
            trusted_issuers=trusted_issuers,
            now=now,
        )

        for key, expected in requirement.required_attributes.items():
            if key in ("device_compliant", "mfa"):
                actual = getattr(security_context, key) if security_context else None
            else:
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
        disqualified_approvers = {request.principal.principal_id, previous_subject}
        allowed_approver_roles = requirement.approver_roles or requirement.required_roles
        verified_approvers: set[str] = set()
        for envelope in request.approvals:
            approval = verify_approval(
                envelope,
                issuer_secret,
                request_id=request.request_id,
                action=request.action,
                resource_id=request.resource.resource_id,
                resource_tenant_id=request.resource.tenant_id,
                trusted_issuers=trusted_issuers,
                now=now,
            )
            if approval is None:
                continue
            if approval.approver_id in disqualified_approvers:
                continue
            if allowed_approver_roles and not set(approval.approver_roles).intersection(
                allowed_approver_roles
            ):
                continue
            verified_approvers.add(approval.approver_id)
        if len(verified_approvers) < approval_requirement:
            obligations.append(f"obtain_{approval_requirement}_approvals")

        if security_context is None:
            if requirement.maximum_risk < 100:
                return deny(
                    "A verified security context with a risk score is required "
                    "for this action"
                )
            obligations.append("provide_verified_security_context")
        else:
            risk_score = security_context.risk_score
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
                verified_hops=verified_hops,
                now=now,
                receipt_secret=receipt_secret,
                receipt_key_id=receipt_key_id,
            )

        reasons.append("All mandatory authorization controls passed")
        return self._finalize(
            request=request,
            effect="allow",
            reasons=reasons,
            obligations=obligations,
            verified_hops=verified_hops,
            now=now,
            receipt_secret=receipt_secret,
            receipt_key_id=receipt_key_id,
        )

    def _role_allows(self, roles: tuple[str, ...], action: str) -> bool:
        for role in roles:
            permissions = self.policy.role_permissions.get(role, ())
            if action in permissions or "*" in permissions:
                return True
        return False

    def _cross_tenant_authorized(self, request: AuthorizationRequest) -> bool:
        for trust in self.policy.cross_tenant_trust:
            if trust.source_tenant_id != request.principal.tenant_id:
                continue
            if trust.destination_tenant_id != request.resource.tenant_id:
                continue
            if trust.action != request.action:
                continue
            if not fnmatch(request.resource.resource_id, trust.resource_pattern):
                continue
            if not self.relationships.check(
                request.principal.principal_id,
                trust.relationship,
                request.resource.resource_id,
                request.resource.tenant_id,
            ):
                continue
            return True
        return False

    def _finalize(
        self,
        request: AuthorizationRequest,
        effect: str,
        reasons: list[str],
        obligations: list[str],
        verified_hops: list,
        now,
        receipt_secret: str,
        receipt_key_id: str,
    ) -> tuple[Decision, dict[str, Any]]:
        expires_at = min(
            now + timedelta(seconds=self.policy.decision_ttl_seconds),
            request.mission.expires_at,
        )
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
            "key_id": receipt_key_id,
            "evidence_id": evidence_id,
            "request_id": request.request_id,
            "principal": {
                "principal_id": request.principal.principal_id,
                "principal_type": request.principal.principal_type,
                "tenant_id": request.principal.tenant_id,
            },
            "delegation_chain": [
                {
                    "delegation_id": hop.delegation_id,
                    "subject": hop.subject,
                    "principal_type": hop.principal_type,
                    "tenant_id": hop.tenant_id,
                }
                for hop in verified_hops
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
