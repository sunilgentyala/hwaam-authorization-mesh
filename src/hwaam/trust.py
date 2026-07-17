"""Signed trust objects issued by systems outside the authorization engine.

The engine must never trust risk scores, device posture, approvals, or
delegation hops that a requester can set unilaterally. Each object here is
signed by its issuer (an identity/device/risk system, an approval system, or
a delegating principal) with an HMAC-SHA256 key shared out of band with the
engine, and is only accepted after signature, freshness, audience, and
subject checks all pass.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any
import hashlib
import hmac

from .models import parse_timestamp
from .receipts import canonical_json


def _sign_payload(payload: dict[str, Any], secret: str) -> dict[str, Any]:
    if not secret:
        raise ValueError("Signing secret cannot be empty")
    signature = hmac.new(
        secret.encode("utf-8"),
        canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()
    return {"payload": payload, "signature": signature, "algorithm": "HMAC-SHA256"}


def _verify_payload(envelope: Any, secret: str) -> dict[str, Any] | None:
    if not envelope or not secret:
        return None
    try:
        payload = dict(envelope["payload"])
        signature = str(envelope["signature"])
        algorithm = str(envelope["algorithm"])
    except (KeyError, TypeError, ValueError):
        return None
    if algorithm != "HMAC-SHA256":
        return None
    expected = hmac.new(
        secret.encode("utf-8"),
        canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None
    return payload


# ---------------------------------------------------------------------------
# Security context: risk score, device posture, and MFA state attested by a
# trusted identity/device/risk system rather than read off the request.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SecurityContext:
    subject_id: str
    issuer: str
    risk_score: int
    device_compliant: bool
    mfa: bool
    issued_at: datetime
    expires_at: datetime
    nonce: str


def sign_security_context(context: SecurityContext, secret: str) -> dict[str, Any]:
    payload = {
        "subject_id": context.subject_id,
        "issuer": context.issuer,
        "risk_score": context.risk_score,
        "device_compliant": context.device_compliant,
        "mfa": context.mfa,
        "issued_at": context.issued_at.isoformat(),
        "expires_at": context.expires_at.isoformat(),
        "nonce": context.nonce,
    }
    return _sign_payload(payload, secret)


def verify_security_context(
    envelope: Any,
    secret: str,
    *,
    subject_id: str,
    trusted_issuers: tuple[str, ...],
    now: datetime,
) -> SecurityContext | None:
    """Return a verified SecurityContext, or None if missing/invalid/stale/untrusted."""
    payload = _verify_payload(envelope, secret)
    if payload is None:
        return None
    try:
        context = SecurityContext(
            subject_id=str(payload["subject_id"]),
            issuer=str(payload["issuer"]),
            risk_score=int(payload["risk_score"]),
            device_compliant=bool(payload["device_compliant"]),
            mfa=bool(payload["mfa"]),
            issued_at=parse_timestamp(payload["issued_at"]),
            expires_at=parse_timestamp(payload["expires_at"]),
            nonce=str(payload["nonce"]),
        )
    except (KeyError, TypeError, ValueError):
        return None
    if context.subject_id != subject_id:
        return None
    if trusted_issuers and context.issuer not in trusted_issuers:
        return None
    if context.issued_at > now or context.expires_at <= now:
        return None
    return context


# ---------------------------------------------------------------------------
# Approvals: signed attestations from an approval system, scoped to one
# request/action/resource and carrying the approver's identity, tenant, and
# role so the engine can enforce separation-of-duty and role checks.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Approval:
    approver_id: str
    approver_tenant_id: str
    approver_roles: tuple[str, ...]
    issuer: str
    request_id: str
    action: str
    resource_id: str
    issued_at: datetime
    expires_at: datetime
    nonce: str


def sign_approval(approval: Approval, secret: str) -> dict[str, Any]:
    payload = {
        "approver_id": approval.approver_id,
        "approver_tenant_id": approval.approver_tenant_id,
        "approver_roles": list(approval.approver_roles),
        "issuer": approval.issuer,
        "request_id": approval.request_id,
        "action": approval.action,
        "resource_id": approval.resource_id,
        "issued_at": approval.issued_at.isoformat(),
        "expires_at": approval.expires_at.isoformat(),
        "nonce": approval.nonce,
    }
    return _sign_payload(payload, secret)


def verify_approval(
    envelope: Any,
    secret: str,
    *,
    request_id: str,
    action: str,
    resource_id: str,
    resource_tenant_id: str,
    trusted_issuers: tuple[str, ...],
    now: datetime,
) -> Approval | None:
    """Return a verified Approval bound to this exact request, or None."""
    payload = _verify_payload(envelope, secret)
    if payload is None:
        return None
    try:
        approval = Approval(
            approver_id=str(payload["approver_id"]),
            approver_tenant_id=str(payload["approver_tenant_id"]),
            approver_roles=tuple(str(item) for item in payload.get("approver_roles", [])),
            issuer=str(payload["issuer"]),
            request_id=str(payload["request_id"]),
            action=str(payload["action"]),
            resource_id=str(payload["resource_id"]),
            issued_at=parse_timestamp(payload["issued_at"]),
            expires_at=parse_timestamp(payload["expires_at"]),
            nonce=str(payload["nonce"]),
        )
    except (KeyError, TypeError, ValueError):
        return None
    if trusted_issuers and approval.issuer not in trusted_issuers:
        return None
    if approval.issued_at > now or approval.expires_at <= now:
        return None
    if approval.request_id != request_id:
        return None
    if approval.action != action:
        return None
    if approval.resource_id != resource_id:
        return None
    if approval.approver_tenant_id != resource_tenant_id:
        return None
    return approval


# ---------------------------------------------------------------------------
# Delegation hops: signed grants proving who issued a delegation, to whom,
# for what, and chaining each hop to its parent so a chain cannot be
# reordered, truncated, or have hops inserted or forged.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DelegationHop:
    delegation_id: str
    issuer: str
    subject: str
    principal_type: str
    tenant_id: str
    audience: str
    parent_delegation_id: str | None
    allowed_actions: tuple[str, ...]
    resource_patterns: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    nonce: str


def sign_delegation_hop(hop: DelegationHop, secret: str) -> dict[str, Any]:
    payload = {
        "delegation_id": hop.delegation_id,
        "issuer": hop.issuer,
        "subject": hop.subject,
        "principal_type": hop.principal_type,
        "tenant_id": hop.tenant_id,
        "audience": hop.audience,
        "parent_delegation_id": hop.parent_delegation_id,
        "allowed_actions": list(hop.allowed_actions),
        "resource_patterns": list(hop.resource_patterns),
        "issued_at": hop.issued_at.isoformat(),
        "expires_at": hop.expires_at.isoformat(),
        "nonce": hop.nonce,
    }
    return _sign_payload(payload, secret)


def verify_delegation_hop(
    envelope: Any,
    secret: str,
    *,
    audience: str,
    trusted_issuers: tuple[str, ...],
    now: datetime,
) -> DelegationHop | None:
    """Return a verified DelegationHop, or None if invalid/stale/wrong audience."""
    payload = _verify_payload(envelope, secret)
    if payload is None:
        return None
    try:
        hop = DelegationHop(
            delegation_id=str(payload["delegation_id"]),
            issuer=str(payload["issuer"]),
            subject=str(payload["subject"]),
            principal_type=str(payload["principal_type"]),
            tenant_id=str(payload["tenant_id"]),
            audience=str(payload["audience"]),
            parent_delegation_id=(
                str(payload["parent_delegation_id"])
                if payload.get("parent_delegation_id") is not None
                else None
            ),
            allowed_actions=tuple(str(item) for item in payload.get("allowed_actions", [])),
            resource_patterns=tuple(
                str(item) for item in payload.get("resource_patterns", [])
            ),
            issued_at=parse_timestamp(payload["issued_at"]),
            expires_at=parse_timestamp(payload["expires_at"]),
            nonce=str(payload["nonce"]),
        )
    except (KeyError, TypeError, ValueError):
        return None
    if trusted_issuers and hop.issuer not in trusted_issuers:
        return None
    if hop.issued_at > now or hop.expires_at <= now:
        return None
    if hop.audience != audience:
        return None
    return hop
