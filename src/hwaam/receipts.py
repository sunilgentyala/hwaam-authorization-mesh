"""Tamper-evident HMAC receipts for authorization decisions.

Receipt verification has two distinct questions, and answering only the
first is a common mistake: (1) is this receipt's payload unmodified since it
was signed ("integrity"), and (2) is the decision it recorded still valid
right now ("current validity") — has the TTL passed, has the mission,
principal, or resource been revoked since, is the policy version still
current. A tampered-but-unexpired receipt and an intact-but-stale receipt
are different failures and callers need to tell them apart.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import hmac
import json
from typing import Any

from .models import parse_timestamp

if False:  # pragma: no cover - typing only, avoids a runtime import cycle
    from .revocation import RevocationRegistry


def canonical_json(data: dict[str, Any]) -> bytes:
    """Serialize data deterministically for signing."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sign_receipt(payload: dict[str, Any], secret: str) -> dict[str, Any]:
    """Return a signed copy of a decision receipt."""
    if not secret:
        raise ValueError("Receipt secret cannot be empty")
    body = dict(payload)
    signature = hmac.new(
        secret.encode("utf-8"),
        canonical_json(body),
        hashlib.sha256,
    ).hexdigest()
    return {"payload": body, "signature": signature, "algorithm": "HMAC-SHA256"}


def _resolve_secret(secret: str | dict[str, str], key_id: str | None) -> str | None:
    if isinstance(secret, dict):
        if key_id is None:
            return None
        return secret.get(key_id)
    return secret


def verify_receipt(receipt: dict[str, Any], secret: str | dict[str, str]) -> bool:
    """Verify receipt integrity (unmodified payload, correct signer) only.

    This does NOT confirm the decision is still valid — call
    ``evaluate_receipt`` for that. ``secret`` may be a single shared secret,
    or a ``{key_id: secret}`` mapping keyed by the receipt payload's
    ``key_id`` to support signing-key rotation.
    """
    try:
        payload = dict(receipt["payload"])
        provided = str(receipt["signature"])
        algorithm = str(receipt["algorithm"])
    except (KeyError, TypeError, ValueError):
        return False

    if algorithm != "HMAC-SHA256":
        return False

    resolved_secret = _resolve_secret(secret, payload.get("key_id"))
    if not resolved_secret:
        return False

    expected = hmac.new(
        resolved_secret.encode("utf-8"),
        canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(provided, expected)


@dataclass(frozen=True)
class ReceiptValidity:
    """The result of checking both integrity and current validity."""

    integrity_valid: bool
    currently_valid: bool
    reasons: tuple[str, ...]


def evaluate_receipt(
    receipt: dict[str, Any],
    secret: str | dict[str, str],
    *,
    now: datetime,
    current_policy_version: str | None = None,
    revocations: "RevocationRegistry | None" = None,
) -> ReceiptValidity:
    """Check receipt integrity and, separately, whether it is still valid now."""
    if not verify_receipt(receipt, secret):
        return ReceiptValidity(
            integrity_valid=False,
            currently_valid=False,
            reasons=("Signature verification failed",),
        )

    payload = receipt["payload"]
    reasons: list[str] = []

    try:
        expires_at = parse_timestamp(payload["expires_at"])
    except (KeyError, TypeError, ValueError):
        return ReceiptValidity(
            integrity_valid=True,
            currently_valid=False,
            reasons=("Receipt payload is missing a usable expiration",),
        )
    if expires_at <= now:
        reasons.append("Decision has expired")

    if revocations is not None:
        principal_id = payload.get("principal", {}).get("principal_id")
        if principal_id and revocations.is_principal_revoked(principal_id):
            reasons.append("Principal has since been revoked")
        mission_id = payload.get("mission_id")
        if mission_id and revocations.is_mission_revoked(mission_id):
            reasons.append("Mission has since been revoked")
        resource_id = payload.get("resource_id")
        if resource_id and revocations.is_resource_revoked(resource_id):
            reasons.append("Resource has since been revoked")

    if (
        current_policy_version is not None
        and payload.get("policy_version") != current_policy_version
    ):
        reasons.append("Receipt was issued under a different policy version")

    return ReceiptValidity(
        integrity_valid=True,
        currently_valid=len(reasons) == 0,
        reasons=tuple(reasons),
    )
