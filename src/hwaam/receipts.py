"""Tamper-evident HMAC receipts for authorization decisions."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


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


def verify_receipt(receipt: dict[str, Any], secret: str) -> bool:
    """Verify receipt integrity using constant-time comparison."""
    try:
        payload = dict(receipt["payload"])
        provided = str(receipt["signature"])
        algorithm = str(receipt["algorithm"])
    except (KeyError, TypeError, ValueError):
        return False

    if algorithm != "HMAC-SHA256" or not secret:
        return False

    expected = hmac.new(
        secret.encode("utf-8"),
        canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(provided, expected)
