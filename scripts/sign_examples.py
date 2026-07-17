"""Regenerate the signed security-context and delegation-hop envelopes used
by the files under examples/.

Run with: python scripts/sign_examples.py

This is a reference for how an identity/device/risk system signs a security
context, and how a delegating principal signs a delegation hop, before
either ever reaches the HWAAM engine. The shared secret used here
("demo-issuer-secret") is documented in the README as the demo value only —
real deployments use per-issuer keys, not one shared secret.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import json

from hwaam.trust import (
    DelegationHop,
    SecurityContext,
    sign_delegation_hop,
    sign_security_context,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"

ISSUER_SECRET = "demo-issuer-secret"
ISSUED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)
EXPIRES_AT = datetime(2099, 12, 31, 23, 59, 59, tzinfo=timezone.utc)


def build_delegation_envelope() -> dict:
    hop = DelegationHop(
        delegation_id="delegation-demo-001",
        issuer="user:suresh",
        subject="agent:change-assistant",
        principal_type="ai_agent",
        tenant_id="tenant-a",
        audience="hwaam-engine",
        parent_delegation_id=None,
        allowed_actions=("snapshot.create",),
        resource_patterns=("volume:prod-db-*",),
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        nonce="demo-delegation-nonce-1",
    )
    return sign_delegation_hop(hop, ISSUER_SECRET)


def build_context_envelope(risk_score: int, nonce: str) -> dict:
    context = SecurityContext(
        subject_id="user:suresh",
        issuer="identity-provider",
        risk_score=risk_score,
        device_compliant=True,
        mfa=True,
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        nonce=nonce,
    )
    return sign_security_context(context, ISSUER_SECRET)


def update_example(filename: str, risk_score: int, nonce: str) -> None:
    path = EXAMPLES / filename
    data = json.loads(path.read_text(encoding="utf-8"))
    data["delegation_chain"] = [build_delegation_envelope()]
    data["security_context"] = build_context_envelope(risk_score, nonce)
    data["context"].pop("risk_score", None)
    data["principal"]["attributes"].pop("device_compliant", None)
    data["principal"]["attributes"].pop("mfa", None)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"updated {filename}")


def main() -> None:
    update_example("request_allowed.json", risk_score=20, nonce="demo-context-nonce-allowed")
    update_example(
        "request_cross_tenant.json", risk_score=20, nonce="demo-context-nonce-cross-tenant"
    )
    update_example(
        "request_high_risk.json", risk_score=90, nonce="demo-context-nonce-high-risk"
    )


if __name__ == "__main__":
    main()
