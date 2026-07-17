"""Command-line interface for HWAAM.

Exit codes for ``evaluate`` reflect the decision effect, not just whether the
process ran without error, so a caller that only checks for exit 0 cannot
mistake a conditional allow (obligations still outstanding) for a clean
allow:

    allow             -> 0
    conditional_allow -> 4
    deny              -> 2
    execution error   -> 1

Exit codes for ``verify-receipt`` distinguish a tampered receipt from a
receipt that is intact but no longer currently valid:

    intact and currently valid          -> 0
    signature/integrity check failed    -> 3
    intact but no longer currently valid -> 5
    execution error                     -> 1
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .engine import AuthorizationEngine
from .io import load_json, write_json
from .models import AuthorizationRequest, utc_now
from .policy import PolicyBundle
from .receipts import evaluate_receipt
from .relationships import RelationshipGraph
from .revocation import RevocationRegistry

EXIT_ALLOW = 0
EXIT_DENY = 2
EXIT_ERROR = 1
EXIT_CONDITIONAL_ALLOW = 4
EXIT_RECEIPT_TAMPERED = 3
EXIT_RECEIPT_NOT_CURRENTLY_VALID = 5


def _add_secret_arguments(parser: argparse.ArgumentParser, name: str, help_text: str) -> None:
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(f"--{name}", help=f"{help_text} (visible in process listings/shell history; prefer the alternatives below)")
    group.add_argument(f"--{name}-file", help=f"{help_text}, read from a file")
    group.add_argument(f"--{name}-env", help=f"{help_text}, read from an environment variable named by this value")
    group.add_argument(f"--{name}-stdin", action="store_true", help=f"{help_text}, read from stdin")


def _resolve_secret(args: argparse.Namespace, name: str) -> str:
    attr = name.replace("-", "_")
    value = getattr(args, attr, None)
    file_path = getattr(args, f"{attr}_file", None)
    env_name = getattr(args, f"{attr}_env", None)
    from_stdin = getattr(args, f"{attr}_stdin", False)

    if file_path:
        return Path(file_path).read_text(encoding="utf-8").strip()
    if env_name:
        result = os.environ.get(env_name)
        if not result:
            raise ValueError(f"Environment variable {env_name} is not set")
        return result
    if from_stdin:
        result = sys.stdin.readline().strip()
        if not result:
            raise ValueError(f"No {name} was provided on stdin")
        return result
    if value:
        print(
            f"warning: --{name} on the command line may be exposed via process "
            f"listing or shell history; prefer --{name}-file, --{name}-env, or "
            f"--{name}-stdin",
            file=sys.stderr,
        )
        return value
    raise ValueError(
        f"One of --{name}, --{name}-file, --{name}-env, --{name}-stdin is required"
    )


def _load_relationships(data: dict) -> RelationshipGraph:
    graph = RelationshipGraph()
    for edge in data.get("relationships", []):
        graph.add(
            str(edge["subject_id"]),
            str(edge["relation"]),
            str(edge["resource_id"]),
            str(edge["tenant_id"]),
        )
    return graph


def _load_revocations(path: str | None) -> RevocationRegistry:
    registry = RevocationRegistry()
    if not path:
        return registry
    data = load_json(path)
    for principal_id in data.get("revoked_principals", []):
        registry.revoke_principal(str(principal_id))
    for mission_id in data.get("revoked_missions", []):
        registry.revoke_mission(str(mission_id))
    for resource_id in data.get("revoked_resources", []):
        registry.revoke_resource(str(resource_id))
    for delegation_id in data.get("revoked_delegations", []):
        registry.revoke_delegation(str(delegation_id))
    return registry


def evaluate_command(args: argparse.Namespace) -> int:
    receipt_secret = _resolve_secret(args, "secret")
    issuer_secret = _resolve_secret(args, "issuer-secret")

    policy_data = load_json(args.policy)
    request_data = load_json(args.request)
    policy = PolicyBundle.from_dict(policy_data)
    graph = _load_relationships(policy_data)
    revocations = _load_revocations(args.revocations)
    request = AuthorizationRequest.from_dict(request_data)
    trusted_issuers = (
        tuple(item.strip() for item in args.trusted_issuers.split(",") if item.strip())
        if args.trusted_issuers
        else ()
    )

    engine = AuthorizationEngine(policy=policy, relationships=graph, revocations=revocations)
    decision, receipt = engine.evaluate(
        request,
        receipt_secret,
        issuer_secret=issuer_secret,
        trusted_issuers=trusted_issuers,
        receipt_key_id=args.receipt_key_id,
    )

    output = decision.to_dict()
    output["receipt"] = receipt
    print(json.dumps(output, indent=2, sort_keys=True))

    if args.receipt_out:
        write_json(args.receipt_out, receipt)

    if decision.effect == "allow":
        return EXIT_ALLOW
    if decision.effect == "conditional_allow":
        return EXIT_CONDITIONAL_ALLOW
    return EXIT_DENY


def verify_command(args: argparse.Namespace) -> int:
    secret = _resolve_secret(args, "secret")
    receipt = load_json(args.receipt)

    current_policy_version = None
    if args.policy:
        current_policy_version = PolicyBundle.from_dict(load_json(args.policy)).version

    revocations = _load_revocations(args.revocations) if args.revocations else None

    validity = evaluate_receipt(
        receipt,
        secret,
        now=utc_now(),
        current_policy_version=current_policy_version,
        revocations=revocations,
    )
    print(
        json.dumps(
            {
                "integrity_valid": validity.integrity_valid,
                "currently_valid": validity.currently_valid,
                "reasons": list(validity.reasons),
            },
            indent=2,
        )
    )

    if not validity.integrity_valid:
        return EXIT_RECEIPT_TAMPERED
    if not validity.currently_valid:
        return EXIT_RECEIPT_NOT_CURRENTLY_VALID
    return EXIT_ALLOW


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hwaam",
        description="Human-Workload-Agent Authorization Mesh reference CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    evaluate = subparsers.add_parser("evaluate", help="Evaluate a request")
    evaluate.add_argument("--policy", required=True)
    evaluate.add_argument("--request", required=True)
    _add_secret_arguments(evaluate, "secret", "Receipt-signing secret")
    _add_secret_arguments(evaluate, "issuer-secret", "Trusted-issuer verification secret")
    evaluate.add_argument(
        "--trusted-issuers",
        help="Comma-separated issuer IDs trusted for security context/approvals/delegation",
    )
    evaluate.add_argument("--revocations", help="Path to a JSON revocation list")
    evaluate.add_argument("--receipt-key-id", default="default")
    evaluate.add_argument("--receipt-out")
    evaluate.set_defaults(func=evaluate_command)

    verify = subparsers.add_parser(
        "verify-receipt",
        help="Verify a signed decision receipt's integrity and current validity",
    )
    verify.add_argument("--receipt", required=True)
    _add_secret_arguments(verify, "secret", "Receipt-signing secret")
    verify.add_argument(
        "--policy", help="Path to the current policy JSON, to detect a stale policy version"
    )
    verify.add_argument("--revocations", help="Path to a JSON revocation list")
    verify.set_defaults(func=verify_command)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        code = args.func(args)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        code = EXIT_ERROR
    raise SystemExit(code)


if __name__ == "__main__":
    main()
