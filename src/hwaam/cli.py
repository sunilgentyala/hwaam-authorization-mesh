"""Command-line interface for HWAAM."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import AuthorizationEngine
from .io import load_json, write_json
from .models import AuthorizationRequest
from .policy import PolicyBundle
from .receipts import verify_receipt
from .relationships import RelationshipGraph


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


def evaluate_command(args: argparse.Namespace) -> int:
    policy_data = load_json(args.policy)
    request_data = load_json(args.request)
    policy = PolicyBundle.from_dict(policy_data)
    graph = _load_relationships(policy_data)
    request = AuthorizationRequest.from_dict(request_data)
    engine = AuthorizationEngine(policy=policy, relationships=graph)
    decision, receipt = engine.evaluate(request, args.secret)

    output = decision.to_dict()
    output["receipt"] = receipt
    print(json.dumps(output, indent=2, sort_keys=True))

    if args.receipt_out:
        write_json(args.receipt_out, receipt)

    return 0 if decision.effect in {"allow", "conditional_allow"} else 2


def verify_command(args: argparse.Namespace) -> int:
    receipt = load_json(args.receipt)
    valid = verify_receipt(receipt, args.secret)
    print(json.dumps({"valid": valid}, indent=2))
    return 0 if valid else 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hwaam",
        description="Human-Workload-Agent Authorization Mesh reference CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    evaluate = subparsers.add_parser("evaluate", help="Evaluate a request")
    evaluate.add_argument("--policy", required=True)
    evaluate.add_argument("--request", required=True)
    evaluate.add_argument("--secret", required=True)
    evaluate.add_argument("--receipt-out")
    evaluate.set_defaults(func=evaluate_command)

    verify = subparsers.add_parser(
        "verify-receipt",
        help="Verify a signed decision receipt",
    )
    verify.add_argument("--receipt", required=True)
    verify.add_argument("--secret", required=True)
    verify.set_defaults(func=verify_command)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        code = args.func(args)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        code = 1
    raise SystemExit(code)


if __name__ == "__main__":
    main()
