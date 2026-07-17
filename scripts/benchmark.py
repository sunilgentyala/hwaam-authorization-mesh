"""Run a local authorization decision benchmark."""

from __future__ import annotations

import argparse
from pathlib import Path
import json
import os
import platform
import statistics
import sys
import time
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from hwaam.engine import AuthorizationEngine
from hwaam.io import load_json
from hwaam.models import AuthorizationRequest
from hwaam.policy import PolicyBundle
from hwaam.relationships import RelationshipGraph


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(len(ordered) * fraction))
    return ordered[index]


def build_engine_and_request():
    policy_data = load_json(ROOT / "examples" / "policy.json")
    policy = PolicyBundle.from_dict(policy_data)
    graph = RelationshipGraph()
    for edge in policy_data["relationships"]:
        graph.add(
            edge["subject_id"],
            edge["relation"],
            edge["resource_id"],
            edge["tenant_id"],
        )
    request_data = load_json(ROOT / "examples" / "request_allowed.json")
    request = AuthorizationRequest.from_dict(request_data)
    return AuthorizationEngine(policy, graph), request


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=20000)
    args = parser.parse_args()
    if args.iterations < 100:
        raise SystemExit("iterations must be at least 100")

    engine, request = build_engine_and_request()
    for _ in range(100):
        engine.evaluate(request, "benchmark-secret")

    timings_ms: list[float] = []
    started = time.perf_counter()
    for _ in range(args.iterations):
        one_started = time.perf_counter()
        decision, _ = engine.evaluate(request, "benchmark-secret")
        timings_ms.append((time.perf_counter() - one_started) * 1000)
        if decision.effect != "allow":
            raise RuntimeError("Benchmark request did not remain allowed")
    elapsed = time.perf_counter() - started

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor() or "not reported",
        "iterations": args.iterations,
        "elapsed_seconds": elapsed,
        "decisions_per_second": args.iterations / elapsed,
        "latency_ms": {
            "mean": statistics.fmean(timings_ms),
            "median": statistics.median(timings_ms),
            "p95": percentile(timings_ms, 0.95),
            "p99": percentile(timings_ms, 0.99),
            "maximum": max(timings_ms),
        },
        "scope": (
            "In-process Python reference engine with in-memory policy, "
            "relationship, and revocation data. Results are not production claims."
        ),
    }

    target = ROOT / "research" / "benchmark-results.json"
    target.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    print(f"\nSaved: {target.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
