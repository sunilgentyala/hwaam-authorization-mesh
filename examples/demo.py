"""Run three reference HWAAM decisions."""

from pathlib import Path
import json

from hwaam.engine import AuthorizationEngine
from hwaam.io import load_json
from hwaam.models import AuthorizationRequest
from hwaam.policy import PolicyBundle
from hwaam.relationships import RelationshipGraph


ROOT = Path(__file__).resolve().parents[1]


def build_engine() -> AuthorizationEngine:
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
    return AuthorizationEngine(policy, graph)


def run(filename: str) -> None:
    engine = build_engine()
    data = load_json(ROOT / "examples" / filename)
    request = AuthorizationRequest.from_dict(data)
    decision, _ = engine.evaluate(request, "demo-secret")
    print(filename)
    print(json.dumps(decision.to_dict(), indent=2))
    print()


if __name__ == "__main__":
    run("request_allowed.json")
    run("request_cross_tenant.json")
    run("request_high_risk.json")
