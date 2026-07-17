import unittest

from hwaam.engine import AuthorizationEngine
from hwaam.models import AuthorizationRequest

from .helpers import build, clone_request_data


class TenantAndDelegationTests(unittest.TestCase):
    def test_denies_cross_tenant_resource(self):
        policy, graph, _ = build()
        data = clone_request_data()
        data["resource"]["tenant_id"] = "tenant-b"
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
        )
        self.assertEqual(decision.effect, "deny")
        self.assertIn("Tenant closure", decision.reasons[0])

    def test_denies_excessive_delegation_depth(self):
        policy, graph, _ = build()
        data = clone_request_data()
        data["delegation_chain"].append(
            {
                "principal_id": "tool:snapshot-api",
                "principal_type": "tool",
                "allowed_actions": ["snapshot.create"],
                "resource_patterns": ["volume:prod-db-*"],
                "tenant_id": "tenant-a",
            }
        )
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
        )
        self.assertEqual(decision.effect, "deny")
        self.assertIn("Delegation depth", decision.reasons[0])

    def test_denies_delegation_action_expansion(self):
        policy, graph, _ = build()
        data = clone_request_data()
        data["delegation_chain"][0]["allowed_actions"] = ["volume.read"]
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
        )
        self.assertEqual(decision.effect, "deny")
        self.assertIn("does not permit the action", decision.reasons[0])


if __name__ == "__main__":
    unittest.main()
