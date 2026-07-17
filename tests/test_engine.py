import unittest

from hwaam.engine import AuthorizationEngine
from hwaam.models import AuthorizationRequest

from .helpers import build, clone_request_data


class EngineTests(unittest.TestCase):
    def test_allows_valid_mission_bounded_request(self):
        policy, graph, request = build()
        decision, receipt = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
        )
        self.assertEqual(decision.effect, "allow")
        self.assertEqual(receipt["algorithm"], "HMAC-SHA256")

    def test_denies_action_outside_mission(self):
        policy, graph, _ = build()
        data = clone_request_data()
        data["action"] = "volume.read"
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
        )
        self.assertEqual(decision.effect, "deny")
        self.assertIn("outside the mission", decision.reasons[0])

    def test_denies_resource_outside_mission(self):
        policy, graph, _ = build()
        data = clone_request_data()
        data["resource"]["resource_id"] = "volume:dev-01"
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
        )
        self.assertEqual(decision.effect, "deny")

    def test_denies_missing_relationship(self):
        policy, _, request = build()
        decision, _ = AuthorizationEngine(policy).evaluate(
            request,
            "test-secret",
        )
        self.assertEqual(decision.effect, "deny")
        self.assertIn("relationship", decision.reasons[0])

    def test_conditional_allow_for_high_risk(self):
        policy, graph, _ = build()
        data = clone_request_data()
        data["context"]["risk_score"] = 75
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
        )
        self.assertEqual(decision.effect, "conditional_allow")
        self.assertIn("step_up_authentication", decision.obligations)


if __name__ == "__main__":
    unittest.main()
