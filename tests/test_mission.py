import unittest
from datetime import datetime, timedelta, timezone

from hwaam.engine import AuthorizationEngine
from hwaam.models import AuthorizationRequest

from .helpers import build, clone_request_data


class MissionTests(unittest.TestCase):
    def test_denies_expired_mission(self):
        policy, graph, _ = build()
        data = clone_request_data()
        data["mission"]["expires_at"] = (
            datetime.now(timezone.utc) - timedelta(minutes=1)
        ).isoformat()
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
        )
        self.assertEqual(decision.effect, "deny")
        self.assertIn("expired", decision.reasons[0])

    def test_denies_excessive_change_count(self):
        policy, graph, _ = build()
        data = clone_request_data()
        data["context"]["requested_changes"] = 2
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
        )
        self.assertEqual(decision.effect, "deny")
        self.assertIn("impact", decision.reasons[0])

    def test_denies_unapproved_output_destination(self):
        policy, graph, _ = build()
        data = clone_request_data()
        data["context"]["output_destination"] = "public-chat"
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
        )
        self.assertEqual(decision.effect, "deny")
        self.assertIn("Output destination", decision.reasons[0])


if __name__ == "__main__":
    unittest.main()
