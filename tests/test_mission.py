import unittest
from datetime import datetime, timedelta, timezone

from hwaam.engine import AuthorizationEngine
from hwaam.models import AuthorizationRequest

from .helpers import ISSUER_SECRET, TRUSTED_ISSUERS, build, clone_request_data


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
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
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
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
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
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "deny")
        self.assertIn("Output destination", decision.reasons[0])

    def test_denies_omitted_output_destination_when_mission_restricts_it(self):
        policy, graph, _ = build()
        data = clone_request_data()
        del data["context"]["output_destination"]
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "deny")
        self.assertIn("Output destination", decision.reasons[0])

    def test_decision_ttl_cannot_outlive_the_mission(self):
        policy, graph, _ = build()
        data = clone_request_data()
        soon = datetime.now(timezone.utc) + timedelta(seconds=2)
        data["mission"]["expires_at"] = soon.isoformat()
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "allow")
        # policy TTL is 60s, but the mission expires in ~2s — the decision
        # must not outlive the mission it was granted under.
        self.assertLessEqual(decision.expires_at, soon)


if __name__ == "__main__":
    unittest.main()
