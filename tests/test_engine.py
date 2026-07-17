import unittest

from hwaam.engine import AuthorizationEngine
from hwaam.models import AuthorizationRequest
from hwaam.policy import PolicyBundle
from hwaam.relationships import RelationshipGraph

from .helpers import (
    ISSUER_SECRET,
    TRUSTED_ISSUERS,
    build,
    clone_request_data,
    policy_data,
    signed_security_context,
)


class EngineTests(unittest.TestCase):
    def test_allows_valid_mission_bounded_request(self):
        policy, graph, request = build()
        decision, receipt = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
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
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
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
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "deny")

    def test_denies_missing_relationship(self):
        policy, _, request = build()
        decision, _ = AuthorizationEngine(policy).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "deny")
        self.assertIn("relationship", decision.reasons[0])

    def test_conditional_allow_for_high_risk(self):
        policy, graph, _ = build()
        data = clone_request_data()
        data["security_context"] = signed_security_context(risk_score=75)
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "conditional_allow")
        self.assertIn("step_up_authentication", decision.obligations)

    def test_missing_security_context_denies_risk_controlled_action(self):
        policy, graph, _ = build()
        data = clone_request_data()
        data["security_context"] = None
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "deny")
        # device_compliant/mfa are also sourced from the verified security
        # context, so a missing context fails the attribute check first.
        self.assertIn("device_compliant", decision.reasons[0])

    def test_missing_security_context_denies_when_risk_is_the_only_gate(self):
        data = policy_data()
        # An action whose only extra control is a risk ceiling, so a missing
        # security context cannot hide behind an unrelated attribute denial.
        data["action_requirements"]["snapshot.create"] = {
            "required_roles": ["storage_operator", "storage_admin"],
            "required_relationship": "manages",
            "maximum_risk": 70,
        }
        policy = PolicyBundle.from_dict(data)
        request_data = clone_request_data()
        request_data["security_context"] = None
        request = AuthorizationRequest.from_dict(request_data)
        graph = RelationshipGraph()
        graph.add("user:suresh", "manages", "volume:prod-db-01", "tenant-a")
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "deny")
        self.assertIn("security context", decision.reasons[0])

    def test_forged_security_context_is_rejected(self):
        policy, graph, _ = build()
        data = clone_request_data()
        # A requester-supplied, unsigned context must not be trusted.
        data["security_context"] = {
            "payload": {
                "subject_id": "user:suresh",
                "issuer": "identity-provider",
                "risk_score": 0,
                "device_compliant": True,
                "mfa": True,
                "issued_at": "2026-01-01T00:00:00+00:00",
                "expires_at": "2099-12-31T23:59:59+00:00",
                "nonce": "forged",
            },
            "signature": "0" * 64,
            "algorithm": "HMAC-SHA256",
        }
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "deny")


if __name__ == "__main__":
    unittest.main()
