import unittest

from hwaam.engine import AuthorizationEngine
from hwaam.models import AuthorizationRequest
from hwaam.revocation import RevocationRegistry

from .helpers import ISSUER_SECRET, TRUSTED_ISSUERS, build, clone_request_data, signed_delegation_hop


class RevocationTests(unittest.TestCase):
    def test_denies_revoked_principal(self):
        policy, graph, request = build()
        registry = RevocationRegistry()
        registry.revoke_principal("user:suresh")
        decision, _ = AuthorizationEngine(
            policy,
            graph,
            registry,
        ).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "deny")
        self.assertIn("Principal is revoked", decision.reasons)

    def test_denies_revoked_mission(self):
        policy, graph, request = build()
        registry = RevocationRegistry()
        registry.revoke_mission("mission-change-001")
        decision, _ = AuthorizationEngine(
            policy,
            graph,
            registry,
        ).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "deny")

    def test_denies_revoked_resource(self):
        policy, graph, request = build()
        registry = RevocationRegistry()
        registry.revoke_resource("volume:prod-db-01")
        decision, _ = AuthorizationEngine(
            policy,
            graph,
            registry,
        ).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "deny")

    def test_denies_revoked_delegation(self):
        policy, graph, _ = build()
        data = clone_request_data()
        data["delegation_chain"] = [signed_delegation_hop(delegation_id="delegation-to-revoke")]
        request = AuthorizationRequest.from_dict(data)
        registry = RevocationRegistry()
        registry.revoke_delegation("delegation-to-revoke")
        decision, _ = AuthorizationEngine(
            policy,
            graph,
            registry,
        ).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "deny")
        self.assertIn("Delegation hop has been revoked", decision.reasons)


if __name__ == "__main__":
    unittest.main()
