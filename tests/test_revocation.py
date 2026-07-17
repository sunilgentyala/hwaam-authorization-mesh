import unittest

from hwaam.engine import AuthorizationEngine
from hwaam.revocation import RevocationRegistry

from .helpers import build


class RevocationTests(unittest.TestCase):
    def test_denies_revoked_principal(self):
        policy, graph, request = build()
        registry = RevocationRegistry()
        registry.revoke_principal("user:suresh")
        decision, _ = AuthorizationEngine(
            policy,
            graph,
            registry,
        ).evaluate(request, "test-secret")
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
        ).evaluate(request, "test-secret")
        self.assertEqual(decision.effect, "deny")

    def test_denies_revoked_resource(self):
        policy, graph, request = build()
        registry = RevocationRegistry()
        registry.revoke_resource("volume:prod-db-01")
        decision, _ = AuthorizationEngine(
            policy,
            graph,
            registry,
        ).evaluate(request, "test-secret")
        self.assertEqual(decision.effect, "deny")


if __name__ == "__main__":
    unittest.main()
