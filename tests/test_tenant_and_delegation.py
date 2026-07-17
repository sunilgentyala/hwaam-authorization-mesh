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
    signed_delegation_hop,
)


class TenantAndDelegationTests(unittest.TestCase):
    def test_denies_cross_tenant_resource(self):
        policy, graph, _ = build()
        data = clone_request_data()
        data["resource"]["tenant_id"] = "tenant-b"
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "deny")
        self.assertIn("Tenant closure", decision.reasons[0])

    def test_explicit_cross_tenant_trust_allows_the_matching_request(self):
        data = policy_data()
        data["cross_tenant_trust"] = [
            {
                "source_tenant_id": "tenant-a",
                "destination_tenant_id": "tenant-b",
                "resource_pattern": "volume:shared-*",
                "relationship": "can_read",
                "action": "volume.read",
            }
        ]
        policy = PolicyBundle.from_dict(data)
        request_data = clone_request_data()
        request_data["action"] = "volume.read"
        request_data["resource"]["resource_id"] = "volume:shared-01"
        request_data["resource"]["tenant_id"] = "tenant-b"
        request_data["mission"]["allowed_actions"] = ["volume.read"]
        request_data["mission"]["resource_patterns"] = ["volume:shared-*"]
        request_data["delegation_chain"] = []
        graph = RelationshipGraph()
        graph.add("user:suresh", "can_read", "volume:shared-01", "tenant-b")
        request = AuthorizationRequest.from_dict(request_data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "allow")

    def test_cross_tenant_trust_does_not_grant_a_different_action(self):
        data = policy_data()
        data["cross_tenant_trust"] = [
            {
                "source_tenant_id": "tenant-a",
                "destination_tenant_id": "tenant-b",
                "resource_pattern": "volume:shared-*",
                "relationship": "can_read",
                "action": "volume.read",
            }
        ]
        policy = PolicyBundle.from_dict(data)
        request_data = clone_request_data()
        request_data["resource"]["resource_id"] = "volume:shared-01"
        request_data["resource"]["tenant_id"] = "tenant-b"
        request_data["mission"]["resource_patterns"] = ["volume:shared-*"]
        request = AuthorizationRequest.from_dict(request_data)
        decision, _ = AuthorizationEngine(policy).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "deny")
        self.assertIn("Tenant closure", decision.reasons[0])

    def test_denies_excessive_delegation_depth(self):
        policy, graph, _ = build()
        data = clone_request_data()
        data["delegation_chain"].append(
            signed_delegation_hop(
                delegation_id="delegation-second-hop",
                issuer="agent:change-assistant",
                subject="tool:snapshot-api",
                principal_type="tool",
                parent_delegation_id="delegation-test-001",
            )
        )
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "deny")
        self.assertIn("Delegation depth", decision.reasons[0])

    def test_denies_delegation_action_expansion(self):
        policy, graph, _ = build()
        data = clone_request_data()
        data["delegation_chain"][0] = signed_delegation_hop(allowed_actions=("volume.read",))
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "deny")
        self.assertIn("does not permit the action", decision.reasons[0])

    def test_denies_forged_delegation_hop(self):
        policy, graph, _ = build()
        data = clone_request_data()
        data["delegation_chain"][0]["signature"] = "0" * 64
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "deny")
        self.assertIn("Delegation hop failed", decision.reasons[0])

    def test_denies_delegation_hop_with_unmatched_issuer(self):
        policy, graph, _ = build()
        data = clone_request_data()
        # A validly-signed hop from a trusted issuer that just isn't the
        # actual prior delegator in this chain.
        data["delegation_chain"][0] = signed_delegation_hop(issuer="approval-system")
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "deny")
        self.assertIn("issuer does not match", decision.reasons[0])


if __name__ == "__main__":
    unittest.main()
