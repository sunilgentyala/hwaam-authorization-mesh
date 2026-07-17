import unittest

from hwaam.engine import AuthorizationEngine
from hwaam.models import AuthorizationRequest

from .helpers import ISSUER_SECRET, TRUSTED_ISSUERS, build, clone_request_data, signed_approval


class PrivilegedActionTests(unittest.TestCase):
    def _delete_request(self):
        data = clone_request_data()
        data["principal"]["roles"] = ["storage_admin"]
        data["action"] = "volume.delete"
        data["mission"]["allowed_actions"] = ["volume.delete"]
        data["mission"]["denied_actions"] = []
        data["mission"]["required_approvals"] = 2
        data["delegation_chain"] = []
        return data

    def test_requires_two_approvals(self):
        policy, graph, _ = build()
        data = self._delete_request()
        data["approvals"] = [signed_approval(approver_id="user:approver-1")]
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "conditional_allow")
        self.assertIn("obtain_2_approvals", decision.obligations)

    def test_privileged_action_has_session_obligation(self):
        policy, graph, _ = build()
        data = self._delete_request()
        data["approvals"] = [
            signed_approval(approver_id="user:approver-1"),
            signed_approval(approver_id="user:approver-2"),
        ]
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "conditional_allow")
        self.assertIn("record_privileged_session", decision.obligations)

    def test_unsigned_approval_strings_are_rejected_at_parse_time(self):
        # Approvals must be signed envelopes now, not arbitrary strings, so
        # legacy plain-string approvals fail closed instead of being counted.
        data = self._delete_request()
        data["approvals"] = ["anything-1", "anything-2"]
        with self.assertRaises(ValueError):
            AuthorizationRequest.from_dict(data)

    def test_malformed_approval_envelopes_do_not_count(self):
        policy, graph, _ = build()
        data = self._delete_request()
        data["approvals"] = [
            {"payload": {}, "signature": "0" * 64, "algorithm": "HMAC-SHA256"},
            {"payload": {}, "signature": "1" * 64, "algorithm": "HMAC-SHA256"},
        ]
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "conditional_allow")
        self.assertIn("obtain_2_approvals", decision.obligations)

    def test_self_approval_does_not_count(self):
        policy, graph, _ = build()
        data = self._delete_request()
        data["approvals"] = [
            signed_approval(approver_id="user:suresh"),
            signed_approval(approver_id="user:approver-2"),
        ]
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "conditional_allow")
        self.assertIn("obtain_2_approvals", decision.obligations)

    def test_approval_for_a_different_action_does_not_count(self):
        policy, graph, _ = build()
        data = self._delete_request()
        data["approvals"] = [
            signed_approval(approver_id="user:approver-1", action="volume.read"),
            signed_approval(approver_id="user:approver-2"),
        ]
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "conditional_allow")
        self.assertIn("obtain_2_approvals", decision.obligations)

    def test_approver_without_required_role_does_not_count(self):
        policy, graph, _ = build()
        data = self._delete_request()
        data["approvals"] = [
            signed_approval(approver_id="user:approver-1", approver_roles=("auditor",)),
            signed_approval(approver_id="user:approver-2"),
        ]
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertEqual(decision.effect, "conditional_allow")
        self.assertIn("obtain_2_approvals", decision.obligations)


if __name__ == "__main__":
    unittest.main()
