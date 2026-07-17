import unittest

from hwaam.engine import AuthorizationEngine
from hwaam.models import AuthorizationRequest

from .helpers import build, clone_request_data


class PrivilegedActionTests(unittest.TestCase):
    def _delete_request(self):
        data = clone_request_data()
        data["principal"]["roles"] = ["storage_admin"]
        data["action"] = "volume.delete"
        data["mission"]["allowed_actions"] = ["volume.delete"]
        data["mission"]["denied_actions"] = []
        data["mission"]["required_approvals"] = 2
        data["delegation_chain"][0]["allowed_actions"] = ["volume.delete"]
        data["context"]["risk_score"] = 10
        return data

    def test_requires_two_approvals(self):
        policy, graph, _ = build()
        data = self._delete_request()
        data["approvals"] = ["approver-1"]
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
        )
        self.assertEqual(decision.effect, "conditional_allow")
        self.assertIn("obtain_2_approvals", decision.obligations)

    def test_privileged_action_has_session_obligation(self):
        policy, graph, _ = build()
        data = self._delete_request()
        data["approvals"] = ["approver-1", "approver-2"]
        request = AuthorizationRequest.from_dict(data)
        decision, _ = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
        )
        self.assertEqual(decision.effect, "conditional_allow")
        self.assertIn("record_privileged_session", decision.obligations)


if __name__ == "__main__":
    unittest.main()
