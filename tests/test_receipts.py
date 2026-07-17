import unittest

from hwaam.engine import AuthorizationEngine
from hwaam.receipts import verify_receipt

from .helpers import build


class ReceiptTests(unittest.TestCase):
    def test_valid_receipt_verifies(self):
        policy, graph, request = build()
        _, receipt = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
        )
        self.assertTrue(verify_receipt(receipt, "test-secret"))

    def test_tampered_receipt_fails(self):
        policy, graph, request = build()
        _, receipt = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
        )
        receipt["payload"]["effect"] = "deny"
        self.assertFalse(verify_receipt(receipt, "test-secret"))

    def test_wrong_secret_fails(self):
        policy, graph, request = build()
        _, receipt = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
        )
        self.assertFalse(verify_receipt(receipt, "wrong-secret"))


if __name__ == "__main__":
    unittest.main()
