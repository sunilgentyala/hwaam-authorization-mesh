import unittest
from datetime import datetime, timedelta, timezone

from hwaam.engine import AuthorizationEngine
from hwaam.receipts import evaluate_receipt, verify_receipt
from hwaam.revocation import RevocationRegistry

from .helpers import ISSUER_SECRET, TRUSTED_ISSUERS, build


class ReceiptTests(unittest.TestCase):
    def test_valid_receipt_verifies(self):
        policy, graph, request = build()
        _, receipt = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertTrue(verify_receipt(receipt, "test-secret"))

    def test_tampered_receipt_fails(self):
        policy, graph, request = build()
        _, receipt = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        receipt["payload"]["effect"] = "deny"
        self.assertFalse(verify_receipt(receipt, "test-secret"))

    def test_wrong_secret_fails(self):
        policy, graph, request = build()
        _, receipt = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        self.assertFalse(verify_receipt(receipt, "wrong-secret"))

    def test_tampered_receipt_is_not_currently_valid_either(self):
        policy, graph, request = build()
        _, receipt = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        receipt["payload"]["effect"] = "deny"
        validity = evaluate_receipt(receipt, "test-secret", now=datetime.now(timezone.utc))
        self.assertFalse(validity.integrity_valid)
        self.assertFalse(validity.currently_valid)

    def test_intact_receipt_is_not_currently_valid_once_expired(self):
        policy, graph, request = build()
        _, receipt = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        future = datetime.now(timezone.utc) + timedelta(hours=2)
        validity = evaluate_receipt(receipt, "test-secret", now=future)
        self.assertTrue(validity.integrity_valid)
        self.assertFalse(validity.currently_valid)
        self.assertIn("Decision has expired", validity.reasons)

    def test_intact_receipt_is_not_currently_valid_once_principal_revoked(self):
        policy, graph, request = build()
        _, receipt = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        registry = RevocationRegistry()
        registry.revoke_principal("user:suresh")
        validity = evaluate_receipt(
            receipt,
            "test-secret",
            now=datetime.now(timezone.utc),
            revocations=registry,
        )
        self.assertTrue(validity.integrity_valid)
        self.assertFalse(validity.currently_valid)
        self.assertIn("Principal has since been revoked", validity.reasons)

    def test_intact_receipt_is_not_currently_valid_under_a_new_policy_version(self):
        policy, graph, request = build()
        _, receipt = AuthorizationEngine(policy, graph).evaluate(
            request,
            "test-secret",
            issuer_secret=ISSUER_SECRET,
            trusted_issuers=TRUSTED_ISSUERS,
        )
        validity = evaluate_receipt(
            receipt,
            "test-secret",
            now=datetime.now(timezone.utc),
            current_policy_version="2099.01.01-different",
        )
        self.assertTrue(validity.integrity_valid)
        self.assertFalse(validity.currently_valid)


if __name__ == "__main__":
    unittest.main()
