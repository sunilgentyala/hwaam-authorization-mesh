import unittest

from hwaam.policy import PolicyBundle


class PolicyValidationTests(unittest.TestCase):
    def test_rejects_allow_by_default(self):
        with self.assertRaises(ValueError):
            PolicyBundle.from_dict(
                {
                    "version": "unsafe",
                    "default_effect": "allow",
                }
            )

    def test_rejects_invalid_ttl(self):
        with self.assertRaises(ValueError):
            PolicyBundle.from_dict(
                {
                    "version": "unsafe",
                    "default_effect": "deny",
                    "decision_ttl_seconds": 0,
                }
            )

    def test_rejects_invalid_risk_limit(self):
        with self.assertRaises(ValueError):
            PolicyBundle.from_dict(
                {
                    "version": "unsafe",
                    "default_effect": "deny",
                    "action_requirements": {
                        "x": {"maximum_risk": 101}
                    },
                }
            )


if __name__ == "__main__":
    unittest.main()
