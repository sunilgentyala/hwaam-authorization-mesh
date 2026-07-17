# Test Results

Generated: `2026-07-16T23:51:22.735428+00:00`

## Summary

- Status: **PASSED**
- Tests executed: **22**
- Exit code: `0`
- Python: `3.13.5`
- Platform: `Linux-4.4.0-x86_64-with-glibc2.41`

## Command

```text
/opt/pyvenv/bin/python3 -m unittest discover -s tests -t . -v
```

## Complete output

```text
test_allows_valid_mission_bounded_request (tests.test_engine.EngineTests.test_allows_valid_mission_bounded_request) ... ok
test_conditional_allow_for_high_risk (tests.test_engine.EngineTests.test_conditional_allow_for_high_risk) ... ok
test_denies_action_outside_mission (tests.test_engine.EngineTests.test_denies_action_outside_mission) ... ok
test_denies_missing_relationship (tests.test_engine.EngineTests.test_denies_missing_relationship) ... ok
test_denies_resource_outside_mission (tests.test_engine.EngineTests.test_denies_resource_outside_mission) ... ok
test_denies_excessive_change_count (tests.test_mission.MissionTests.test_denies_excessive_change_count) ... ok
test_denies_expired_mission (tests.test_mission.MissionTests.test_denies_expired_mission) ... ok
test_denies_unapproved_output_destination (tests.test_mission.MissionTests.test_denies_unapproved_output_destination) ... ok
test_rejects_allow_by_default (tests.test_policy_validation.PolicyValidationTests.test_rejects_allow_by_default) ... ok
test_rejects_invalid_risk_limit (tests.test_policy_validation.PolicyValidationTests.test_rejects_invalid_risk_limit) ... ok
test_rejects_invalid_ttl (tests.test_policy_validation.PolicyValidationTests.test_rejects_invalid_ttl) ... ok
test_privileged_action_has_session_obligation (tests.test_privileged_action.PrivilegedActionTests.test_privileged_action_has_session_obligation) ... ok
test_requires_two_approvals (tests.test_privileged_action.PrivilegedActionTests.test_requires_two_approvals) ... ok
test_tampered_receipt_fails (tests.test_receipts.ReceiptTests.test_tampered_receipt_fails) ... ok
test_valid_receipt_verifies (tests.test_receipts.ReceiptTests.test_valid_receipt_verifies) ... ok
test_wrong_secret_fails (tests.test_receipts.ReceiptTests.test_wrong_secret_fails) ... ok
test_denies_revoked_mission (tests.test_revocation.RevocationTests.test_denies_revoked_mission) ... ok
test_denies_revoked_principal (tests.test_revocation.RevocationTests.test_denies_revoked_principal) ... ok
test_denies_revoked_resource (tests.test_revocation.RevocationTests.test_denies_revoked_resource) ... ok
test_denies_cross_tenant_resource (tests.test_tenant_and_delegation.TenantAndDelegationTests.test_denies_cross_tenant_resource) ... ok
test_denies_delegation_action_expansion (tests.test_tenant_and_delegation.TenantAndDelegationTests.test_denies_delegation_action_expansion) ... ok
test_denies_excessive_delegation_depth (tests.test_tenant_and_delegation.TenantAndDelegationTests.test_denies_excessive_delegation_depth) ... ok

----------------------------------------------------------------------
Ran 22 tests in 0.004s

OK
```

These results were generated from the repository's standard-library test suite.
