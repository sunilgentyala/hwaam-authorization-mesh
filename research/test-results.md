# Test Results

Generated: `2026-07-17T04:28:46.003640+00:00`

## Summary

- Status: **PASSED**
- Tests executed: **41**
- Exit code: `0`
- Python: `3.14.4`
- Platform: `Windows-11-10.0.26200-SP0`

## Command

```text
C:\Gitrepos\hwaam-authorization-mesh\.venv\Scripts\python.exe -m unittest discover -s tests -t . -v
```

## Complete output

```text
test_allows_valid_mission_bounded_request (tests.test_engine.EngineTests.test_allows_valid_mission_bounded_request) ... ok
test_conditional_allow_for_high_risk (tests.test_engine.EngineTests.test_conditional_allow_for_high_risk) ... ok
test_denies_action_outside_mission (tests.test_engine.EngineTests.test_denies_action_outside_mission) ... ok
test_denies_missing_relationship (tests.test_engine.EngineTests.test_denies_missing_relationship) ... ok
test_denies_resource_outside_mission (tests.test_engine.EngineTests.test_denies_resource_outside_mission) ... ok
test_forged_security_context_is_rejected (tests.test_engine.EngineTests.test_forged_security_context_is_rejected) ... ok
test_missing_security_context_denies_risk_controlled_action (tests.test_engine.EngineTests.test_missing_security_context_denies_risk_controlled_action) ... ok
test_missing_security_context_denies_when_risk_is_the_only_gate (tests.test_engine.EngineTests.test_missing_security_context_denies_when_risk_is_the_only_gate) ... ok
test_decision_ttl_cannot_outlive_the_mission (tests.test_mission.MissionTests.test_decision_ttl_cannot_outlive_the_mission) ... ok
test_denies_excessive_change_count (tests.test_mission.MissionTests.test_denies_excessive_change_count) ... ok
test_denies_expired_mission (tests.test_mission.MissionTests.test_denies_expired_mission) ... ok
test_denies_omitted_output_destination_when_mission_restricts_it (tests.test_mission.MissionTests.test_denies_omitted_output_destination_when_mission_restricts_it) ... ok
test_denies_unapproved_output_destination (tests.test_mission.MissionTests.test_denies_unapproved_output_destination) ... ok
test_rejects_allow_by_default (tests.test_policy_validation.PolicyValidationTests.test_rejects_allow_by_default) ... ok
test_rejects_invalid_risk_limit (tests.test_policy_validation.PolicyValidationTests.test_rejects_invalid_risk_limit) ... ok
test_rejects_invalid_ttl (tests.test_policy_validation.PolicyValidationTests.test_rejects_invalid_ttl) ... ok
test_approval_for_a_different_action_does_not_count (tests.test_privileged_action.PrivilegedActionTests.test_approval_for_a_different_action_does_not_count) ... ok
test_approver_without_required_role_does_not_count (tests.test_privileged_action.PrivilegedActionTests.test_approver_without_required_role_does_not_count) ... ok
test_malformed_approval_envelopes_do_not_count (tests.test_privileged_action.PrivilegedActionTests.test_malformed_approval_envelopes_do_not_count) ... ok
test_privileged_action_has_session_obligation (tests.test_privileged_action.PrivilegedActionTests.test_privileged_action_has_session_obligation) ... ok
test_requires_two_approvals (tests.test_privileged_action.PrivilegedActionTests.test_requires_two_approvals) ... ok
test_self_approval_does_not_count (tests.test_privileged_action.PrivilegedActionTests.test_self_approval_does_not_count) ... ok
test_unsigned_approval_strings_are_rejected_at_parse_time (tests.test_privileged_action.PrivilegedActionTests.test_unsigned_approval_strings_are_rejected_at_parse_time) ... ok
test_intact_receipt_is_not_currently_valid_once_expired (tests.test_receipts.ReceiptTests.test_intact_receipt_is_not_currently_valid_once_expired) ... ok
test_intact_receipt_is_not_currently_valid_once_principal_revoked (tests.test_receipts.ReceiptTests.test_intact_receipt_is_not_currently_valid_once_principal_revoked) ... ok
test_intact_receipt_is_not_currently_valid_under_a_new_policy_version (tests.test_receipts.ReceiptTests.test_intact_receipt_is_not_currently_valid_under_a_new_policy_version) ... ok
test_tampered_receipt_fails (tests.test_receipts.ReceiptTests.test_tampered_receipt_fails) ... ok
test_tampered_receipt_is_not_currently_valid_either (tests.test_receipts.ReceiptTests.test_tampered_receipt_is_not_currently_valid_either) ... ok
test_valid_receipt_verifies (tests.test_receipts.ReceiptTests.test_valid_receipt_verifies) ... ok
test_wrong_secret_fails (tests.test_receipts.ReceiptTests.test_wrong_secret_fails) ... ok
test_denies_revoked_delegation (tests.test_revocation.RevocationTests.test_denies_revoked_delegation) ... ok
test_denies_revoked_mission (tests.test_revocation.RevocationTests.test_denies_revoked_mission) ... ok
test_denies_revoked_principal (tests.test_revocation.RevocationTests.test_denies_revoked_principal) ... ok
test_denies_revoked_resource (tests.test_revocation.RevocationTests.test_denies_revoked_resource) ... ok
test_cross_tenant_trust_does_not_grant_a_different_action (tests.test_tenant_and_delegation.TenantAndDelegationTests.test_cross_tenant_trust_does_not_grant_a_different_action) ... ok
test_denies_cross_tenant_resource (tests.test_tenant_and_delegation.TenantAndDelegationTests.test_denies_cross_tenant_resource) ... ok
test_denies_delegation_action_expansion (tests.test_tenant_and_delegation.TenantAndDelegationTests.test_denies_delegation_action_expansion) ... ok
test_denies_delegation_hop_with_unmatched_issuer (tests.test_tenant_and_delegation.TenantAndDelegationTests.test_denies_delegation_hop_with_unmatched_issuer) ... ok
test_denies_excessive_delegation_depth (tests.test_tenant_and_delegation.TenantAndDelegationTests.test_denies_excessive_delegation_depth) ... ok
test_denies_forged_delegation_hop (tests.test_tenant_and_delegation.TenantAndDelegationTests.test_denies_forged_delegation_hop) ... ok
test_explicit_cross_tenant_trust_allows_the_matching_request (tests.test_tenant_and_delegation.TenantAndDelegationTests.test_explicit_cross_tenant_trust_allows_the_matching_request) ... ok

----------------------------------------------------------------------
Ran 41 tests in 0.009s

OK
```

These results were generated from the repository's standard-library test suite.
