# HWAAM Threat Model

## Protected assets

- Tenant data and resource boundaries
- Authorization policies
- Mission envelopes
- Delegation chains
- Revocation state
- Decision receipts
- Service and agent identities
- Audit evidence

## Threat actors

- Authenticated users attempting unauthorized object access
- Compromised workloads or service accounts
- Malicious or manipulated AI agents
- External attackers holding stolen tokens
- Insiders with excessive role permissions
- Misconfigured automation and CI/CD systems
- Administrators who unintentionally create policy conflicts

## Trust assumptions

- Principal credentials are validated before HWAAM evaluation.
- Policy bundles are distributed through an authenticated channel.
- Receipt secrets or signing keys are protected.
- Relationship and attribute sources identify their tenant and version.
- Enforcement points cannot be bypassed for protected operations.

## Threat scenarios and controls

| Threat | HWAAM control | Test evidence |
|---|---|---|
| Cross-tenant object substitution | Tenant closure | `test_denies_cross_tenant_resource` |
| Prompt-injected tool request | Mission action and resource limits | `test_denies_action_outside_mission` |
| Sub-agent authority expansion | Delegation attenuation | `test_denies_delegation_action_expansion` |
| Excessive sub-agent chain | Delegation depth limit | `test_denies_excessive_delegation_depth` |
| Stale or terminated authority | Revocation registry | Revocation test module |
| Missing object relationship | Relationship graph | `test_denies_missing_relationship` |
| Excessive operation count | Mission impact limit | `test_denies_excessive_change_count` |
| Dangerous destination | Output destination restriction | `test_denies_unapproved_output_destination` |
| High-risk session | Step-up obligation | `test_conditional_allow_for_high_risk` |
| Receipt tampering | HMAC verification | Receipt test module |

## Out-of-scope threats for version 0.1.0

- Compromise of the Python runtime
- Host operating-system compromise
- Side-channel attacks
- Distributed denial of service
- Secret extraction from process memory
- Malicious policy administrator with signing access
- Byzantine consensus between distributed policy replicas
- Cryptographic agility beyond HMAC-SHA256

## Required production hardening

- Replace shared HMAC secrets with managed asymmetric signing keys where appropriate.
- Store evidence in append-only or tamper-resistant infrastructure.
- Authenticate and authorize policy administration separately from runtime decisions.
- Implement durable revocation events and bounded cache freshness.
- Protect enforcement points from bypass.
- Add rate limits and circuit-breaker behavior.
- Conduct independent penetration testing and code review.
