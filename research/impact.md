# HWAAM Impact Analysis

## Purpose

HWAAM addresses the authorization gap between identity validation and the exact action that a human, workload, or AI agent performs on a protected resource.

The reference implementation does not claim completed enterprise deployment results. It provides measurable controls and an evaluation baseline that organizations can test against their own systems.

## Security impact

### 1. Reduced cross-tenant exposure

Every request binds the principal, resource, and mission to a tenant. A mismatch is denied before role or token permissions can broaden access.

Suggested measure:

```text
Cross-tenant substitution tests denied / cross-tenant tests executed
```

Target for protected endpoints: 100 percent.

### 2. Reduced mission and scope mismatch

A broad platform permission cannot authorize an action excluded by the mission. The mission limits actions, resource patterns, delegation depth, change count, expiry, approvals, and output destinations.

Suggested measures:

- Percentage of delegated operations carrying a mission identifier
- Percentage of sensitive actions constrained by impact limits
- Number of denied requests that had valid platform credentials but invalid mission context

### 3. Better agent and workload accountability

The decision receipt preserves the initiating principal, delegation chain, mission, action, resource, policy version, obligations, and timestamps.

Suggested measures:

- Percentage of sensitive actions with verifiable receipts
- Percentage of agent actions linked to an initiating human or service owner
- Mean time to reconstruct an authorization decision

### 4. Faster revocation response

The reference engine checks principal, mission, and resource revocation before evaluating permissions. A production design should combine short decision lifetimes with event-driven invalidation.

Suggested measures:

- P95 time from revocation event to denied access
- Number of active workflows terminated after mission revocation
- Maximum accepted age of identity, relationship, and policy data

### 5. Improved authorization testing

The included tests cover positive access, negative access, tenant boundaries, mission expiration, delegation attenuation, relationship checks, risk obligations, approvals, and receipt integrity.

Suggested measures:

- Authorization paths tested / authorization paths implemented
- Negative tests / protected operations
- Policy changes rejected by predeployment tests

## Operational impact

HWAAM can reduce duplicated authorization logic by giving APIs, gateways, storage adapters, Kubernetes controls, and agent tool gateways one normalized request and decision contract.

Potential benefits include:

- Consistent deny reasons
- Faster access reviews
- Easier least-privilege analysis
- Reusable mission templates
- Stronger incident evidence
- Clear ownership of non-human identities
- Reduced dependence on broad, long-lived credentials

## Research impact

The framework offers a practical testbed for these research questions:

1. Can mission-bounded authorization reduce misuse of broad OAuth scopes?
2. Can delegation-chain preservation improve forensic reconstruction?
3. What revocation architecture provides acceptable latency without creating an availability bottleneck?
4. Can formal policy checks detect privilege composition before deployment?
5. Which explanation format helps administrators without exposing sensitive policy information?
6. How should persistent agent memory inherit, expire, or delete authorization state?

## Adoption phases

### Phase 1: Observe

Integrate HWAAM in decision-only mode. Compare its result with the existing system without blocking production actions.

### Phase 2: Enforce high-risk denials

Block cross-tenant access, revoked missions, expired missions, and invalid delegation.

### Phase 3: Enforce obligations

Require approvals, step-up authentication, session recording, or output restrictions.

### Phase 4: Optimize privilege

Use effective permissions, decision evidence, and documented exceptions to propose narrower roles and mission templates.

## Limitations

This repository uses an in-memory graph and revocation registry. It does not include a production identity provider, distributed consistency, durable event delivery, hardware-backed signing keys, or formal verification proofs. Those capabilities belong in later releases and deployment-specific integrations.
