# HWAAM Authorization Mesh

[![CI](https://github.com/sunilgentyala/hwaam-authorization-mesh/actions/workflows/ci.yml/badge.svg)](https://github.com/sunilgentyala/hwaam-authorization-mesh/actions/workflows/ci.yml)
[![GitHub Pages](https://github.com/sunilgentyala/hwaam-authorization-mesh/actions/workflows/pages.yml/badge.svg)](https://github.com/sunilgentyala/hwaam-authorization-mesh/actions/workflows/pages.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

HWAAM is a reference implementation of the Human-Workload-Agent Authorization Mesh. It applies deterministic authorization to humans, workloads, service accounts, and AI agents while preserving tenant boundaries, mission limits, delegation context, revocation state, and signed decision evidence.

## Authors

- Primary author and project lead: Sunil Gentyala
- Co-author and framework contributor: Suresh Kumar Darisi

## Why HWAAM

Modern authorization is fragmented across role-based access control, attribute rules, relationship graphs, OAuth scopes, cloud identity systems, Kubernetes, service accounts, and AI-agent tools. A request may pass every local check while still violating the user's purpose, tenant boundary, or least-privilege requirement.

HWAAM adds a shared decision contract and enforces these controls:

- Baseline role permissions
- Object and tenant authorization
- Relationship-aware access
- Mission-bounded actions and resources
- Delegation-depth limits
- Authority attenuation across delegation hops
- Approval and risk obligations
- Continuous revocation checks
- Fail-closed processing
- HMAC-signed decision receipts

## Repository contents

```text
hwaam-authorization-mesh/
├── src/hwaam/                 Core authorization package
├── tests/                     Standard-library test suite
├── examples/                  Policies, requests, and demo script
├── scripts/                   Test, benchmark, and report scripts
├── docs/                      GitHub Pages website
├── research/                  Threat model, impact, and results
└── .github/workflows/         CI and Pages deployment
```

## Quick start

HWAAM requires Python 3.10 or later and uses only the Python standard library at runtime.

```bash
git clone https://github.com/sunilgentyala/hwaam-authorization-mesh.git
cd hwaam-authorization-mesh
python -m pip install -e .
hwaam evaluate \
  --policy examples/policy.json \
  --request examples/request_allowed.json \
  --secret demo-secret \
  --issuer-secret demo-issuer-secret \
  --trusted-issuers identity-provider,user:suresh
```

`--secret` signs the engine's own decision receipt. `--issuer-secret` verifies
signed objects the engine did not create — the security context, approvals,
and delegation hops attached to the request (see [Trust model](#trust-model)
below). Passing either as a bare CLI flag works for local testing but prints
a warning; prefer `--secret-file`, `--secret-env`, or `--secret-stdin` (and
the matching `--issuer-secret-*` forms) so the value never lands in shell
history or `ps` output.

Expected result:

```json
{
  "effect": "allow",
  "reasons": [
    "All mandatory authorization controls passed"
  ]
}
```

Run the complete test suite:

```bash
python scripts/run_tests.py
```

Run a reproducible local benchmark:

```bash
python scripts/benchmark.py --iterations 20000
```

Generate machine-readable and Markdown reports:

```bash
python scripts/generate_results.py
```

## CLI examples

Evaluate an allowed request. Exit code reflects the effect: `0` allow, `4`
conditional allow (obligations are still outstanding — do not treat this as
a clean pass), `2` deny, `1` execution error.

```bash
hwaam evaluate \
  --policy examples/policy.json \
  --request examples/request_allowed.json \
  --secret demo-secret \
  --issuer-secret demo-issuer-secret \
  --trusted-issuers identity-provider,user:suresh
```

Evaluate a denied cross-tenant request:

```bash
hwaam evaluate \
  --policy examples/policy.json \
  --request examples/request_cross_tenant.json \
  --secret demo-secret \
  --issuer-secret demo-issuer-secret \
  --trusted-issuers identity-provider,user:suresh
```

Verify a signed receipt. This reports two separate results — `integrity_valid`
(has the payload been tampered with) and `currently_valid` (has it since
expired, or has the principal/mission/resource it names since been revoked,
or was it issued under an older policy version). Exit code `0` means both
are true, `3` means integrity failed, `5` means integrity passed but the
decision is no longer currently valid:

```bash
hwaam verify-receipt \
  --receipt decision-receipt.json \
  --secret demo-secret \
  --policy examples/policy.json \
  --revocations revocations.json
```

## Trust model

The engine never trusts a risk score, device-compliance flag, MFA flag,
approval, or delegation grant that arrives unsigned in the request — those
are exactly the fields a requester (or a compromised agent acting as one)
controls. Each is instead a signed envelope, verified against
`--issuer-secret` before the engine will use it:

- **Security context** (`security_context` on the request) — risk score,
  device compliance, and MFA state, signed by a trusted identity/device/risk
  system and bound to the requesting principal. Missing or unverifiable
  context denies risk-controlled actions rather than defaulting to zero risk.
- **Approvals** (`approvals`) — each entry is signed by an approval system
  and bound to the exact request ID, action, and resource. The engine
  additionally enforces separation of duty (a requester or delegate cannot
  approve their own request) and, where configured, that the approver holds
  a permitted role.
- **Delegation hops** (`delegation_chain`) — each hop is signed by its
  issuer (the prior delegator) and carries issuer, subject, audience, a
  parent-delegation link, action/resource restrictions, expiration, and a
  nonce, so a chain cannot be reordered, truncated, or have hops forged or
  inserted, and revoked delegations are rejected even if still validly
  signed.
- **Cross-tenant access** is never a single boolean. `PolicyBundle.cross_tenant_trust`
  is an explicit list of `(source tenant, destination tenant, resource
  pattern, relationship, action)` grants; nothing crosses a tenant boundary
  without matching one exactly.

`--issuer-secret` is a single shared HMAC key in this reference
implementation, standing in for what would be per-issuer keys (or full
asymmetric signatures) in a production deployment — see
[Security position](#security-position).

## Core decision flow

1. Validate the request schema.
2. Check principal, mission, and resource revocation.
3. Enforce tenant closure — same-tenant by default, cross-tenant only against
   an explicit `cross_tenant_trust` grant.
4. Validate mission expiration, action, resource, impact, and delegation depth.
5. Verify authority attenuation across signed, chained delegation hops.
6. Evaluate role and attribute requirements.
7. Validate required relationships.
8. Verify signed approvals (with separation-of-duty and role checks) and a
   signed security context; apply approval and risk obligations.
9. Return allow, deny, or conditional allow.
10. Sign a decision receipt, capped to expire no later than the mission
    itself, for audit and verification.

## Security position

HWAAM is a reference implementation, not a complete identity provider or production policy service. Production deployment requires hardened key management, authenticated policy distribution, durable revocation, protected audit storage, service-to-service authentication, monitoring, and independent security review.

The engine defaults to deny when required policy, attributes, relationships, or revocation information is missing.

## Test and benchmark evidence

The repository contains reproducible results generated from the included code:

- [Test results](research/test-results.md)
- [Benchmark results](research/benchmark-results.md)
- [Impact analysis](research/impact.md)
- [Threat model](research/threat-model.md)

Benchmark figures describe the local execution environment only. They are not production performance claims.

## GitHub Pages

The website is located in `docs/`. The included Pages workflow deploys it automatically after GitHub Pages is configured to use GitHub Actions.

Expected project URL:

```text
https://sunilgentyala.github.io/hwaam-authorization-mesh/
```

## Project status

Version 0.2.0 provides a testable reference engine and research artifact. See [ROADMAP.md](ROADMAP.md) for planned integrations with OPA, Cedar, OpenFGA, OAuth token exchange, Kubernetes admission controls, and agent tool gateways.

## How to Cite

If you use HWAAM Authorization Mesh in your research, please cite the software:

```bibtex
@software{gentyala2026hwaam,
  author    = {Gentyala, Sunil and Darisi, Suresh Kumar},
  title     = {HWAAM Authorization Mesh},
  year      = {2026},
  version   = {0.2.0},
  url       = {https://github.com/sunilgentyala/hwaam-authorization-mesh}
}
```

Machine-readable metadata is in [`CITATION.cff`](CITATION.cff); GitHub shows it under "Cite this repository".

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
