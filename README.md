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
  --secret demo-secret
```

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

Evaluate an allowed request:

```bash
hwaam evaluate \
  --policy examples/policy.json \
  --request examples/request_allowed.json \
  --secret demo-secret
```

Evaluate a denied cross-tenant request:

```bash
hwaam evaluate \
  --policy examples/policy.json \
  --request examples/request_cross_tenant.json \
  --secret demo-secret
```

Verify a signed receipt:

```bash
hwaam verify-receipt \
  --receipt decision-receipt.json \
  --secret demo-secret
```

## Core decision flow

1. Validate the request schema.
2. Check principal, mission, and resource revocation.
3. enforce tenant closure.
4. Validate mission expiration, action, resource, impact, and delegation depth.
5. Check authority attenuation across delegation hops.
6. Evaluate role and attribute requirements.
7. Validate required relationships.
8. Apply approval and risk obligations.
9. Return allow, deny, or conditional allow.
10. Sign a decision receipt for audit and verification.

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

Version 0.1.0 provides a testable reference engine and research artifact. See [ROADMAP.md](ROADMAP.md) for planned integrations with OPA, Cedar, OpenFGA, OAuth token exchange, Kubernetes admission controls, and agent tool gateways.

## Citation

Citation metadata is provided in [CITATION.cff](CITATION.cff).

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
