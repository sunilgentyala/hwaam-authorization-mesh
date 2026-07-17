# File Manifest

## Core implementation

- `src/hwaam/engine.py`: Deterministic decision engine
- `src/hwaam/models.py`: Principal, resource, mission, delegation, request, and decision models
- `src/hwaam/policy.py`: Fail-closed policy loading and validation
- `src/hwaam/relationships.py`: Tenant-scoped relationship graph
- `src/hwaam/revocation.py`: Principal, mission, and resource revocation
- `src/hwaam/receipts.py`: HMAC-SHA256 decision receipts
- `src/hwaam/cli.py`: Evaluation and receipt-verification commands

## Tests and evidence

- `tests/`: 22 authorization tests
- `research/test-results.json`: Machine-readable test output
- `research/test-results.md`: Human-readable test output
- `research/benchmark-results.json`: Machine-readable local benchmark
- `research/benchmark-results.md`: Human-readable local benchmark
- `research/impact.md`: Security and operational impact analysis
- `research/threat-model.md`: Threat model and control mapping

## GitHub and website

- `.github/workflows/ci.yml`: Multi-version Python CI
- `.github/workflows/pages.yml`: GitHub Pages deployment
- `docs/`: Static GitHub Pages website
- `UPLOAD_TO_GITHUB.md`: Manual upload and Pages instructions

## Project governance

- `README.md`
- `LICENSE`
- `NOTICE`
- `SECURITY.md`
- `CONTRIBUTING.md`
- `CODE_OF_CONDUCT.md`
- `CITATION.cff`
- `ROADMAP.md`
- `CHANGELOG.md`
