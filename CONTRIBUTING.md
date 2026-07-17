# Contributing to HWAAM

Thank you for contributing to HWAAM.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python scripts/run_tests.py
```

On Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e .
python scripts/run_tests.py
```

## Contribution requirements

Every authorization change must include:

- A clear threat or operational gap
- A deterministic rule
- A defined fail-closed behavior
- Positive tests
- Negative tests
- Tenant-boundary tests when relevant
- Delegation and revocation tests when relevant
- Updated documentation

Do not merge a rule that broadens access only to make an existing test pass.

## Commit guidance

Use clear commit messages such as:

```text
feat: add mission output restriction
fix: deny tenant mismatch before role evaluation
test: add delegated authority expansion case
docs: explain receipt verification
```

## Security reports

Do not open a public issue for a suspected vulnerability. Follow [SECURITY.md](SECURITY.md).
