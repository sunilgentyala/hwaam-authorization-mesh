# Research Artifacts

This directory contains reproducible evidence and analysis for the HWAAM reference implementation.

- `impact.md`: Security, operational, and research impact
- `threat-model.md`: Threat actors, assets, scenarios, and controls
- `test-results.json`: Machine-readable test execution result
- `test-results.md`: Human-readable test report
- `benchmark-results.json`: Machine-readable local benchmark
- `benchmark-results.md`: Human-readable benchmark report

Run:

```bash
python scripts/run_tests.py
python scripts/benchmark.py --iterations 20000
python scripts/generate_results.py
```
