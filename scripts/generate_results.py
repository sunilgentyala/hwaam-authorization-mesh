"""Generate human-readable reports from test and benchmark JSON."""

from __future__ import annotations

from pathlib import Path
import html
import json
import re


ROOT = Path(__file__).resolve().parents[1]


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def count_tests(output: str) -> int:
    match = re.search(r"Ran (\d+) tests?", output)
    return int(match.group(1)) if match else 0


def main() -> int:
    test_json = load(ROOT / "research" / "test-results.json")
    benchmark = load(ROOT / "research" / "benchmark-results.json")
    tests_run = count_tests(test_json["output"])

    test_md = f"""# Test Results

Generated: `{test_json['generated_at']}`

## Summary

- Status: **{test_json['status'].upper()}**
- Tests executed: **{tests_run}**
- Exit code: `{test_json['exit_code']}`
- Python: `{test_json['python']}`
- Platform: `{test_json['platform']}`

## Command

```text
{test_json['command']}
```

## Complete output

```text
{test_json['output']}
```

These results were generated from the repository's standard-library test suite.
"""
    (ROOT / "research" / "test-results.md").write_text(
        test_md,
        encoding="utf-8",
    )

    latency = benchmark["latency_ms"]
    benchmark_md = f"""# Benchmark Results

Generated: `{benchmark['generated_at']}`

## Local result

- Iterations: **{benchmark['iterations']:,}**
- Decisions per second: **{benchmark['decisions_per_second']:,.2f}**
- Mean latency: **{latency['mean']:.4f} ms**
- Median latency: **{latency['median']:.4f} ms**
- P95 latency: **{latency['p95']:.4f} ms**
- P99 latency: **{latency['p99']:.4f} ms**
- Maximum latency: **{latency['maximum']:.4f} ms**
- Python: `{benchmark['python']}`
- Platform: `{benchmark['platform']}`

## Scope and limitation

{benchmark['scope']}

The benchmark signs every decision receipt with HMAC-SHA256. It excludes network latency, external databases, durable audit storage, remote identity providers, and production cryptographic key services.
"""
    (ROOT / "research" / "benchmark-results.md").write_text(
        benchmark_md,
        encoding="utf-8",
    )

    page = ROOT / "docs" / "test-results.html"
    page.write_text(
        f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>HWAAM Test Results</title>
  <link rel="stylesheet" href="assets/style.css">
</head>
<body>
<header class="site-header"><a href="index.html">HWAAM</a></header>
<main class="container">
  <h1>Test and benchmark results</h1>
  <section class="metric-grid">
    <article><strong>{tests_run}</strong><span>tests executed</span></article>
    <article><strong>{html.escape(test_json['status'].upper())}</strong><span>test status</span></article>
    <article><strong>{benchmark['decisions_per_second']:,.0f}</strong><span>decisions per second</span></article>
    <article><strong>{latency['p95']:.4f} ms</strong><span>P95 local latency</span></article>
  </section>
  <p class="notice">These measurements describe one local, in-process run. They are not production performance claims.</p>
  <h2>Test output</h2>
  <pre>{html.escape(test_json['output'])}</pre>
  <h2>Benchmark environment</h2>
  <pre>{html.escape(json.dumps(benchmark, indent=2))}</pre>
</main>
<footer>HWAAM reference implementation</footer>
</body>
</html>
""",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
