# Benchmark Results

Generated: `2026-07-17T04:28:46.362970+00:00`

## Local result

- Iterations: **2,000**
- Decisions per second: **27,476.19**
- Mean latency: **0.0361 ms**
- Median latency: **0.0344 ms**
- P95 latency: **0.0381 ms**
- P99 latency: **0.0682 ms**
- Maximum latency: **0.3571 ms**
- Python: `3.14.4`
- Platform: `Windows-11-10.0.26200-SP0`

## Scope and limitation

In-process Python reference engine with in-memory policy, relationship, and revocation data. Results are not production claims.

The benchmark signs every decision receipt with HMAC-SHA256. It excludes network latency, external databases, durable audit storage, remote identity providers, and production cryptographic key services.
