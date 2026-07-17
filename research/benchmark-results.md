# Benchmark Results

Generated: `2026-07-16T23:51:24.289370+00:00`

## Local result

- Iterations: **20,000**
- Decisions per second: **45,838.91**
- Mean latency: **0.0215 ms**
- Median latency: **0.0210 ms**
- P95 latency: **0.0239 ms**
- P99 latency: **0.0350 ms**
- Maximum latency: **0.2200 ms**
- Python: `3.13.5`
- Platform: `Linux-4.4.0-x86_64-with-glibc2.41`

## Scope and limitation

In-process Python reference engine with in-memory policy, relationship, and revocation data. Results are not production claims.

The benchmark signs every decision receipt with HMAC-SHA256. It excludes network latency, external databases, durable audit storage, remote identity providers, and production cryptographic key services.
