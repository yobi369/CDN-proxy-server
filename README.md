# CDN Proxy Server — Adaptive Edge Research

A self-hostable Python HTTP caching proxy that combines conventional proxy engineering with a transparent adaptive-cache research layer. It runs on your own computer, VPS, or private infrastructure—not only inside GitHub.

## Capabilities

- Proxies GET requests to explicitly allowlisted HTTP(S) origins.
- Disk cache with expiry, per-object limit, and a global storage budget.
- Respects restrictive origin cache directives such as no-store, private, and no-cache; avoids caching Set-Cookie responses.
- Health endpoint and token-protected statistics endpoint.
- SQLite request metadata without response-body logging.
- Conservative adaptive policy that shortens TTL for cold objects but never extends origin-approved TTL.

## Security model

**This is not an open proxy.** Configure CDN_ALLOWED_HOSTS with exact hostnames you control or are authorized to proxy. Other hosts are rejected. Redirect following is disabled so an allowed origin cannot redirect the proxy to another destination.

The service binds to 127.0.0.1 by default. Do not expose it directly to the public internet without an authentication layer, TLS termination, firewall/rate-limit review, and operational monitoring. The /stats endpoint requires PROXY_STATS_TOKEN; if no token is configured, stats access stays disabled. The /proxy endpoint requires PROXY_ACCESS_TOKEN when configured and refuses tokenless operation on non-loopback binds.

The host allowlist is a strong first boundary, not a substitute for deployment network controls. For sensitive environments, restrict outbound network traffic at the host/container firewall too.

## Quick start

Requires Python 3.11 or newer.

    python -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

Set CDN_ALLOWED_HOSTS to comma-separated exact hostnames and PROXY_STATS_TOKEN to a long random secret, then run:

    export CDN_ALLOWED_HOSTS="example.com,www.example.com"
    export PROXY_STATS_TOKEN="replace-with-a-long-random-secret"
    python cdn_proxy_server.py

On Windows, activate the environment with .venv\Scripts\activate.

Try it:

    curl http://127.0.0.1:8080/health
    curl -i "http://127.0.0.1:8080/proxy?url=https%3A%2F%2Fexample.com%2F"
    curl -H "Authorization: Bearer replace-with-a-long-random-secret" http://127.0.0.1:8080/stats

The target hostname must exactly match an entry in CDN_ALLOWED_HOSTS. Never put secrets in URLs.

## Docker deployment

Docker Engine with the Compose plugin is required. Copy `.env.example` to `.env` and replace the example hostnames and secret (never commit `.env`):

    CDN_ALLOWED_HOSTS=example.com,www.example.com
    PROXY_STATS_TOKEN=replace-with-a-long-random-secret

Then build and start:

    docker compose up --build -d
    curl http://127.0.0.1:8080/health
    curl -H "X-Proxy-Token: replace-with-a-different-long-random-secret" "http://127.0.0.1:8080/proxy?url=https%3A%2F%2Fexample.com%2F"
    docker compose logs -f cdn-proxy

The published port is bound to loopback only. Container deployments require both `PROXY_ACCESS_TOKEN` (sent as `X-Proxy-Token` to `/proxy`) and `PROXY_STATS_TOKEN` (sent as a bearer token to `/stats`). Use different random secrets. The container runs as a non-root user, drops Linux capabilities, uses a read-only root filesystem, and stores cache/database data in named volumes. Do not change the port binding to a public interface until TLS, client authentication, firewall policy, and deployment-specific egress controls have been configured and tested.

Stop the service with `docker compose down`. Named volumes persist until explicitly removed.

## Configuration

| Variable | Default | Purpose |
|---|---:|---|
| PROXY_HOST | 127.0.0.1 | Bind address |
| PROXY_PORT | 8080 | Listen port |
| CDN_ALLOWED_HOSTS | empty; startup blocked | Comma-separated exact host allowlist |
| PROXY_CACHE_DIR | ./cache | Cache directory |
| PROXY_ANALYTICS_DB | ./analytics.db | SQLite database |
| PROXY_MAX_CACHE_BYTES | 268435456 | Approximate cache storage budget |
| PROXY_MAX_OBJECT_BYTES | 8388608 | Maximum accepted origin body size |
| PROXY_DEFAULT_TTL | 300 | Fallback TTL if origin gives no freshness |
| PROXY_MAX_TTL | 86400 | Maximum cache TTL |
| PROXY_TIMEOUT_SECONDS | 15 | Origin request timeout |
| PROXY_RATE_LIMIT | 120 | Requests/minute per observed client IP |
| PROXY_ACCESS_TOKEN | empty | Token for /proxy when configured; mandatory for non-loopback binds, sent as X-Proxy-Token |
| PROXY_STATS_TOKEN | empty | Bearer token for /stats |

Rate limiting and statistics are process-local, not distributed multi-node coordination.

## Adaptive and unconventional computing research

AdaptivePolicy is intentionally conservative and explainable. It uses observed hit/miss reuse to shorten TTL for cold objects while respecting origin restrictions. It is a baseline for experiments, not a claim of autonomous intelligence or a proven performance win.

Research directions:
- Compare fixed-TTL and recency/frequency-aware policies.
- Use online adaptation with bounded parameters and explicit safety invariants.
- Use evolutionary search to tune safe cache-policy parameters offline.
- Explore cooperative multi-node hints without sharing private payloads.
- Investigate energy-aware scheduling only where actual power measurements are available.

Evaluate experiments against a fixed baseline with reproducible workloads, warm-up periods, repeated runs, and metrics such as hit ratio, p50/p95 latency, origin bytes avoided, resource use, and error rate. A policy must never weaken SSRF protections, authorization, cache privacy, or resource limits. Do not describe simulations as production results.

## Development and tests

    pip install -r requirements-dev.txt
    python -m unittest discover -s tests -v
    python experiments/cache_policy_benchmark.py --requests 10000 --objects 100 --seed 2026
    python experiments/evolutionary_policy_search.py --requests 3000 --objects 80 --generations 8 --population 12 --seed 2026

The benchmark uses a deterministic synthetic Zipf-like workload and illustrative latency assumptions. Its output is **simulation, not a production performance claim**. Use representative traffic and measured origin/cache latency before selecting a policy.

GitHub Actions runs the tests on pushes and pull requests. GitHub is used for source control and verification; the proxy itself runs independently on your infrastructure.

## Current limitations

- Single-process prototype, not a globally distributed CDN.
- No TLS termination, user accounts, purge API, distributed rate limiting, or multi-node cache coherence.
- Client-side conditional response handling, Range caching, streaming large objects, and complete RFC cache semantics need more implementation and tests before production use. Expired cached objects can be conditionally revalidated with origin ETag/Last-Modified validators.
- Review deployment topology and outbound firewall rules before allowing access beyond localhost.

## License

No license has been declared. Until one is added, the repository grants no explicit open-source reuse license.
