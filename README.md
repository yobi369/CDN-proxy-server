# CDN Proxy Server

A small asynchronous HTTP caching proxy with bounded disk cache, origin response limits, request throttling, analytics, and defensive URL/DNS validation.

## Security model

- Binds to `127.0.0.1` by default. Binding to a non-loopback address requires `PROXY_API_KEY`. Send it as `Authorization: Bearer <key>` (or the raw key in the header).
- Accepts only HTTP/HTTPS URLs on standard ports; rejects credentials, local hostnames, and non-public literal IPs. The custom DNS resolver rejects private/reserved DNS answers, including for redirect targets. This is defense in depth, not a substitute for network-level egress controls.
- Caps upstream response size and upstream time, reuses a pooled HTTP client, and limits per-client request rates. The limiter is process-local; use a shared gateway/store for multi-instance deployments.
- Caches only successful responses that do not opt out via `Cache-Control: private`, `no-store`, or `no-cache`; skips `Vary: *` and responses with cookies. Disk entries are evicted oldest-first to enforce the configured body-size budget.
- `/stats` requires the API key when configured. `/health` is intentionally unauthenticated for liveness checks. CORS is disabled unless exact origins are listed in `CORS_ORIGINS`.

## Quick start

Requires Python 3.11+.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # edit values; export them in your shell before launch
python cdn_proxy_server.py
```

Example request:

```bash
curl -G 'http://127.0.0.1:8080/proxy' --data-urlencode 'url=https://example.com/'
curl 'http://127.0.0.1:8080/health'
```

For remote access, generate a strong secret (for example, `python -c 'import secrets; print(secrets.token_urlsafe(32))'`), set `PROXY_API_KEY`, set `HOST` to the intended interface, and put the service behind TLS and a firewall. Never expose an unauthenticated open proxy.

## Configuration

See `.env.example`. Environment variables are read by the process; the app does not automatically parse `.env` files. Keep secrets out of source control.

## Tests

```bash
pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m compileall -q cdn_proxy_server.py tests
```

## Operational notes

The analytics database stores a hash of the requested URL rather than the full URL, avoiding accidental storage of query-string secrets. The in-memory rate limiter and statistics reset on process restart. For production scale, use shared rate limiting, persistent metrics, structured log aggregation, TLS termination, outbound network policies, and a dedicated cache backend.
