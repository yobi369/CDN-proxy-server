# Security Policy

## Scope

This project is an origin-allowlisted caching proxy prototype. It is not intended to be an unrestricted public proxy or a globally distributed CDN.

## Deployment requirements

- Keep the listener bound to loopback unless a reviewed ingress layer provides TLS, client authentication, rate limiting, and request logging.
- Configure `CDN_ALLOWED_HOSTS` with exact origin hostnames you control or are authorized to proxy.
- Use a long, random `PROXY_STATS_TOKEN` and do not commit secrets.
- Retain outbound firewall rules that block private, loopback, link-local, metadata-service, and other non-public destinations.
- Keep the runtime non-root and restrict filesystem access.
- Do not cache authenticated/cookie-bearing requests or responses that set cookies or use `Vary` until complete variant-aware caching is implemented.
- Treat the adaptive policy as untrusted experimental logic. It must not modify destination allowlists, authentication, or resource ceilings.

## Reporting a vulnerability

Do not publish details of an exploitable vulnerability in a public issue. If GitHub private vulnerability reporting is enabled for this repository, use it. Otherwise contact the repository maintainer privately through GitHub to arrange coordinated disclosure.

## Security limitations

The allowlist and public-address DNS resolver reduce SSRF exposure but do not replace deployment-level egress filtering. The application has not yet undergone an independent security audit or penetration test. Do not use it as a public internet-facing service for sensitive workloads without additional review.
