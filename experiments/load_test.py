#!/usr/bin/env python3
"""Bounded load test for an explicitly configured, authorized CDN proxy."""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import statistics
import time
from collections import Counter
from urllib.parse import urlsplit

import aiohttp


def validate_urls(proxy_url: str, target_url: str, token: str | None) -> None:
    proxy = urlsplit(proxy_url)
    target = urlsplit(target_url)
    if proxy.scheme not in ("http", "https") or not proxy.hostname:
        raise ValueError("proxy-url must be an absolute HTTP(S) URL")
    if proxy.username is not None or proxy.password is not None:
        raise ValueError("proxy-url must not contain credentials")
    if target.scheme not in ("http", "https") or not target.hostname:
        raise ValueError("target-url must be an absolute HTTP(S) URL")
    if target.username is not None or target.password is not None:
        raise ValueError("target-url must not contain credentials")
    proxy_host = proxy.hostname.lower().rstrip(".")
    try:
        loopback = ipaddress.ip_address(proxy_host).is_loopback
    except ValueError:
        loopback = proxy_host == "localhost"
    if not loopback and not token:
        raise ValueError("a proxy access token is required for non-loopback proxy URLs")
    if not loopback and proxy.scheme != "https":
        raise ValueError("non-loopback proxy URLs must use HTTPS to protect the access token")


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, int((len(ordered) - 1) * p)))]


async def run_load_test(proxy_url: str, target_url: str, requests: int = 100,
                        concurrency: int = 10, timeout: float = 15.0,
                        token: str | None = None, max_response_bytes: int = 64 * 1024 * 1024) -> dict:
    if not 1 <= requests <= 10000:
        raise ValueError("requests must be between 1 and 10000")
    if not 1 <= concurrency <= 100:
        raise ValueError("concurrency must be between 1 and 100")
    if timeout <= 0 or max_response_bytes < 1:
        raise ValueError("timeout and max_response_bytes must be positive")
    validate_urls(proxy_url, target_url, token)

    semaphore = asyncio.Semaphore(concurrency)
    latencies: list[float] = []
    statuses: Counter[str] = Counter()
    cache_statuses: Counter[str] = Counter()
    errors: Counter[str] = Counter()
    total_bytes = 0
    started_all = time.perf_counter()
    headers = {"X-Proxy-Token": token} if token else {}

    async def one_request(session: aiohttp.ClientSession) -> None:
        nonlocal total_bytes
        async with semaphore:
            started = time.perf_counter()
            try:
                async with session.get(proxy_url, params={"url": target_url}, headers=headers) as response:
                    size = 0
                    async for chunk in response.content.iter_chunked(64 * 1024):
                        size += len(chunk)
                        if size > max_response_bytes:
                            errors["response_size_limit"] += 1
                            return
                    latencies.append((time.perf_counter() - started) * 1000)
                    statuses[str(response.status)] += 1
                    cache_statuses[response.headers.get("X-CDN-Cache", "UNKNOWN")] += 1
                    total_bytes += size
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                errors[type(exc).__name__] += 1

    timeout_config = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(timeout=timeout_config) as session:
        await asyncio.gather(*(one_request(session) for _ in range(requests)))
    elapsed = time.perf_counter() - started_all
    successful = len(latencies)
    return {
        "benchmark": "live-proxy-load-test",
        "target_host": urlsplit(target_url).hostname,
        "requests_requested": requests,
        "requests_completed": successful,
        "concurrency": concurrency,
        "elapsed_seconds": round(elapsed, 3),
        "throughput_requests_per_second": round(requests / elapsed, 3) if elapsed else 0.0,
        "latency_ms": {
            "p50": round(statistics.median(latencies), 3) if latencies else 0.0,
            "p95": round(percentile(latencies, 0.95), 3),
            "p99": round(percentile(latencies, 0.99), 3),
            "mean": round(statistics.fmean(latencies), 3) if latencies else 0.0,
        },
        "http_statuses": dict(statuses),
        "cache_statuses": dict(cache_statuses),
        "errors": dict(errors),
        "response_bytes_completed": total_bytes,
        "interpretation": "Live measurement of the configured endpoint. Run only against infrastructure and origins you are authorized to test; results depend on network, origin, warm-up, and workload.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy-url", default="http://127.0.0.1:8080/proxy")
    parser.add_argument("--target-url", required=True)
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--max-response-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--token", default=os.getenv("PROXY_ACCESS_TOKEN"))
    args = parser.parse_args()
    try:
        report = asyncio.run(run_load_test(
            args.proxy_url, args.target_url, args.requests, args.concurrency,
            args.timeout, args.token, args.max_response_bytes,
        ))
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2))
