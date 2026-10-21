#!/usr/bin/env python3
"""Deterministic synthetic cache-policy benchmark; results are simulation only."""
from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cdn_proxy_server import AdaptivePolicy


def make_trace(requests: int, objects: int, seed: int) -> list[str]:
    """Generate a reproducible skewed popularity trace (not captured production traffic)."""
    rng = random.Random(seed)
    weights = [1 / rank for rank in range(1, objects + 1)]
    return [f"asset-{rng.choices(range(objects), weights=weights, k=1)[0]}" for _ in range(requests)]


def simulate(trace: list[str], mode: str, ttl_seconds: int = 60,
             step_seconds: float = 0.25) -> dict:
    cache_expiry: dict[str, float] = {}
    adaptive = AdaptivePolicy()
    latencies: list[float] = []
    hits = 0
    origin_requests = 0

    for index, key in enumerate(trace):
        now = index * step_seconds
        if cache_expiry.get(key, -1) > now:
            hits += 1
            latencies.append(2.0)  # Synthetic cache-hit latency in milliseconds.
            adaptive.record(key, True)
            continue

        origin_requests += 1
        latencies.append(30.0)  # Synthetic origin latency in milliseconds.
        adaptive.record(key, False)
        ttl = ttl_seconds if mode == "fixed" else adaptive.adjust_ttl(key, ttl_seconds)
        if ttl > 0:
            cache_expiry[key] = now + ttl

    ordered = sorted(latencies)
    def percentile(p: float) -> float:
        if not ordered:
            return 0.0
        return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * p))]

    count = len(trace)
    return {
        "mode": mode,
        "requests": count,
        "cache_hits": hits,
        "origin_requests": origin_requests,
        "hit_ratio": round(hits / count, 6) if count else 0.0,
        "simulated_latency_ms": {
            "p50": round(statistics.median(ordered), 3) if ordered else 0.0,
            "p95": round(percentile(0.95), 3),
            "mean": round(statistics.fmean(ordered), 3) if ordered else 0.0,
        },
    }


def run_benchmark(requests: int = 10000, objects: int = 100, seed: int = 2026) -> dict:
    if requests < 1 or objects < 1:
        raise ValueError("requests and objects must be positive integers")
    trace = make_trace(requests, objects, seed)
    fixed = simulate(trace, "fixed")
    adaptive = simulate(trace, "adaptive")
    return {
        "benchmark": "synthetic-cache-policy-comparison",
        "seed": seed,
        "workload": {"requests": requests, "unique_objects": objects, "pattern": "Zipf-like popularity"},
        "assumptions": {
            "step_seconds": 0.25,
            "ttl_seconds": 60,
            "cache_hit_latency_ms": 2,
            "origin_latency_ms": 30,
            "production_measurement": False,
        },
        "results": [fixed, adaptive],
        "interpretation": "Synthetic comparison only. Run representative real workloads before making performance claims.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requests", type=int, default=10000)
    parser.add_argument("--objects", type=int, default=100)
    parser.add_argument("--seed", type=int, default=2026)
    args = parser.parse_args()
    print(json.dumps(run_benchmark(args.requests, args.objects, args.seed), indent=2))
