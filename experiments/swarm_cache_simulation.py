#!/usr/bin/env python3
"""Simulate decentralized cache-demand hints without sharing payloads or private URLs."""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from experiments.cache_policy_benchmark import make_trace


def simulate_swarm(requests: int = 10000, objects: int = 100, nodes: int = 4,
                   seed: int = 2026, ttl_seconds: int = 60,
                   sync_interval: int = 100, hot_threshold: int = 3,
                   cold_ttl_fraction: float = 0.5) -> dict:
    if requests < 1 or objects < 1 or nodes < 2 or sync_interval < 1 or ttl_seconds < 1:
        raise ValueError("requests/objects/sync interval/TTL must be positive and nodes must be at least 2")
    if hot_threshold < 1 or not 0.05 <= cold_ttl_fraction <= 1.0:
        raise ValueError("hot_threshold must be positive and cold_ttl_fraction must be in [0.05, 1.0]")

    trace = make_trace(requests, objects, seed)
    node_rng = random.Random(seed + 1)
    assignments = [node_rng.randrange(nodes) for _ in trace]
    step_seconds = 0.25

    def run(cooperative: bool) -> dict:
        caches: list[dict[str, float]] = [dict() for _ in range(nodes)]
        local_counts: list[Counter[str]] = [Counter() for _ in range(nodes)]
        global_hints: Counter[str] = Counter()
        hits = 0
        origin_requests = 0
        control_syncs = 0
        control_bytes = 0

        for index, (key, node) in enumerate(zip(trace, assignments)):
            now = index * step_seconds
            cache = caches[node]
            if cache.get(key, -1) > now:
                hits += 1
            else:
                origin_requests += 1
                if cooperative and global_hints[key] >= hot_threshold:
                    ttl = ttl_seconds
                elif cooperative:
                    ttl = max(1, int(ttl_seconds * cold_ttl_fraction))
                else:
                    ttl = ttl_seconds
                cache[key] = now + ttl
            local_counts[node][key] += 1

            if cooperative and (index + 1) % sync_interval == 0:
                global_hints = Counter()
                for counts in local_counts:
                    global_hints.update(counts)
                control_syncs += 1
                # Estimated control-plane payload: key digest + counter per hint per peer.
                control_bytes += len(global_hints) * 16 * nodes * (nodes - 1)

        return {
            "policy": "cooperative-hints" if cooperative else "independent-fixed-ttl",
            "requests": len(trace),
            "nodes": nodes,
            "cache_hits": hits,
            "origin_requests": origin_requests,
            "hit_ratio": round(hits / len(trace), 6),
            "control_syncs": control_syncs,
            "estimated_control_plane_bytes": control_bytes,
        }

    return {
        "experiment": "decentralized-edge-cache-hints",
        "seed": seed,
        "workload": {"requests": requests, "unique_objects": objects, "pattern": "Zipf-like popularity"},
        "parameters": {
            "nodes": nodes,
            "ttl_seconds": ttl_seconds,
            "sync_interval_requests": sync_interval,
            "hot_threshold": hot_threshold,
            "cold_ttl_fraction": cold_ttl_fraction,
        },
        "results": [run(False), run(True)],
        "payloads_shared": False,
        "simulation_only": True,
        "interpretation": "Synthetic control-plane experiment only. Hint messages are estimated; no real nodes or network traffic are used.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requests", type=int, default=10000)
    parser.add_argument("--objects", type=int, default=100)
    parser.add_argument("--nodes", type=int, default=4)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--ttl", type=int, default=60)
    parser.add_argument("--sync-interval", type=int, default=100)
    parser.add_argument("--hot-threshold", type=int, default=3)
    parser.add_argument("--cold-ttl-fraction", type=float, default=0.5)
    args = parser.parse_args()
    print(json.dumps(simulate_swarm(
        args.requests, args.objects, args.nodes, args.seed, args.ttl,
        args.sync_interval, args.hot_threshold, args.cold_ttl_fraction,
    ), indent=2))
