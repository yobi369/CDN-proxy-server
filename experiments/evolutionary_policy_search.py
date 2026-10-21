#!/usr/bin/env python3
"""Seeded evolutionary search over safe adaptive-cache parameters (simulation only)."""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from experiments.cache_policy_benchmark import make_trace, simulate


def clamp(value: float, low: float, high: float) -> float:
    return min(high, max(low, value))


def evaluate(candidate: dict, trace: list[str], freshness_weight: float) -> dict:
    metrics = simulate(trace, "adaptive", policy_params=candidate)
    # Illustrative multi-objective score: cache hit ratio plus a configurable
    # reward for shorter cold-object TTLs. This is a research choice, not a universal optimum.
    score = metrics["hit_ratio"] + freshness_weight * (1.0 - candidate["cold_ttl_fraction"])
    return {"candidate": candidate, "score": round(score, 6), "metrics": metrics}


def search(requests: int = 3000, objects: int = 80, seed: int = 2026,
           generations: int = 8, population_size: int = 12,
           freshness_weight: float = 0.1) -> dict:
    if requests < 1 or objects < 1 or generations < 1 or population_size < 4:
        raise ValueError("requests, objects, generations must be positive and population_size at least 4")
    if freshness_weight < 0:
        raise ValueError("freshness_weight must be non-negative")

    rng = random.Random(seed)
    trace = make_trace(requests, objects, seed)
    population = [
        {
            "cold_ttl_fraction": round(rng.uniform(0.1, 1.0), 3),
            "warm_hit_threshold": round(rng.uniform(0.5, 0.95), 3),
            "min_observations": rng.randint(2, 6),
        }
        for _ in range(population_size)
    ]
    best = None
    for _ in range(generations):
        ranked = sorted(
            (evaluate(candidate, trace, freshness_weight) for candidate in population),
            key=lambda item: item["score"],
            reverse=True,
        )
        if best is None or ranked[0]["score"] > best["score"]:
            best = ranked[0]
        elites = [item["candidate"] for item in ranked[:max(2, population_size // 4)]]
        next_population = list(elites)
        while len(next_population) < population_size:
            parent = dict(rng.choice(elites))
            parent["cold_ttl_fraction"] = round(clamp(parent["cold_ttl_fraction"] + rng.uniform(-0.15, 0.15), 0.1, 1.0), 3)
            parent["warm_hit_threshold"] = round(clamp(parent["warm_hit_threshold"] + rng.uniform(-0.1, 0.1), 0.5, 0.95), 3)
            if rng.random() < 0.5:
                parent["min_observations"] = rng.randint(2, 6)
            next_population.append(parent)
        population = next_population

    final = evaluate(best["candidate"], trace, freshness_weight)
    return {
        "experiment": "evolutionary-adaptive-cache-parameter-search",
        "seed": seed,
        "generations": generations,
        "population_size": population_size,
        "freshness_weight": freshness_weight,
        "workload": {"requests": requests, "unique_objects": objects, "pattern": "Zipf-like popularity"},
        "candidate": final["candidate"],
        "objective_score": final["score"],
        "metrics": final["metrics"],
        "simulation_only": True,
        "interpretation": "Candidate parameters are not automatically deployed. Validate against baselines and representative workloads first.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requests", type=int, default=3000)
    parser.add_argument("--objects", type=int, default=80)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--generations", type=int, default=8)
    parser.add_argument("--population", type=int, default=12)
    parser.add_argument("--freshness-weight", type=float, default=0.1)
    args = parser.parse_args()
    print(json.dumps(search(args.requests, args.objects, args.seed, args.generations,
                            args.population, args.freshness_weight), indent=2))
