#!/usr/bin/env python3
"""Estimate cache-policy energy from user-supplied measurements and a synthetic workload."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from experiments.cache_policy_benchmark import make_trace, simulate


def energy_report(requests: int, objects: int, seed: int, energy_budget_mwh: float,
                  measured_harvested_energy_mwh: float, cache_hit_energy_mwh: float,
                  origin_miss_energy_mwh: float) -> dict:
    if requests < 1 or objects < 1:
        raise ValueError("requests and objects must be positive")
    values = (energy_budget_mwh, measured_harvested_energy_mwh,
              cache_hit_energy_mwh, origin_miss_energy_mwh)
    if any(value < 0 for value in values):
        raise ValueError("energy inputs must be non-negative")
    trace = make_trace(requests, objects, seed)
    available = energy_budget_mwh + measured_harvested_energy_mwh
    policies = []
    for mode in ("fixed", "adaptive"):
        metrics = simulate(trace, mode)
        estimated = (
            metrics["cache_hits"] * cache_hit_energy_mwh
            + metrics["origin_requests"] * origin_miss_energy_mwh
        )
        policies.append({
            "policy": mode,
            "cache_hits": metrics["cache_hits"],
            "origin_requests": metrics["origin_requests"],
            "hit_ratio": metrics["hit_ratio"],
            "estimated_energy_mwh": round(estimated, 9),
            "energy_per_request_mwh": round(estimated / requests, 9),
            "available_energy_mwh": round(available, 9),
            "budget_margin_mwh": round(available - estimated, 9),
            "energy_budget_sufficient_for_entire_trace": estimated <= available,
        })
    return {
        "experiment": "measured-input-energy-budget-estimate",
        "seed": seed,
        "workload": {"requests": requests, "unique_objects": objects, "pattern": "Zipf-like popularity"},
        "measurement_inputs_mwh": {
            "available_stored_energy_budget": energy_budget_mwh,
            "measured_harvested_energy_added": measured_harvested_energy_mwh,
            "measured_cache_hit_energy_per_request": cache_hit_energy_mwh,
            "measured_origin_miss_energy_per_request": origin_miss_energy_mwh,
        },
        "results": policies,
        "simulation_only": True,
        "interpretation": "Workload is synthetic; energy costs and harvested energy must come from measurements. Excludes idle power, conversion/storage losses, and measurement uncertainty unless separately included in supplied values. Does not infer usable energy from ambient RF presence.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requests", type=int, default=10000)
    parser.add_argument("--objects", type=int, default=100)
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--energy-budget-mwh", type=float, required=True)
    parser.add_argument("--measured-harvested-energy-mwh", type=float, required=True)
    parser.add_argument("--cache-hit-energy-mwh", type=float, required=True)
    parser.add_argument("--origin-miss-energy-mwh", type=float, required=True)
    args = parser.parse_args()
    try:
        report = energy_report(
            args.requests, args.objects, args.seed, args.energy_budget_mwh,
            args.measured_harvested_energy_mwh, args.cache_hit_energy_mwh,
            args.origin_miss_energy_mwh,
        )
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2))
