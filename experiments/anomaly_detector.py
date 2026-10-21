#!/usr/bin/env python3
"""Analyze proxy SQLite telemetry for robust latency/size outliers without exposing URLs or IPs."""
from __future__ import annotations

import argparse
import json
import sqlite3
import statistics
from collections import defaultdict
from pathlib import Path


def load_events(db_path: str, limit: int = 5000) -> list[dict]:
    if limit < 1 or limit > 100000:
        raise ValueError("limit must be between 1 and 100000")
    path = Path(db_path)
    if not path.is_file():
        raise FileNotFoundError(f"Analytics database not found: {path}")
    with sqlite3.connect(str(path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT id, timestamp, target_host, cache_status, response_size, response_time_ms
               FROM requests ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(row) for row in reversed(rows)]


def robust_scale(values: list[float]) -> tuple[float, float, float]:
    median = statistics.median(values)
    mad = statistics.median([abs(value - median) for value in values])
    # A zero MAD is common in small/quantized telemetry; use a conservative floor.
    scale = 1.4826 * mad if mad > 0 else max(abs(median) * 0.1, 1.0)
    return median, mad, scale


def analyze_events(events: list[dict], threshold: float = 3.5,
                   min_samples: int = 10) -> dict:
    if threshold <= 0 or min_samples < 3:
        raise ValueError("threshold must be positive and min_samples must be at least 3")
    usable = [event for event in events if not str(event.get("cache_status", "")).startswith("PURGE")]
    by_host: dict[str, list[dict]] = defaultdict(list)
    for event in usable:
        by_host[str(event.get("target_host") or "unknown")].append(event)

    baselines = {}
    for host, rows in by_host.items():
        if len(rows) < min_samples:
            continue
        latencies = [max(0.0, float(row.get("response_time_ms") or 0.0)) for row in rows]
        sizes = [max(0.0, float(row.get("response_size") or 0.0)) for row in rows]
        lat_med, lat_mad, lat_scale = robust_scale(latencies)
        size_med, size_mad, size_scale = robust_scale(sizes)
        baselines[host] = {
            "samples": len(rows),
            "latency_median_ms": round(lat_med, 3),
            "latency_mad_ms": round(lat_mad, 3),
            "size_median_bytes": round(size_med, 3),
            "size_mad_bytes": round(size_mad, 3),
            "_latency_scale": lat_scale,
            "_size_scale": size_scale,
        }

    anomalies = []
    for event in usable:
        host = str(event.get("target_host") or "unknown")
        baseline = baselines.get(host)
        if not baseline:
            continue
        latency = max(0.0, float(event.get("response_time_ms") or 0.0))
        size = max(0.0, float(event.get("response_size") or 0.0))
        latency_score = (latency - baseline["latency_median_ms"]) / baseline["_latency_scale"]
        size_score = (size - baseline["size_median_bytes"]) / baseline["_size_scale"]
        reasons = []
        if latency_score > threshold:
            reasons.append("latency_outlier")
        if size_score > threshold:
            reasons.append("response_size_outlier")
        if str(event.get("cache_status", "")).startswith("STREAM-ERROR"):
            reasons.append("stream_error")
        if reasons:
            anomalies.append({
                "event_id": event.get("id"),
                "timestamp": event.get("timestamp"),
                "target_host": host,
                "cache_status": event.get("cache_status"),
                "response_time_ms": round(latency, 3),
                "response_size_bytes": int(size),
                "reasons": sorted(set(reasons)),
                "robust_latency_score": round(latency_score, 3),
                "robust_size_score": round(size_score, 3),
            })

    public_baselines = {
        host: {key: value for key, value in data.items() if not key.startswith("_")}
        for host, data in baselines.items()
    }
    return {
        "analyzer": "robust-proxy-telemetry",
        "events_analyzed": len(usable),
        "hosts_with_baseline": len(public_baselines),
        "threshold_mad_sigma": threshold,
        "minimum_samples_per_host": min_samples,
        "baselines": public_baselines,
        "anomalies": anomalies,
        "interpretation": "Statistical flags are investigation leads, not proof of an attack or fault. This report omits client IPs and full URLs.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="analytics.db")
    parser.add_argument("--limit", type=int, default=5000)
    parser.add_argument("--threshold", type=float, default=3.5)
    parser.add_argument("--min-samples", type=int, default=10)
    args = parser.parse_args()
    try:
        events = load_events(args.db, args.limit)
        report = analyze_events(events, args.threshold, args.min_samples)
    except (ValueError, FileNotFoundError, sqlite3.Error) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2))
