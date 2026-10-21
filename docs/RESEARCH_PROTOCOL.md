# Adaptive Edge Research Protocol

## Purpose

The experimental layer explores whether simple adaptive policies can improve edge-cache behavior under particular workloads. It does not assume that emergent behavior, evolutionary search, swarm coordination, or other unconventional-computing ideas outperform conventional methods.

## Baselines

Every candidate must be compared with at least:
1. Fixed TTL with the same cache capacity.
2. A documented recency-based policy.
3. The candidate adaptive policy with its parameters recorded.
4. Where relevant, a resource-aware policy that accounts for measured CPU, memory, network, and power costs.

## Synthetic benchmark

Run the decentralized hint experiment:

```bash
python experiments/swarm_cache_simulation.py --requests 10000 --objects 100 --nodes 4 --sync-interval 100 --seed 2026
```

This compares independent fixed-TTL caches with cooperative aggregate-demand hints. It models control-plane overhead and never exchanges response payloads. It is a synthetic simulation, not evidence that real multi-node deployments will improve performance.


Run:

```bash
python experiments/cache_policy_benchmark.py --requests 10000 --objects 100 --seed 2026
```

The script uses a deterministic skewed synthetic request trace and illustrative hit/origin latency values. It is a functional experiment, not a production load test. The seed and workload parameters must be preserved when comparing runs.

## Production-style evaluation before claiming gains

- Use a workload that is representative and legally safe to collect.
- Separate warm-up from measurement and repeat each experiment.
- Keep hardware, network, cache capacity, origin, concurrency, and request mix controlled.
- Record p50/p95/p99 latency, hit ratio, origin request reduction, bytes transferred, CPU, memory, disk I/O, and error rates.
- Include confidence intervals or report run-to-run variation.
- Report failures and regressions, not only the best result.
- Never include credentials, personal data, or private response bodies in benchmark artifacts.

## Research directions grounded in the broader project vision

- **Self-modifying software:** let an optimizer propose bounded policy configurations or code changes in an isolated experiment branch. It must not self-edit security boundaries, credentials, allowlists, network access, or deployment controls. Candidate changes require reproducible tests, reviewable diffs, and a rollback path before promotion.
- **Swarm / decentralized edge coordination:** test exchanging compact cache-demand hints or aggregate counters between nodes. Do not exchange private response bodies or credentials. Compare coordination overhead and failure behavior against independent nodes.
- **Evolutionary optimization:** search a constrained parameter space offline, keep the seed and objective function fixed, and retain baseline comparisons to avoid overfitting.
- **Energy-aware operation and harvesting research:** measure device power draw and any harvested electrical input with calibrated instrumentation. Ambient RF presence is not evidence of useful net power; record input power, conversion efficiency, storage losses, and workload energy before claiming energy independence.
- **Emergent behavior:** describe a behavior as emergent only when it is observed in repeatable multi-agent experiments and distinguish it from ordinary programmed rules.


An experimental policy may adjust only explicitly bounded performance parameters. It may not change the destination allowlist, resolver behavior, authentication, authorization, response privacy rules, rate limits, or maximum resource budgets. Evolutionary or multi-agent experiments should run offline or in a sandbox, and any candidate configuration should pass the full test suite before deployment.

## Reporting format

Each experiment report should include the hypothesis, baseline, workload, hardware/runtime details, parameter values, number of repetitions, raw result artifact, summary statistics, limitations, and a clear statement of whether results are synthetic or measured.
