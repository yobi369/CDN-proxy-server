# Adaptive Edge Research Protocol

## Purpose

The experimental layer explores whether simple adaptive policies can improve edge-cache behavior under particular workloads. It does not assume that emergent behavior, evolutionary search, swarm coordination, or other unconventional-computing ideas outperform conventional methods.

## Baselines

Every candidate must be compared with at least:
1. Fixed TTL with the same cache capacity.
2. A documented recency-based policy.
3. The candidate adaptive policy with its parameters recorded.

## Synthetic benchmark

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

## Safety invariants

An experimental policy may adjust only explicitly bounded performance parameters. It may not change the destination allowlist, resolver behavior, authentication, authorization, response privacy rules, rate limits, or maximum resource budgets. Evolutionary or multi-agent experiments should run offline or in a sandbox, and any candidate configuration should pass the full test suite before deployment.

## Reporting format

Each experiment report should include the hypothesis, baseline, workload, hardware/runtime details, parameter values, number of repetitions, raw result artifact, summary statistics, limitations, and a clear statement of whether results are synthetic or measured.
