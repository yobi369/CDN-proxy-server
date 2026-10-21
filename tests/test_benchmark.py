import unittest
from experiments.cache_policy_benchmark import run_benchmark

class BenchmarkTests(unittest.TestCase):
    def test_benchmark_is_reproducible(self):
        self.assertEqual(run_benchmark(200, 12, 7), run_benchmark(200, 12, 7))

    def test_results_are_bounded_and_account_for_every_request(self):
        report = run_benchmark(250, 15, 11)
        self.assertFalse(report["assumptions"]["production_measurement"])
        for result in report["results"]:
            self.assertEqual(result["cache_hits"] + result["origin_requests"], 250)
            self.assertGreaterEqual(result["hit_ratio"], 0)
            self.assertLessEqual(result["hit_ratio"], 1)

    def test_rejects_invalid_workload(self):
        with self.assertRaises(ValueError):
            run_benchmark(0, 10, 1)

if __name__ == "__main__":
    unittest.main()
