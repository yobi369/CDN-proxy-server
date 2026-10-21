import unittest
from experiments.evolutionary_policy_search import search


class EvolutionarySearchTests(unittest.TestCase):
    def test_search_is_reproducible_for_fixed_seed(self):
        first = search(requests=300, objects=20, seed=9, generations=3, population_size=6)
        second = search(requests=300, objects=20, seed=9, generations=3, population_size=6)
        self.assertEqual(first, second)
        self.assertTrue(first["simulation_only"])

    def test_candidate_parameters_stay_within_safe_bounds(self):
        result = search(requests=200, objects=12, seed=3, generations=2, population_size=4)
        candidate = result["candidate"]
        self.assertGreaterEqual(candidate["cold_ttl_fraction"], 0.1)
        self.assertLessEqual(candidate["cold_ttl_fraction"], 1.0)
        self.assertGreaterEqual(candidate["warm_hit_threshold"], 0.5)
        self.assertLessEqual(candidate["warm_hit_threshold"], 0.95)
        self.assertGreaterEqual(candidate["min_observations"], 2)
        self.assertLessEqual(candidate["min_observations"], 6)

    def test_rejects_too_small_population(self):
        with self.assertRaises(ValueError):
            search(requests=100, objects=10, generations=2, population_size=3)


if __name__ == "__main__":
    unittest.main()
