import unittest
from experiments.swarm_cache_simulation import simulate_swarm


class SwarmSimulationTests(unittest.TestCase):
    def test_simulation_is_reproducible(self):
        a = simulate_swarm(requests=400, objects=20, nodes=3, seed=7, sync_interval=20)
        b = simulate_swarm(requests=400, objects=20, nodes=3, seed=7, sync_interval=20)
        self.assertEqual(a, b)
        self.assertTrue(a["simulation_only"])
        self.assertFalse(a["payloads_shared"])

    def test_requests_are_accounted_for_and_control_overhead_is_reported(self):
        result = simulate_swarm(requests=300, objects=15, nodes=3, seed=5, sync_interval=25)
        for policy in result["results"]:
            self.assertEqual(policy["cache_hits"] + policy["origin_requests"], 300)
        cooperative = result["results"][1]
        self.assertGreater(cooperative["control_syncs"], 0)
        self.assertGreater(cooperative["estimated_control_plane_bytes"], 0)

    def test_rejects_single_node_swarm(self):
        with self.assertRaises(ValueError):
            simulate_swarm(requests=10, objects=5, nodes=1)

if __name__ == "__main__":
    unittest.main()
