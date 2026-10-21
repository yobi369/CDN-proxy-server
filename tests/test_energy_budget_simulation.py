import unittest
from experiments.energy_budget_simulation import energy_report


class EnergyBudgetSimulationTests(unittest.TestCase):
    def test_uses_measured_inputs_and_reports_estimates(self):
        report = energy_report(200, 20, 7, 5.0, 1.0, 0.01, 0.1)
        self.assertTrue(report["simulation_only"])
        self.assertEqual(report["measurement_inputs_mwh"]["available_stored_energy_budget"], 5.0)
        for result in report["results"]:
            expected = result["cache_hits"] * 0.01 + result["origin_requests"] * 0.1
            self.assertAlmostEqual(result["estimated_energy_mwh"], expected, places=7)
            self.assertEqual(result["available_energy_mwh"], 6.0)

    def test_rejects_negative_energy_values(self):
        with self.assertRaises(ValueError):
            energy_report(100, 10, 1, 2.0, -0.1, 0.01, 0.1)

    def test_reproducible_for_fixed_seed(self):
        first = energy_report(100, 10, 5, 2.0, 0.2, 0.01, 0.1)
        second = energy_report(100, 10, 5, 2.0, 0.2, 0.01, 0.1)
        self.assertEqual(first, second)

if __name__ == "__main__":
    unittest.main()
