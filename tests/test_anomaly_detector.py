import unittest

from experiments.anomaly_detector import analyze_events


class AnomalyDetectorTests(unittest.TestCase):
    def test_detects_robust_latency_and_size_outliers(self):
        events = [
            {"id": i, "timestamp": f"2026-10-21T08:00:{i:02d}+00:00", "target_host": "example.com",
             "cache_status": "HIT", "response_size": 100, "response_time_ms": 10.0,
             "client_ip": "192.0.2.1", "url": "https://private.example/path?secret=x"}
            for i in range(1, 13)
        ]
        events.append({
            "id": 13, "timestamp": "2026-10-21T08:01:00+00:00", "target_host": "example.com",
            "cache_status": "BYPASS", "response_size": 10000, "response_time_ms": 1000.0,
            "client_ip": "192.0.2.2", "url": "https://private.example/private",
        })
        report = analyze_events(events, threshold=3.5, min_samples=10)
        self.assertEqual(len(report["anomalies"]), 1)
        anomaly = report["anomalies"][0]
        self.assertEqual(anomaly["event_id"], 13)
        self.assertIn("latency_outlier", anomaly["reasons"])
        self.assertIn("response_size_outlier", anomaly["reasons"])
        self.assertNotIn("client_ip", anomaly)
        self.assertNotIn("url", anomaly)

    def test_stream_errors_are_flagged_without_a_baseline(self):
        report = analyze_events([{
            "id": 1, "timestamp": "2026-10-21T08:00:00+00:00", "target_host": "example.com",
            "cache_status": "STREAM-ERROR", "response_size": 10, "response_time_ms": 20.0,
        }])
        self.assertEqual(report["anomalies"][0]["reasons"], ["stream_error"])

    def test_rejects_invalid_threshold(self):
        with self.assertRaises(ValueError):
            analyze_events([], threshold=0)

if __name__ == "__main__":
    unittest.main()
