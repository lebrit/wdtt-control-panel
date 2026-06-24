import tempfile
import unittest
from pathlib import Path

from wdtt_panel import fleet


class FleetConfigTests(unittest.TestCase):
    def test_configures_outbound_agent_without_exposing_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fleet-agent.json"
            status = fleet.configure(
                {
                    "endpoint": "https://fleet.example.com:8444/fleet-agent-abc123/",
                    "enrollment_grant": "a" * 40,
                    "enabled": True,
                    "poll_interval_seconds": 15,
                },
                path,
            )
            self.assertTrue(status["configured"])
            self.assertFalse(status["enrolled"])
            stored = path.read_text(encoding="utf-8")
            self.assertIn("identity_fingerprint", stored)
            self.assertEqual(fleet.load_config(path)["agent_token"], "")
            self.assertNotIn("enrollment_grant", status)

    def test_rejects_non_https_endpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(fleet.FleetValidationError):
                fleet.configure(
                    {"endpoint": "http://fleet.example.com", "enrollment_grant": "a" * 40, "enabled": True},
                    Path(directory) / "fleet-agent.json",
                )

    def test_allows_toggling_an_enrolled_agent_without_reentering_grant(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fleet-agent.json"
            fleet.configure(
                {"endpoint": "https://fleet.example.com/agent/", "enrollment_grant": "a" * 40, "enabled": True},
                path,
            )
            config = fleet.load_config(path)
            config["agent_token"] = "b" * 40
            config["node_id"] = "node-1"
            config["enrollment_grant"] = ""
            fleet.save_config(config, path)
            status = fleet.configure({"endpoint": "https://fleet.example.com/agent/", "enabled": False}, path)
            self.assertTrue(status["configured"])
            self.assertFalse(status["enabled"])


if __name__ == "__main__":
    unittest.main()
