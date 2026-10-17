import io
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from connectors import windows_sysmon as connector


class WindowsSysmonConnectorTests(unittest.TestCase):
    def sample(self, event_id=1, data=None):
        return {
            "record_id": "42",
            "event_id": event_id,
            "timestamp": "2026-10-17T08:00:00.0000000Z",
            "computer": "LAB-WIN-01",
            "provider": "Microsoft-Windows-Sysmon",
            "user": "S-1-5-18",
            "data": data or {
                "Image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
                "CommandLine": "powershell.exe -NoProfile",
                "User": "LAB\\\\analyst",
                "ProcessId": "1234",
            },
        }

    def test_normalizes_process_creation_with_provenance(self):
        event = connector.normalize_record(self.sample())
        self.assertEqual(event["event_id"], "sysmon:LAB-WIN-01:42")
        self.assertEqual(event["source"], "windows-sysmon")
        self.assertEqual(event["event_type"], "process_start")
        self.assertEqual(event["host"], "LAB-WIN-01")
        self.assertIn("powershell.exe", event["command_line"])
        self.assertTrue(event["timestamp"].endswith("Z"))

    def test_normalizes_network_event(self):
        record = self.sample(3, {
            "SourceIp": "192.0.2.10",
            "DestinationIp": "198.51.100.20",
            "DestinationPort": "443",
            "Protocol": "tcp",
        })
        event = connector.normalize_record(record)
        self.assertEqual(event["event_type"], "network_connection")
        self.assertEqual(event["src_ip"], "192.0.2.10")
        self.assertEqual(event["destination"], "198.51.100.20:443")

    def test_unknown_sysmon_event_is_preserved(self):
        event = connector.normalize_record(self.sample(999, {"Details": "fixture"}))
        self.assertEqual(event["event_type"], "sysmon_event")
        self.assertIn('"sysmon_event_id":999', event["message"])

    def test_rejects_missing_record_identity(self):
        record = self.sample()
        record["record_id"] = ""
        with self.assertRaisesRegex(ValueError, "record_id"):
            connector.normalize_record(record)

    def test_rejects_timezone_naive_timestamp(self):
        record = self.sample()
        record["timestamp"] = "2026-10-17T08:00:00"
        with self.assertRaises(ValueError):
            connector.normalize_record(record)

    def test_cli_requires_explicit_opt_in_before_collection(self):
        stderr = io.StringIO()
        with patch("sys.stderr", stderr):
            with self.assertRaises(SystemExit) as raised:
                connector.main(["--output", "must-not-be-created.jsonl"])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--enable-local-read-only", stderr.getvalue())

    def test_bounds_are_explicit(self):
        with self.assertRaises(ValueError):
            connector.collect(datetime.now(timezone.utc), datetime.now(timezone.utc), 0)

    def test_query_is_read_only_and_has_no_operator_interpolation(self):
        self.assertIn("Get-WinEvent -FilterHashtable", connector.POWERSHELL_SCRIPT)
        self.assertIn("ConvertTo-Json", connector.POWERSHELL_SCRIPT)
        self.assertNotIn("Invoke-Expression", connector.POWERSHELL_SCRIPT)
        self.assertNotIn("Start-Process", connector.POWERSHELL_SCRIPT)


if __name__ == "__main__":
    unittest.main()
