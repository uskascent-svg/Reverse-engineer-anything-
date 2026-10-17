import json
import tempfile
import unittest
from pathlib import Path

from soc_io import detect, load_events, load_iocs, parse_event


def event(event_id, minute, outcome="failed", **extra):
    row = {
        "event_id": event_id,
        "timestamp": f"2026-10-17T08:{minute:02d}:00Z",
        "source": "test-idp",
        "event_type": "authentication",
        "user": "alice",
        "outcome": outcome,
        "src_ip": "192.0.2.7",
        **extra,
    }
    return parse_event(row, 1)


class SocIoTests(unittest.TestCase):
    def test_detects_repeated_failures(self):
        events = [event(f"f{i}", i) for i in range(5)]
        alerts = detect(events, {"ips": set(), "domains": set(), "hashes": set()})
        self.assertIn("SOCIO-AUTH-001", {alert.rule_id for alert in alerts})

    def test_detects_success_after_failures(self):
        events = [event(f"f{i}", i) for i in range(3)]
        events.append(event("success", 4, "success"))
        alerts = detect(events, {"ips": set(), "domains": set(), "hashes": set()})
        self.assertIn("SOCIO-AUTH-002", {alert.rule_id for alert in alerts})

    def test_encoded_powershell_is_explainable(self):
        item = parse_event({
            "event_id": "p1", "timestamp": "2026-10-17T08:00:00Z",
            "source": "endpoint", "event_type": "process_start",
            "process": "powershell.exe", "command_line": "powershell -EncodedCommand abc"
        }, 1)
        alerts = detect([item], {"ips": set(), "domains": set(), "hashes": set()})
        self.assertIn("SOCIO-PROC-001", {alert.rule_id for alert in alerts})

    def test_ioc_match_is_local_and_disclosed(self):
        item = parse_event({
            "event_id": "n1", "timestamp": "2026-10-17T08:00:00Z",
            "source": "firewall", "event_type": "network", "src_ip": "198.51.100.9"
        }, 1)
        alerts = detect([item], {"ips": {"198.51.100.9"}, "domains": set(), "hashes": set()})
        self.assertIn("SOCIO-IOC-001", {alert.rule_id for alert in alerts})

    def test_timezone_required(self):
        with self.assertRaises(ValueError):
            parse_event({"event_id": "x", "timestamp": "2026-10-17T08:00:00",
                         "source": "test", "event_type": "test"}, 1)

    def test_duplicate_source_event_id_is_skipped(self):
        line = json.dumps({"event_id": "same", "timestamp": "2026-10-17T08:00:00Z",
                           "source": "test", "event_type": "test"})
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "events.jsonl"
            path.write_text(line + "\n" + line + "\n", encoding="utf-8")
            events, warnings = load_events(path)
        self.assertEqual(len(events), 1)
        self.assertTrue(any("duplicate" in warning for warning in warnings))

    def test_malformed_json_is_warning_not_crash(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "events.jsonl"
            path.write_text("{not-json}\n", encoding="utf-8")
            events, warnings = load_events(path)
        self.assertEqual(events, [])
        self.assertEqual(len(warnings), 1)


if __name__ == "__main__":
    unittest.main()
