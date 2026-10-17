#!/usr/bin/env python3
"""SOC-IO: isolated, offline-first security event triage prototype.

This tool reads JSONL events and optional local IOC JSON. It performs bounded,
deterministic checks only. It does not connect to endpoints, execute event
payloads, send telemetry, or perform response actions. Priority is a heuristic,
not a probability or a prediction of compromise.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

MAX_LINE_BYTES = 1_000_000
MAX_EVENTS = 100_000
MAX_ALERTS = 20_000
WINDOW = timedelta(minutes=10)
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass(frozen=True)
class Event:
    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    host: str = "unknown"
    user: str = "unknown"
    outcome: str = "unknown"
    src_ip: str = ""
    process: str = ""
    command_line: str = ""
    file_hash: str = ""
    destination: str = ""
    message: str = ""
    raw_fingerprint: str = ""


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    title: str
    severity: str
    priority_score: int
    evidence_confidence: str
    summary: str
    event_ids: list[str]
    entities: dict[str, str]
    recommendations: list[str]
    limitations: list[str]
    status: str = "open"


def parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a non-empty ISO-8601 string")
    normalized = value.strip().replace("Z", "+00:00")
    try:
        result = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError("timestamp must be ISO-8601") from exc
    if result.tzinfo is None:
        raise ValueError("timestamp must include a timezone offset")
    return result.astimezone(timezone.utc)


def _text(row: dict[str, Any], key: str, default: str = "") -> str:
    value = row.get(key, default)
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string")
    if len(value) > 16_384:
        raise ValueError(f"{key} exceeds 16384 characters")
    return value.strip()


def parse_event(row: Any, line_number: int) -> Event:
    if not isinstance(row, dict):
        raise ValueError(f"line {line_number}: event must be a JSON object")
    required = ("event_id", "timestamp", "source", "event_type")
    for key in required:
        if key not in row:
            raise ValueError(f"line {line_number}: missing required field {key}")
    event_id = _text(row, "event_id")
    source = _text(row, "source")
    event_type = _text(row, "event_type")
    if not event_id or not source or not event_type:
        raise ValueError(f"line {line_number}: required string fields cannot be empty")
    timestamp = parse_time(row.get("timestamp"))
    canonical = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return Event(
        event_id=event_id[:256], timestamp=timestamp, source=source[:256],
        event_type=event_type.lower()[:128], host=_text(row, "host", "unknown")[:256] or "unknown",
        user=_text(row, "user", "unknown")[:256] or "unknown",
        outcome=_text(row, "outcome", "unknown").lower()[:64],
        src_ip=_text(row, "src_ip")[:256], process=_text(row, "process")[:1024],
        command_line=_text(row, "command_line")[:16_384], file_hash=_text(row, "file_hash").lower()[:256],
        destination=_text(row, "destination")[:1024], message=_text(row, "message")[:4096],
        raw_fingerprint=fingerprint,
    )


def load_events(path: Path) -> tuple[list[Event], list[str]]:
    events: list[Event] = []
    warnings: list[str] = []
    seen: set[str] = set()
    try:
        with path.open("rb") as stream:
            for line_number, raw in enumerate(stream, 1):
                if len(raw) > MAX_LINE_BYTES:
                    warnings.append(f"line {line_number}: rejected oversized event")
                    continue
                if not raw.strip():
                    continue
                if len(events) >= MAX_EVENTS:
                    warnings.append(f"event limit ({MAX_EVENTS}) reached; remaining input ignored")
                    break
                try:
                    row = json.loads(raw.decode("utf-8"))
                    event = parse_event(row, line_number)
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                    warnings.append(f"line {line_number}: rejected event ({exc})")
                    continue
                # Event IDs are source-local identifiers; retain distinct IDs even if payloads match.
                dedupe_key = f"{event.source}:{event.event_id}"
                if dedupe_key in seen:
                    warnings.append(f"line {line_number}: duplicate source/event_id ignored")
                    continue
                seen.add(dedupe_key)
                events.append(event)
    except OSError as exc:
        raise RuntimeError(f"cannot read event file: {exc}") from exc
    events.sort(key=lambda item: (item.timestamp, item.source, item.event_id))
    return events, warnings


def load_iocs(path: Path | None) -> dict[str, set[str]]:
    indicators: dict[str, set[str]] = {"ips": set(), "domains": set(), "hashes": set()}
    if path is None:
        return indicators
    try:
        if path.stat().st_size > MAX_LINE_BYTES:
            raise ValueError("IOC file exceeds 1 MB")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read IOC file: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("IOC file must be a JSON object with ips, domains, and hashes arrays")
    for key in indicators:
        values = payload.get(key, [])
        if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
            raise ValueError(f"IOC field {key} must be an array of strings")
        indicators[key] = {v.strip().lower() for v in values if v.strip()}
    return indicators


def _alert(rule_id: str, title: str, severity: str, confidence: str, summary: str,
           events: list[Event], entities: dict[str, str], recommendations: list[str],
           limitations: list[str] | None = None) -> Alert:
    ids = sorted({event.event_id for event in events})
    identity = "|".join((rule_id, *ids))
    alert_id = hashlib.sha256(identity.encode()).hexdigest()[:12]
    # Transparent queue ordering heuristic; deliberately not a probability.
    score = SEVERITY_ORDER[severity] * 20 + (20 if confidence == "high" else 10 if confidence == "medium" else 0)
    return Alert(alert_id, rule_id, title, severity, score, confidence, summary, ids,
                 entities, recommendations, limitations or ["Rule-based lead; validate against source evidence."])


def detect(events: list[Event], iocs: dict[str, set[str]]) -> list[Alert]:
    alerts: list[Alert] = []
    failed: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        if event.event_type in {"authentication", "auth", "login"} and event.outcome in {"failed", "failure", "denied"}:
            failed[(event.user, event.src_ip)].append(event)

    # Repeated failures and subsequent successful authentication are separate, explainable detections.
    for (user, ip), group in failed.items():
        group.sort(key=lambda item: item.timestamp)
        for index, event in enumerate(group):
            window_events = [candidate for candidate in group[index:]
                             if candidate.timestamp - event.timestamp <= WINDOW]
            if len(window_events) >= 5:
                alerts.append(_alert(
                    "SOCIO-AUTH-001", "Repeated authentication failures", "high", "medium",
                    f"{len(window_events)} failed authentication events for one user/source IP within 10 minutes.",
                    window_events, {"user": user, "source_ip": ip},
                    ["Confirm whether the source is an approved scanner or user.", "Review identity-provider logs and MFA outcomes.", "Check for successful authentication after the failures."]
                ))
                break
        successes = [event for event in events if event.user == user and event.src_ip == ip
                     and event.event_type in {"authentication", "auth", "login"}
                     and event.outcome in {"success", "succeeded", "allowed"}]
        for success in successes:
            prior = [event for event in group if timedelta(0) <= success.timestamp - event.timestamp <= WINDOW]
            if len(prior) >= 3:
                alerts.append(_alert(
                    "SOCIO-AUTH-002", "Successful login after repeated failures", "high", "high",
                    f"A successful authentication followed {len(prior)} failed attempts for the same user/source IP within 10 minutes.",
                    prior + [success], {"user": user, "source_ip": ip},
                    ["Verify the login with the account owner and MFA records.", "Inspect session creation and subsequent activity.", "Revoke sessions only through an approved incident runbook."]
                ))

    for event in events:
        command = event.command_line.lower()
        process = event.process.lower().replace("\\", "/")
        if ("powershell" in process or "pwsh" in process or "powershell" in command) and re.search(r"(?<![a-z])-(?:enc|encodedcommand)(?![a-z])", command):
            alerts.append(_alert(
                "SOCIO-PROC-001", "PowerShell encoded command", "high", "medium",
                "PowerShell command line contains an encoded-command option; encoded use can be legitimate and requires context.",
                [event], {"host": event.host, "user": event.user, "process": event.process},
                ["Retrieve the original process-creation event and parent process.", "Decode the command only in a controlled analysis workflow.", "Compare the signer, script origin, and user activity with policy."]
            ))
        if any(token in process for token in ("/temp/", "/tmp/", "/downloads/")):
            alerts.append(_alert(
                "SOCIO-PROC-002", "Process launched from a user-writable staging path", "medium", "medium",
                "Process path includes a common temporary or downloads directory; this alone does not prove maliciousness.",
                [event], {"host": event.host, "user": event.user, "process": event.process},
                ["Check file hash, signer, parent process, prevalence, and creation time.", "Confirm whether installation or software deployment explains the path."]
            ))
        domain = event.destination.lower().strip().rstrip(".")
        if ((event.src_ip and event.src_ip.lower() in iocs["ips"])
                or (domain and domain in iocs["domains"])
                or (event.file_hash and event.file_hash in iocs["hashes"])):
            matched = []
            if event.src_ip and event.src_ip.lower() in iocs["ips"]:
                matched.append("source IP")
            if domain and domain in iocs["domains"]:
                matched.append("destination/domain")
            if event.file_hash and event.file_hash in iocs["hashes"]:
                matched.append("file hash")
            alerts.append(_alert(
                "SOCIO-IOC-001", "Local threat-indicator match", "high", "medium",
                "Event matched locally supplied indicator(s): " + ", ".join(matched) + ". Indicator reputation and freshness were not independently verified.",
                [event], {"host": event.host, "user": event.user, "source_ip": event.src_ip, "destination": event.destination, "file_hash": event.file_hash},
                ["Validate the indicator source, timestamp, expiry, and confidence.", "Seek independent endpoint/network evidence before declaring compromise.", "Check whether the indicator is shared infrastructure or a known false positive."]
            ))
    # Deduplicate exact rule/evidence matches and bound output.
    unique: dict[str, Alert] = {}
    for alert in alerts:
        unique[f"{alert.rule_id}:{','.join(alert.event_ids)}"] = alert
    return sorted(unique.values(), key=lambda a: (-a.priority_score, a.rule_id, a.alert_id))[:MAX_ALERTS]


def build_report(events: list[Event], alerts: list[Alert], warnings: list[str]) -> dict[str, Any]:
    return {
        "product": "SOC-IO",
        "mode": "offline-deterministic-triage-prototype",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "events_accepted": len(events),
            "alerts": len(alerts),
            "warnings": len(warnings),
            "forecast_status": "unavailable",
            "priority_score_note": "Heuristic queue-ordering score; not a probability or prediction."
        },
        "telemetry": {
            "sources": sorted({event.source for event in events}),
            "time_range": {
                "start": min((e.timestamp for e in events), default=None).isoformat() if events else None,
                "end": max((e.timestamp for e in events), default=None).isoformat() if events else None,
            },
            "coverage_note": "Only the supplied event file is represented; missing sources cannot be assumed clean."
        },
        "alerts": [asdict(alert) for alert in alerts],
        "warnings": warnings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SOC-IO offline security event triage (no network or response actions).")
    parser.add_argument("events", type=Path, help="JSONL file of normalized events")
    parser.add_argument("--iocs", type=Path, help="optional local JSON IOC file: ips/domains/hashes arrays")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON report")
    args = parser.parse_args(argv)
    try:
        events, warnings = load_events(args.events)
        iocs = load_iocs(args.iocs)
        alerts = detect(events, iocs)
        report = build_report(events, alerts, warnings)
    except (RuntimeError, ValueError) as exc:
        print(f"soc-io: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        summary = report["summary"]
        print(f"SOC-IO | Offline triage | events={summary['events_accepted']} alerts={summary['alerts']} warnings={summary['warnings']}")
        print("Forecast: unavailable (no trained or validated forecasting model).")
        print("Priority scores are heuristic, not probabilities. Missing telemetry is not evidence of safety.\n")
        for alert in report["alerts"]:
            print(f"[{alert['severity'].upper()}] {alert['rule_id']} {alert['title']} (priority {alert['priority_score']}, confidence {alert['evidence_confidence']})")
            print(f"  {alert['summary']}")
            print(f"  Events: {', '.join(alert['event_ids'])}")
            for recommendation in alert["recommendations"]:
                print(f"  Next: {recommendation}")
        for warning in warnings:
            print(f"WARNING: {warning}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
