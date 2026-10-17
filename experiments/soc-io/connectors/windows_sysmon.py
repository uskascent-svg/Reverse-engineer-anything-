#!/usr/bin/env python3
"""Explicit opt-in, local, read-only Windows Sysmon event-log adapter.

Requires Windows PowerShell 5.1+ or PowerShell 7 and the Sysmon operational
channel. No network access, credential access, or response actions are used.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

MAX_EVENTS_HARD_LIMIT = 20_000
SOURCE = "windows-sysmon"
CHANNEL = "Microsoft-Windows-Sysmon/Operational"

# This script is static. All operator-controlled values are passed via
# environment variables and parsed as data, never interpolated into PowerShell.
POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$start = [DateTimeOffset]::Parse($env:SOCIO_SYSMon_START).LocalDateTime
$end = [DateTimeOffset]::Parse($env:SOCIO_SYSMON_END).LocalDateTime
$limit = [Math]::Min([Math]::Max([int]$env:SOCIO_SYSMON_LIMIT, 1), 20000)
$channel = 'Microsoft-Windows-Sysmon/Operational'
$null = Get-WinEvent -ListLog $channel -ErrorAction Stop
$events = @(Get-WinEvent -FilterHashtable @{ LogName = $channel; StartTime = $start; EndTime = $end } -MaxEvents $limit -ErrorAction SilentlyContinue)
foreach ($event in $events) {
    [xml]$xml = $event.ToXml()
    $data = [ordered]@{}
    foreach ($node in $xml.Event.EventData.Data) {
        $name = [string]$node.Name
        if (-not $name) { $name = 'unnamed' }
        if ($data.Contains($name)) { $name = $name + '_' + $data.Count }
        $data[$name] = [string]$node.'#text'
    }
    $record = [ordered]@{
        record_id = [string]$event.RecordId
        event_id = [int]$event.Id
        timestamp = $event.TimeCreated.ToUniversalTime().ToString('o')
        computer = [string]$event.MachineName
        provider = [string]$event.ProviderName
        user = [string]$event.UserId
        level = [string]$event.LevelDisplayName
        data = $data
    }
    ConvertTo-Json -InputObject $record -Depth 6 -Compress
}
"""


def _iso_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp from Windows Event Log has no timezone")
    return parsed.astimezone(timezone.utc)


def _field(data: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:16_384]
    return ""


def normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    """Map one Sysmon record into SOC-IO's normalized event schema."""
    if not isinstance(record, dict) or not isinstance(record.get("data"), dict):
        raise ValueError("Sysmon record must contain a data object")
    record_id = str(record.get("record_id", "")).strip()
    event_id = int(record.get("event_id", 0))
    if not record_id or event_id <= 0:
        raise ValueError("Sysmon record is missing record_id or event_id")
    timestamp = _iso_utc(str(record.get("timestamp", ""))).isoformat().replace("+00:00", "Z")
    data = record["data"]
    image = _field(data, "Image", "Application")
    command_line = _field(data, "CommandLine")
    user = _field(data, "User") or _field({"user": record.get("user")}, "user") or "unknown"
    host = str(record.get("computer", "")).strip()[:256] or "unknown"
    source_ip = _field(data, "SourceIp", "SourceIP")
    destination_ip = _field(data, "DestinationIp", "DestinationIP")
    destination_port = _field(data, "DestinationPort")
    destination = destination_ip + ((":" + destination_port) if destination_port else "")
    event_type_by_id = {
        1: "process_start",
        3: "network_connection",
        7: "image_load",
        8: "remote_thread",
        10: "process_access",
        11: "file_create",
        12: "registry_change",
        13: "registry_change",
        14: "registry_change",
        15: "file_stream_create",
        17: "pipe_create",
        18: "pipe_connect",
        19: "wmi_event",
        20: "wmi_event",
        21: "wmi_event",
        22: "dns_query",
        23: "file_delete",
        25: "process_tampering",
        26: "file_delete",
    }
    event_type = event_type_by_id.get(event_id, "sysmon_event")
    message = json.dumps(
        {"sysmon_event_id": event_id, "data": data},
        ensure_ascii=False, separators=(",", ":"),
    )[:16_384]
    return {
        "event_id": f"sysmon:{host}:{record_id}",
        "timestamp": timestamp,
        "source": SOURCE,
        "event_type": event_type,
        "host": host,
        "user": user,
        "outcome": "unknown",
        "src_ip": source_ip,
        "process": image[:1024],
        "command_line": command_line[:16_384],
        "destination": destination[:1024],
        "message": message,
    }


def collect(start: datetime, end: datetime, max_events: int, powershell: str | None = None) -> list[dict[str, Any]]:
    """Read a bounded time window from the local Sysmon channel; never writes to it."""
    if os.name != "nt":
        raise RuntimeError("Windows Sysmon collection can only run on Windows")
    if start.tzinfo is None or end.tzinfo is None or start >= end:
        raise ValueError("start/end must be timezone-aware and start must precede end")
    if max_events < 1 or max_events > MAX_EVENTS_HARD_LIMIT:
        raise ValueError(f"max_events must be between 1 and {MAX_EVENTS_HARD_LIMIT}")
    executable = powershell or shutil.which("pwsh") or shutil.which("powershell")
    if not executable:
        raise RuntimeError("PowerShell was not found; install PowerShell or pass --powershell")
    env = os.environ.copy()
    env.update({
        "SOCIO_SYSMON_START": start.isoformat(),
        "SOCIO_SYSMON_END": end.isoformat(),
        "SOCIO_SYSMON_LIMIT": str(max_events),
    })
    try:
        result = subprocess.run(
            [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", POWERSHELL_SCRIPT],
            capture_output=True, text=True, timeout=120, check=False, env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Sysmon query timed out after 120 seconds") from exc
    if result.returncode != 0:
        # PowerShell errors may include host or configuration details; cap output.
        detail = (result.stderr or result.stdout or "unknown PowerShell error").strip()[:1000]
        raise RuntimeError(f"Sysmon query failed: {detail}")
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(result.stdout.splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            rows.append(normalize_record(record))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise RuntimeError(f"invalid Sysmon output at record line {line_no}: {exc}") from exc
        if len(rows) >= max_events:
            break
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since-minutes", type=int, default=60, help="lookback window (1..10080 minutes)")
    parser.add_argument("--max-events", type=int, default=1000, help=f"limit records (1..{MAX_EVENTS_HARD_LIMIT})")
    parser.add_argument("--output", type=Path, required=True, help="JSONL destination; will not overwrite an existing file")
    parser.add_argument("--powershell", help="optional explicit PowerShell executable path")
    parser.add_argument("--enable-local-read-only", action="store_true", help="required explicit opt-in; queries local Sysmon logs only")
    args = parser.parse_args(argv)
    if not args.enable_local_read_only:
        parser.error("explicit opt-in required: pass --enable-local-read-only")
    if args.since_minutes < 1 or args.since_minutes > 7 * 24 * 60:
        parser.error("--since-minutes must be between 1 and 10080")
    if args.max_events < 1 or args.max_events > MAX_EVENTS_HARD_LIMIT:
        parser.error(f"--max-events must be between 1 and {MAX_EVENTS_HARD_LIMIT}")
    if args.output.exists():
        parser.error(f"refusing to overwrite existing output file: {args.output}")
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=args.since_minutes)
    try:
        rows = collect(start, end, args.max_events, args.powershell)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive creation prevents accidental clobbering. No raw secrets are written.
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            for row in rows:
                stream.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"SOC-IO Sysmon connector error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "connector": SOURCE, "channel": CHANNEL, "records_written": len(rows),
        "window_start": start.isoformat(), "window_end": end.isoformat(),
        "mode": "explicit opt-in, local, read-only",
        "note": "A zero-record query means no records were returned for this window; it is not proof of a healthy endpoint.",
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
