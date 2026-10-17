#!/usr/bin/env python3
"""Offline event-level evaluation for SOC-IO rules. No network access."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from soc_io import detect, load_events, load_iocs

MAX_LABELS_BYTES = 10_000_000


def load_labels(path: Path) -> dict[str, bool]:
    if path.stat().st_size > MAX_LABELS_BYTES:
        raise ValueError("label file exceeds 10 MB")
    labels: dict[str, bool] = {}
    with path.open("r", encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                row: Any = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"line {line_no}: invalid JSON") from exc
            if not isinstance(row, dict) or not isinstance(row.get("event_id"), str) or not isinstance(row.get("malicious"), bool):
                raise ValueError(f"line {line_no}: expected event_id string and malicious boolean")
            if row["event_id"] in labels:
                raise ValueError(f"line {line_no}: duplicate event_id {row['event_id']!r}")
            labels[row["event_id"]] = row["malicious"]
    if not labels:
        raise ValueError("label file has no labeled events")
    return labels


def score(labels: dict[str, bool], predicted_event_ids: set[str]) -> dict[str, Any]:
    unknown = predicted_event_ids - labels.keys()
    if unknown:
        # Unknown predictions are excluded; make the loss of evaluation coverage explicit.
        predicted_event_ids = predicted_event_ids & labels.keys()
    tp = sum(1 for event_id, truth in labels.items() if truth and event_id in predicted_event_ids)
    fp = sum(1 for event_id, truth in labels.items() if not truth and event_id in predicted_event_ids)
    fn = sum(1 for event_id, truth in labels.items() if truth and event_id not in predicted_event_ids)
    tn = sum(1 for event_id, truth in labels.items() if not truth and event_id not in predicted_event_ids)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / len(labels) if labels else 0.0
    return {
        "evaluation_unit": "event_id",
        "labeled_events": len(labels),
        "predictions_without_labels_excluded": len(unknown),
        "confusion_matrix": {"true_positive": tp, "false_positive": fp, "false_negative": fn, "true_negative": tn},
        "metrics": {
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1": round(f1, 6),
            "specificity": round(specificity, 6),
            "false_positive_rate": round(1 - specificity, 6),
            "accuracy": round(accuracy, 6),
        },
        "caveats": [
            "Event-level labels are only a rough proxy for alert quality; correlated alerts may include benign context events.",
            "Metrics are meaningful only when labels are representative, independently reviewed, and not used to tune and score the same run.",
            "Use time-separated holdout data and report confidence intervals before comparing versions.",
            "These metrics do not establish future threat-prediction accuracy or production readiness."
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate SOC-IO detections against manually labeled event JSONL.")
    parser.add_argument("events", type=Path, help="normalized SOC-IO events JSONL")
    parser.add_argument("labels", type=Path, help="JSONL rows: event_id and malicious boolean")
    parser.add_argument("--iocs", type=Path, help="optional local IOC JSON")
    args = parser.parse_args(argv)
    try:
        events, warnings = load_events(args.events)
        labels = load_labels(args.labels)
        alerts = detect(events, load_iocs(args.iocs))
        predicted = {event_id for alert in alerts for event_id in alert.event_ids}
        result = score(labels, predicted)
        result["input"] = {"accepted_events": len(events), "alerts": len(alerts), "ingestion_warnings": len(warnings)}
        result["ingestion_warnings"] = warnings
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"soc-io-evaluate: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
