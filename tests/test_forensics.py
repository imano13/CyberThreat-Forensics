
"""Automated tests for digital evidence integrity and reporting."""

import hashlib
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from threat_engine.detector import (
    analyze_events,
    build_investigation_report,
    load_events,
    sha256_file,
)


def test_sha256_matches_expected_fingerprint(tmp_path):
    evidence = tmp_path / "evidence.txt"
    evidence.write_bytes(b"Original forensic evidence")

    expected = hashlib.sha256(
        b"Original forensic evidence"
    ).hexdigest()

    assert sha256_file(evidence) == expected


def test_evidence_modification_changes_hash(tmp_path):
    evidence = tmp_path / "evidence.txt"
    evidence.write_bytes(b"Original forensic evidence")

    original_hash = sha256_file(evidence)

    # Simulate unauthorized modification.
    evidence.write_bytes(b"Modified forensic evidence")

    modified_hash = sha256_file(evidence)

    assert original_hash != modified_hash


def test_unchanged_evidence_keeps_same_hash(tmp_path):
    evidence = tmp_path / "evidence.txt"
    evidence.write_bytes(b"Unchanged security logs")

    first_hash = sha256_file(evidence)
    second_hash = sha256_file(evidence)

    assert first_hash == second_hash


def test_investigation_report_contains_evidence_hash():
    evidence = (
        PROJECT_ROOT / "data" / "samples" / "auth_events.jsonl"
    )

    events = load_events(evidence)
    alerts = analyze_events(events)

    report = build_investigation_report(
        evidence, events, alerts
    )

    assert report["evidence"]["sha256"] == sha256_file(evidence)
    assert report["evidence"]["event_count"] == 11
    assert report["summary"]["alert_count"] == 2
    assert len(report["alerts"]) == 2


def test_incident_timeline_is_chronological_and_linked():
    evidence = (
        PROJECT_ROOT / "data" / "samples" / "auth_events.jsonl"
    )

    events = load_events(evidence)
    alerts = analyze_events(events)
    report = build_investigation_report(evidence, events, alerts)

    timeline = report["timeline"]

    # Every authentication event should appear in the timeline.
    assert len(timeline) == 11

    # Events must appear in chronological order.
    timestamps = [event["timestamp_utc"] for event in timeline]
    assert timestamps == sorted(timestamps)

    # Ten failed logins should be linked to detection alerts.
    flagged_events = [
        event for event in timeline
        if event["linked_alert_rules"]
    ]
    assert len(flagged_events) == 10

    # The normal successful login should have no linked alerts.
    assert timeline[0]["event_type"] == "login_success"
    assert timeline[0]["linked_alert_rules"] == []
