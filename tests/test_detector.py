
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

# Allow tests to import our source module.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from threat_engine.detector import (
    SecurityEvent,
    analyze_events,
    detect_brute_force,
    detect_password_spraying,
    load_events,
)


def make_event(
    minute: int,
    username: str = "admin",
    event_type: str = "login_failure",
    source_ip: str = "203.0.113.10",
) -> SecurityEvent:
    """Create a synthetic authentication event for testing."""
    timestamp = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)
    return SecurityEvent(
        timestamp=timestamp + timedelta(minutes=minute),
        event_type=event_type,
        username=username,
        source_ip=source_ip,
    )


def test_sample_dataset_generates_two_expected_alerts():
    sample_path = PROJECT_ROOT / "data" / "samples" / "auth_events.jsonl"

    events = load_events(sample_path)
    alerts = analyze_events(events)

    assert len(events) == 11
    assert len(alerts) == 2
    assert {alert.rule_id for alert in alerts} == {
        "BRUTE_FORCE",
        "PASSWORD_SPRAYING",
    }


def test_brute_force_detects_five_failures_against_one_account():
    events = [make_event(minute=i) for i in range(5)]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "BRUTE_FORCE"
    assert alerts[0].event_count == 5
    assert alerts[0].usernames == ["admin"]


def test_four_failures_do_not_trigger_brute_force():
    events = [make_event(minute=i) for i in range(4)]

    assert detect_brute_force(events) == []


def test_different_accounts_are_not_brute_force_by_this_rule():
    usernames = ["alice", "bob", "carol", "dave", "erin"]
    events = [
        make_event(minute=i, username=username)
        for i, username in enumerate(usernames)
    ]

    assert detect_brute_force(events) == []


def test_password_spraying_detects_five_accounts():
    usernames = ["alice", "bob", "carol", "dave", "erin"]
    events = [
        make_event(
            minute=i,
            username=username,
            source_ip="198.51.100.20",
        )
        for i, username in enumerate(usernames)
    ]

    alerts = detect_password_spraying(events)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "PASSWORD_SPRAYING"
    assert alerts[0].event_count == 5
    assert len(alerts[0].usernames) == 5


def test_successful_logins_alone_do_not_trigger_alerts():
    events = [
        make_event(
            minute=i,
            event_type="login_success",
        )
        for i in range(6)
    ]

    assert analyze_events(events) == []


def test_invalid_ip_address_is_rejected(tmp_path):
    log_file = tmp_path / "invalid.jsonl"
    record = {
        "timestamp": "2026-10-27T12:00:00Z",
        "event_type": "login_failure",
        "username": "admin",
        "source_ip": "not-an-ip",
    }
    log_file.write_text(json.dumps(record) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid event"):
        load_events(log_file)
