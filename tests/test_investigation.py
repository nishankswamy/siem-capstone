"""The investigation layer: triage order, evidence pivot, entity view, timeline."""

import pytest

from siem.detect.engine import DetectionEngine
from siem.events import Event
from siem.investigate.investigation import Investigation
from siem.store.eventstore import EventStore


@pytest.fixture
def platform():
    store = EventStore()
    eng = DetectionEngine()
    t0 = 1_773_580_000.0
    events = []
    for i in range(6):
        events.append(Event(t0 + i * 5, "auth", "authentication", "ssh_login",
                            "failure", source_ip="45.13.1.1", user="root", host="web01"))
    events.append(Event(t0 + 40, "auth", "authentication", "ssh_login", "success",
                        source_ip="45.13.1.1", user="root", host="web01"))
    events.append(Event(t0 + 120, "network", "network", "flow", source_ip="45.13.1.1",
                        dest_ip="203.0.1.1", bytes=40_000_000))
    for i in range(20):  # benign noise
        events.append(Event(t0 + i * 3, "web", "web", "http_request", "success",
                            source_ip="10.0.0.5", url_path="/", http_status=200))
    for e in events:
        store.append(e)
        eng.process(e)
    return Investigation(store, eng.alerts), store, eng


def test_triage_orders_worst_first(platform):
    inv, _, _ = platform
    queue = inv.triage_queue()
    severities = [a.severity for a in queue]
    # Critical must precede high must precede medium/low.
    assert severities[0] == "critical"
    assert severities.index("critical") < severities.index("high")


def test_evidence_pivots_to_raw_events(platform):
    inv, _, eng = platform
    critical = next(a for a in inv.triage_queue() if a.severity == "critical")
    evidence = inv.evidence(critical)
    # The raw events behind the alert, all from the attacker IP.
    assert len(evidence) > 0
    assert all(e.source_ip == "45.13.1.1" for e in evidence)


def test_entity_view_spans_all_sources(platform):
    inv, _, _ = platform
    activity = inv.entity_activity("ip", "45.13.1.1")
    assert activity["event_count"] == 8            # 7 ssh + 1 flow
    assert set(activity["sources"]) == {"auth", "network"}
    assert "203.0.1.1" in activity["connected_ips"]
    assert len(activity["alerts"]) >= 2


def test_entity_view_ignores_unrelated_entities(platform):
    inv, _, _ = platform
    benign = inv.entity_activity("ip", "10.0.0.5")
    assert benign["event_count"] == 20
    assert len(benign["alerts"]) == 0              # noise generated no alerts


def test_timeline_interleaves_events_and_alerts_in_order(platform):
    inv, _, _ = platform
    timeline = inv.timeline("ip", "45.13.1.1")
    kinds = [kind for _, kind, _ in timeline.events]
    times = [ts for ts, _, _ in timeline.events]
    assert times == sorted(times)                  # chronological
    assert "alert" in kinds and "event" in kinds   # both present


def test_timeline_tells_the_attack_story(platform):
    inv, _, _ = platform
    timeline = inv.timeline("ip", "45.13.1.1")
    descriptions = " ".join(d for _, _, d in timeline.events)
    # The narrative: brute force, then a landed login, then egress.
    assert "brute force" in descriptions.lower()
    assert "succeeded" in descriptions.lower()
    assert "egress" in descriptions.lower()


def test_queue_summary_counts_by_severity(platform):
    inv, _, _ = platform
    summary = inv.queue_summary()
    assert summary["critical"] == 1
    assert summary["informational"] == 0
