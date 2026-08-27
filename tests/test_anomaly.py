"""Behavioural anomaly detection — the signature-less half of the platform."""

from siem.detect.anomaly import AnomalyDetector
from siem.detect.engine import DetectionEngine
from siem.events import Event
from siem.scenario import INSIDER, build_scenario
from siem.store.eventstore import EventStore


def flow(ip, ts, nbytes):
    return Event(ts, "network", "network", "flow", source_ip=ip,
                 dest_ip="10.0.0.1", bytes=nbytes)


def test_warmup_suppresses_early_events():
    """A brand-new entity's first big event must not self-trigger — there's no
    baseline to be anomalous against yet."""
    det = AnomalyDetector(min_history=20, threshold=6.0)
    assert det.observe(flow("a", 0, 10_000_000)) is None  # first ever event


def test_departure_from_baseline_is_flagged():
    det = AnomalyDetector(min_history=20, threshold=6.0)
    t = 0.0
    for i in range(30):                    # establish a small-volume baseline
        assert det.observe(flow("a", t + i, 100_000)) is None
    spike = det.observe(flow("a", t + 100, 5_000_000))   # 50x normal
    assert spike is not None
    assert spike["z_score"] > 6.0


def test_each_entity_has_its_own_baseline():
    """A big flow from a normally-big host isn't anomalous; the same flow from a
    normally-small host is."""
    det = AnomalyDetector(min_history=20, threshold=6.0)
    for i in range(30):
        det.observe(flow("big", i, 5_000_000))     # this host is always big
        det.observe(flow("small", i, 10_000))      # this one always small
    assert det.observe(flow("big", 100, 5_000_000)) is None       # normal for big
    assert det.observe(flow("small", 100, 5_000_000)) is not None # anomalous for small


def test_scoring_uses_only_past_not_the_event_itself():
    """The event is judged against its own history, then folds in — otherwise a
    spike would inflate its own baseline and hide itself."""
    det = AnomalyDetector(min_history=5, threshold=4.0)
    for i in range(10):
        det.observe(flow("a", i, 1000))
    first_spike = det.observe(flow("a", 100, 500_000))
    assert first_spike is not None            # caught, not masked by itself


def test_platform_catches_the_signatureless_insider():
    """End to end: the insider anomaly in the scenario is caught by the baseline
    and by NO signature rule — the whole point of adding behavioural detection."""
    events, _ = build_scenario()
    store, eng = EventStore(), DetectionEngine()
    for e in events:
        store.append(e)
        eng.process(e)

    insider = [a for a in eng.alerts if a.entity == INSIDER]
    assert any(a.rule_id == "behavioural_anomaly" for a in insider)
    assert not any(a.rule_id == "large_egress" for a in insider)  # under threshold


def test_anomaly_can_be_disabled():
    eng = DetectionEngine(anomaly=False)
    assert eng.anomaly is None
