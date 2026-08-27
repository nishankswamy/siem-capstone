"""The end-to-end attack replay: every stage must be detected."""

from siem.detect.engine import DetectionEngine
from siem.investigate.investigation import Investigation
from siem.scenario import ATTACKER, build_scenario
from siem.store.eventstore import EventStore


def run():
    events, stages = build_scenario()
    store, eng = EventStore(), DetectionEngine()
    for e in events:
        store.append(e)
        eng.process(e)
    return store, eng, stages


def test_all_attack_stages_detected():
    _, eng, _ = run()
    techniques = {a.attack.split(".")[0] for a in eng.alerts if a.entity == ATTACKER}
    # recon (T1595), brute force / compromise (T1110), exfil (T1048).
    assert {"T1595", "T1110", "T1048"} <= techniques


def test_the_landed_login_produces_a_critical_alert():
    _, eng, _ = run()
    assert any(a.severity == "critical" and a.entity == ATTACKER for a in eng.alerts)


def test_benign_traffic_generates_no_attacker_alerts_elsewhere():
    """Alerts should concentrate on the attacker, not smear across benign IPs."""
    _, eng, _ = run()
    attacker_alerts = sum(a.entity == ATTACKER for a in eng.alerts)
    other_alerts = sum(a.entity != ATTACKER for a in eng.alerts)
    assert attacker_alerts >= 4
    assert other_alerts == 0        # clean: no benign false positives


def test_investigation_reconstructs_the_full_campaign():
    store, eng, _ = run()
    inv = Investigation(store, eng.alerts)
    activity = inv.entity_activity("ip", ATTACKER)
    # One entity, all sources, the exfil destination, every alert.
    assert set(activity["sources"]) >= {"web", "auth", "network"}
    assert len(activity["connected_ips"]) >= 1
    assert len(activity["alerts"]) >= 4


def test_indexed_pivot_returns_only_the_entity():
    store, eng, _ = run()
    events = list(store.by_entity("ip", ATTACKER))
    assert all(e.source_ip == ATTACKER for e in events)
    assert len(events) == sum(1 for e in build_scenario()[0]
                              if e.source_ip == ATTACKER)
