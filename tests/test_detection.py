"""The detection engine: rules, thresholds, dedup, correlation, ATT&CK."""

from siem.detect.engine import DetectionEngine
from siem.detect.rules import DEFAULT_RULES
from siem.events import Event


def ssh_fail(ip, ts, user="root"):
    return Event(ts, "auth", "authentication", "ssh_login", "failure", source_ip=ip, user=user)


def test_threshold_rule_fires_at_count():
    eng = DetectionEngine()
    t0 = 1_773_580_000.0
    alerts = []
    for i in range(5):
        alerts += eng.process(ssh_fail("1.1.1.1", t0 + i))
    assert any(a.rule_id == "ssh_bruteforce" for a in alerts)


def test_threshold_dedups_a_burst():
    eng = DetectionEngine(dedup_window=300)
    t0 = 1_773_580_000.0
    alerts = []
    for i in range(40):
        alerts += eng.process(ssh_fail("1.1.1.1", t0 + i))
    assert sum(a.rule_id == "ssh_bruteforce" for a in alerts) == 1


def test_window_expiry_prevents_firing():
    eng = DetectionEngine()
    t0 = 1_773_580_000.0
    alerts = []
    for i in range(4):
        alerts += eng.process(ssh_fail("1.1.1.1", t0 + i))
    alerts += eng.process(ssh_fail("1.1.1.1", t0 + 200))  # window is 60s
    assert not any(a.rule_id == "ssh_bruteforce" for a in alerts)


def test_correlation_catches_the_landed_login():
    eng = DetectionEngine()
    t0 = 1_773_580_000.0
    for i in range(5):
        eng.process(ssh_fail("2.2.2.2", t0 + i))
    alerts = eng.process(Event(t0 + 30, "auth", "authentication", "ssh_login",
                               "success", source_ip="2.2.2.2", user="root"))
    assert any(a.rule_id == "ssh_bruteforce_success" and a.severity == "critical"
               for a in alerts)


def test_match_rule_fires_per_event():
    eng = DetectionEngine()
    alert = eng.process(Event(1_773_580_000.0, "web", "web", "http_request", "success",
                              source_ip="9.9.9.9", url_path="/.env"))
    assert any(a.rule_id == "web_scan" for a in alert)


def test_every_alert_has_an_attack_technique():
    eng = DetectionEngine()
    t0 = 1_773_580_000.0
    for i in range(6):
        eng.process(ssh_fail("3.3.3.3", t0 + i))
    assert all(a.attack.startswith("T") for a in eng.alerts)


def test_large_egress_detected():
    eng = DetectionEngine()
    alerts = eng.process(Event(1_773_580_000.0, "network", "network", "flow",
                               source_ip="4.4.4.4", dest_ip="8.8.8.8", bytes=50_000_000))
    assert any(a.rule_id == "large_egress" for a in alerts)


def test_informational_rule_does_not_alert_by_default():
    """min_severity='low' means an informational success login doesn't page."""
    eng = DetectionEngine(min_severity="low")
    alerts = eng.process(Event(1_773_580_000.0, "auth", "authentication", "ssh_login",
                               "success", source_ip="5.5.5.5", user="alice"))
    assert not any(a.rule_id == "ssh_success" for a in alerts)
