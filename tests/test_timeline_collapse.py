"""Timeline collapse: a run of identical events becomes one line with a count."""

from siem.investigate.investigation import IncidentTimeline


def test_collapses_a_run_of_identical_events():
    rows = [(float(i), "event", "auth/ssh_login failure") for i in range(40)]
    rendered = IncidentTimeline("x", rows).render(collapse=True)
    assert "×40" in rendered
    # 40 identical lines become one, plus the header.
    assert rendered.count("ssh_login failure") == 1


def test_alerts_are_never_collapsed():
    rows = [(1.0, "event", "flow"), (2.0, "alert", "ALERT [high] egress"),
            (3.0, "event", "flow")]
    rendered = IncidentTimeline("x", rows).render(collapse=True)
    assert "🚨" in rendered
    assert "ALERT" in rendered


def test_distinct_events_are_not_merged():
    rows = [(1.0, "event", "a"), (2.0, "event", "b"), (3.0, "event", "a")]
    rendered = IncidentTimeline("x", rows).render(collapse=True)
    assert "×" not in rendered            # no run of length > 1


def test_collapse_can_be_turned_off():
    rows = [(float(i), "event", "same") for i in range(5)]
    rendered = IncidentTimeline("x", rows).render(collapse=False)
    assert rendered.count("same") == 5
