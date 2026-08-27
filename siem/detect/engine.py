"""The detection engine: rules + anomaly hooks, dedup, ATT&CK, an alert store.

Runs events past every rule. Threshold rules keep a per-entity sliding window;
match rules fire immediately. Two platform behaviours the earlier detection
project established, carried here:

**Dedup.** A brute-force burst is one alert, not four hundred. Once a rule fires
for an entity it stays quiet for that entity until the dedup window drains, so a
sustained attack is a steady signal, not a flood.

**Correlation.** A successful SSH login from an IP that was just brute-forcing is
a distinct, higher-severity alert — the guess that landed. Informational events
feed correlation without alerting on their own.

Alerts carry the triggering event and the entity, which is what the investigation
layer pivots on.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field

from ..events import Event
from .rules import DEFAULT_RULES, Rule


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str
    attack: str
    timestamp: float
    entity: str
    entity_type: str
    count: int
    event: Event
    status: str = "open"          # open | triaged | closed
    id: int = 0

    def key(self) -> tuple:
        return (self.rule_id, self.entity)


_SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]


class DetectionEngine:
    def __init__(self, rules: list[Rule] | None = None,
                 dedup_window: float = 300, min_severity: str = "low") -> None:
        self.rules = rules or DEFAULT_RULES
        self.dedup_window = dedup_window
        self.min_severity = min_severity
        self._windows: dict[tuple, deque] = defaultdict(deque)
        self._last_fired: dict[tuple, float] = {}
        self._recent_bruteforce: dict[str, float] = {}
        self.alerts: list[Alert] = []
        self._next_id = 1

    def _entity_value(self, event: Event, group_by: str) -> str:
        return str(event.get(group_by) or event.source_ip or "-")

    def _emit(self, rule_id, title, severity, attack, event, entity, entity_type, count) -> Alert:
        alert = Alert(rule_id, title, severity, attack, event.timestamp,
                      entity, entity_type, count, event, id=self._next_id)
        self._next_id += 1
        self.alerts.append(alert)
        return alert

    def _suppressed(self, rule_id, entity, now) -> bool:
        last = self._last_fired.get((rule_id, entity))
        return last is not None and (now - last) < self.dedup_window

    def process(self, event: Event) -> list[Alert]:
        fired = []
        for rule in self.rules:
            if not rule.matches(event):
                continue
            alert = self._threshold(rule, event) if rule.is_threshold else self._match(rule, event)
            if alert is not None:
                fired.append(alert)
                if rule.id == "ssh_bruteforce":
                    self._recent_bruteforce[alert.entity] = event.timestamp

        # correlation: successful login after a recent brute force from same IP
        if (event.action == "ssh_login" and event.outcome == "success"
                and event.source_ip in self._recent_bruteforce
                and event.timestamp - self._recent_bruteforce[event.source_ip] <= 300):
            del self._recent_bruteforce[event.source_ip]
            fired.append(self._emit(
                "ssh_bruteforce_success", "SSH brute force succeeded", "critical",
                "T1110.001", event, event.source_ip, "ip", 1))
        return fired

    def _match(self, rule, event) -> Alert | None:
        if _SEVERITY_ORDER.index(rule.severity) < _SEVERITY_ORDER.index(self.min_severity):
            return None
        entity = self._entity_value(event, rule.group_by)
        if self._suppressed(rule.id, entity, event.timestamp):
            return None
        self._last_fired[(rule.id, entity)] = event.timestamp
        etype = "user" if rule.group_by == "user.name" else "ip"
        return self._emit(rule.id, rule.title, rule.severity, rule.attack,
                          event, entity, etype, 1)

    def _threshold(self, rule, event) -> Alert | None:
        entity = event.get(rule.group_by)
        if entity is None:
            return None
        wkey = (rule.id, entity)
        window = self._windows[wkey]
        window.append(event.timestamp)
        cutoff = event.timestamp - rule.window
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) < rule.threshold:
            return None
        if self._suppressed(rule.id, str(entity), event.timestamp):
            return None
        self._last_fired[(rule.id, str(entity))] = event.timestamp
        etype = "user" if rule.group_by == "user.name" else "ip"
        return self._emit(rule.id, rule.title, rule.severity, rule.attack,
                          event, str(entity), etype, len(window))

    def run(self, events) -> list[Alert]:
        out = []
        for event in events:
            out.extend(self.process(event))
        return out
