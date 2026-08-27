"""The investigation layer — where most security tools are bad and this one isn't.

An alert is a starting point, not an answer. The analyst's real questions are:
what's worth looking at first (triage), what actually happened (pivot to the raw
events behind the alert), what did this attacker do overall (entity view), and in
what order (timeline). A platform that fires alerts but makes you grep raw logs to
answer those has done the easy 20% and skipped the 80%.

Every operation here is O(index lookup), not O(scan), because the store maintains
entity indexes. The measurable claim in the README is 'clicks to evidence' — each
of these methods is one such click.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from ..detect.engine import Alert, _SEVERITY_ORDER
from ..events import Event
from ..store.eventstore import EventStore


@dataclass
class IncidentTimeline:
    entity: str
    events: list          # (timestamp, kind, description)

    def render(self, collapse: bool = True) -> str:
        """Render the timeline. Consecutive identical events are collapsed into
        one line with a count and time span — a wall of forty identical brute-
        force lines is exactly the noise the investigation layer should remove."""
        lines = [f"Timeline for {self.entity}:"]
        i = 0
        rows = self.events
        while i < len(rows):
            ts, kind, desc = rows[i]
            if collapse and kind == "event":
                # look ahead for a run of the same description
                j = i
                while j < len(rows) and rows[j][1] == "event" and rows[j][2] == desc:
                    j += 1
                run = j - i
                if run > 1:
                    span = f"{_fmt(ts)}–{_fmt(rows[j-1][0])}"
                    lines.append(f"  {span}  ×{run:<4} {desc}")
                    i = j
                    continue
            marker = "🚨" if kind == "alert" else "  "
            lines.append(f"  {_fmt(ts)}  {marker} {desc}")
            i += 1
        return "\n".join(lines)


class Investigation:
    def __init__(self, store: EventStore, alerts: list[Alert]) -> None:
        self.store = store
        self.alerts = alerts

    # --- triage ------------------------------------------------------------

    def triage_queue(self, limit: int = 20) -> list[Alert]:
        """Open alerts, worst first. Severity then recency — the order an analyst
        works. This is the front page of the platform."""
        open_alerts = [a for a in self.alerts if a.status == "open"]
        return sorted(
            open_alerts,
            key=lambda a: (-_SEVERITY_ORDER.index(a.severity), -a.timestamp),
        )[:limit]

    def queue_summary(self) -> dict:
        counts = Counter(a.severity for a in self.alerts if a.status == "open")
        return {sev: counts.get(sev, 0) for sev in reversed(_SEVERITY_ORDER)}

    # --- pivot: alert -> the raw events behind it --------------------------

    def evidence(self, alert: Alert, window: float = 120) -> list[Event]:
        """The raw events that produced an alert: everything from the alert's
        entity around the alert time. One call — the 'pivot to evidence' click."""
        entity_type = alert.entity_type
        events = [e for e in self.store.by_entity(entity_type, alert.entity)
                  if abs(e.timestamp - alert.timestamp) <= window]
        return sorted(events, key=lambda e: e.timestamp)

    # --- entity view: everything one IP/user/host did ----------------------

    def entity_activity(self, entity_type: str, value: str) -> dict:
        """The full picture for one entity — the 'what else did this IP do?'
        view. Summarises across all sources, not just the one that alerted."""
        events = list(self.store.by_entity(entity_type, value))
        by_action = Counter(e.action for e in events)
        by_source = Counter(e.source for e in events)
        touched_ips = {e.dest_ip for e in events if e.dest_ip} | \
                      {e.source_ip for e in events if e.source_ip and e.source_ip != value}
        related_alerts = [a for a in self.alerts if a.entity == value]
        return {
            "entity": value,
            "event_count": len(events),
            "first_seen": min((e.timestamp for e in events), default=None),
            "last_seen": max((e.timestamp for e in events), default=None),
            "actions": dict(by_action),
            "sources": dict(by_source),
            "connected_ips": sorted(touched_ips),
            "alerts": related_alerts,
        }

    # --- timeline: reconstruct the incident --------------------------------

    def timeline(self, entity_type: str, value: str) -> IncidentTimeline:
        """Interleave an entity's events and alerts in time order — the incident
        story, which is what goes in the postmortem."""
        rows = []
        for e in self.store.by_entity(entity_type, value):
            rows.append((e.timestamp, "event",
                         f"{e.source}/{e.action} {e.outcome or ''}".strip()))
        for a in self.alerts:
            if a.entity == value:
                rows.append((a.timestamp, "alert",
                             f"ALERT [{a.severity}] {a.title} ({a.attack})"))
        rows.sort(key=lambda r: (r[0], r[1] != "alert"))
        return IncidentTimeline(value, rows)


def _fmt(ts: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S")
