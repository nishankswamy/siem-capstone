"""The normalised event — the spine of the whole platform.

Every source, however it's formatted, becomes one of these before storage. Rules,
anomaly detectors, the investigation views, and the timeline all address these
fields and never the raw log. That single schema is what makes a SIEM a platform
rather than a pile of parsers: a detection written once runs against auth logs,
web logs and network flows alike.

Field names follow the Elastic Common Schema (ECS) so the schema matches
something real rather than something invented here.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Event:
    timestamp: float             # unix seconds
    source: str                  # "auth" | "web" | "network"
    category: str                # "authentication" | "web" | "network"
    action: str                  # "ssh_login", "http_request", "flow", ...
    outcome: str | None = None   # "success" | "failure"

    source_ip: str | None = None
    dest_ip: str | None = None
    user: str | None = None
    host: str | None = None

    # web
    http_method: str | None = None
    http_status: int | None = None
    url_path: str | None = None
    user_agent: str | None = None
    bytes: int | None = None

    # network
    dest_port: int | None = None
    protocol: str | None = None

    raw: str = ""
    extra: dict = field(default_factory=dict)

    def get(self, dotted: str):
        """Field access by ECS dotted name, e.g. 'source.ip'. The one place the
        dotted<->attribute mapping lives, so rules and events never argue about
        spelling."""
        mapping = {
            "@timestamp": "timestamp", "event.category": "category",
            "event.action": "action", "event.outcome": "outcome",
            "source.ip": "source_ip", "destination.ip": "dest_ip",
            "user.name": "user", "host.name": "host",
            "http.request.method": "http_method",
            "http.response.status_code": "http_status",
            "url.path": "url_path", "user_agent.original": "user_agent",
            "network.bytes": "bytes", "destination.port": "dest_port",
            "network.protocol": "protocol",
        }
        if dotted in mapping:
            return getattr(self, mapping[dotted])
        return self.extra.get(dotted)

    def entities(self) -> dict:
        """The entities this event touches — IPs, users, hosts. Investigation
        pivots on these: 'what else did this IP do?' is a filter on one of
        them."""
        out = {}
        if self.source_ip:
            out["ip"] = self.source_ip
        if self.user:
            out["user"] = self.user
        if self.host:
            out["host"] = self.host
        return out
