"""Detection rules: match and threshold, mapped to MITRE ATT&CK.

Two rule shapes, the distinction from the detection-engineering project: a
*match* rule fires on one event; a *threshold* rule fires when N matching events
share an entity inside a time window. Threshold rules are what catch brute force,
scanning and stuffing — patterns invisible in any single event.

Every rule carries an ATT&CK technique id, so an alert reads as a story
("credential access, T1110") not a code. That mapping is what lets the
investigation layer group an incident by tactic.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field


@dataclass
class Rule:
    id: str
    title: str
    severity: str                 # low | medium | high | critical
    attack: str                   # ATT&CK technique id
    match: dict                   # field -> expected value(s)
    threshold: int = 1            # 1 = match rule
    window: float = 0.0           # seconds; 0 = no window
    group_by: str = "source.ip"   # entity to count within

    def matches(self, event) -> bool:
        for field_name, expected in self.match.items():
            value = event.get(field_name)
            if isinstance(expected, (list, tuple)):
                if value not in expected:
                    return False
            elif callable(expected):
                if not expected(value):
                    return False
            elif value != expected:
                return False
        return True

    @property
    def is_threshold(self) -> bool:
        return self.threshold > 1


DEFAULT_RULES = [
    Rule("ssh_bruteforce", "SSH brute force", "high", "T1110.001",
         {"event.action": "ssh_login", "event.outcome": "failure"},
         threshold=5, window=60, group_by="source.ip"),
    Rule("web_cred_stuffing", "Web credential stuffing", "high", "T1110.004",
         {"event.category": "web", "http.response.status_code": [401, 403]},
         threshold=10, window=60, group_by="source.ip"),
    Rule("web_scan", "Sensitive path access", "medium", "T1595.003",
         {"url.path": lambda p: p is not None and any(
             s in p for s in ("/.env", "/.git", "/wp-admin", ".sql", "/admin"))}),
    Rule("scanner_ua", "Scanning tool user agent", "low", "T1595",
         {"user_agent.original": lambda ua: ua is not None and any(
             t in ua.lower() for t in ("sqlmap", "nikto", "nmap", "gobuster", "curl"))}),
    Rule("large_egress", "Large data egress", "high", "T1048",
         {"event.action": "flow",
          "network.bytes": lambda b: b is not None and b > 10_000_000}),
    Rule("ssh_success", "Successful SSH login", "informational", "T1078",
         {"event.action": "ssh_login", "event.outcome": "success"}),
]
