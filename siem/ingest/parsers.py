"""Source parsers. Each turns one raw format into normalised Events.

Deliberately compact — the parsing craft was the subject of the detection-
engineering and traffic-analysis projects. Here the parsers exist to feed the
platform; the point of this capstone is what happens *after* normalisation.

Every parser returns None for a line it doesn't recognise. Real ingestion sees
junk, and one bad line must never stall the pipeline.
"""

from __future__ import annotations

import json
import re
from datetime import datetime

from ..events import Event

_SSH = re.compile(
    r"(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"sshd\[\d+\]:\s+(?P<result>Failed|Accepted)\s+\w+\s+for\s+(?:invalid user\s+)?"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
)
_NGINX = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) "[^"]*" "(?P<agent>[^"]*)"'
)
_MONTHS = {m: i for i, m in enumerate(
    ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], 1)}


def parse_ssh(line: str, year: int = 2026) -> Event | None:
    m = _SSH.search(line)
    if not m:
        return None
    ts = datetime(year, _MONTHS[m["mon"]], int(m["day"]),
                  *map(int, m["time"].split(":"))).timestamp()
    return Event(
        timestamp=ts, source="auth", category="authentication", action="ssh_login",
        outcome="failure" if m["result"] == "Failed" else "success",
        source_ip=m["ip"], user=m["user"], host=m["host"],
        extra={"invalid_user": "invalid user" in line}, raw=line.strip())


def parse_nginx(line: str) -> Event | None:
    m = _NGINX.match(line.strip())
    if not m:
        return None
    ts = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z").timestamp()
    status = int(m["status"])
    return Event(
        timestamp=ts, source="web", category="web", action="http_request",
        outcome="failure" if status in (401, 403) else "success",
        source_ip=m["ip"], http_method=m["method"], url_path=m["path"],
        http_status=status, user_agent=m["agent"],
        bytes=int(m["bytes"]) if m["bytes"].isdigit() else 0, raw=line.strip())


def parse_flow(line: str) -> Event | None:
    """A JSON flow record (as a flow exporter would emit)."""
    try:
        r = json.loads(line)
    except json.JSONDecodeError:
        return None
    if "src_ip" not in r:
        return None
    return Event(
        timestamp=float(r["timestamp"]), source="network", category="network",
        action="flow", source_ip=r["src_ip"], dest_ip=r.get("dst_ip"),
        dest_port=r.get("dst_port"), protocol=r.get("protocol", "tcp"),
        bytes=r.get("bytes", 0), raw=line.strip())


PARSERS = {"ssh": parse_ssh, "nginx": parse_nginx, "flow": parse_flow}
