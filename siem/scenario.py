"""A full multi-stage attack, embedded in benign traffic, for end-to-end replay.

The scenario a SIEM must actually handle: not one alert, but a *campaign* whose
stages span sources and time, buried in normal activity. This generates one — an
external attacker who scans, brute-forces SSH, lands, and exfiltrates — mixed
into web/auth/network noise from legitimate users, every event labelled so the
platform's output can be scored.
"""

from __future__ import annotations

import numpy as np

from .events import Event

ATTACKER = "45.13.37.9"
VICTIM_HOST = "web01"
EXFIL_DST = "203.0.113.50"


def build_scenario(benign_users: int = 50, duration: float = 3600,
                   seed: int = 23) -> tuple[list[Event], dict]:
    """Return (events sorted by time, ground-truth stage timestamps)."""
    rng = np.random.default_rng(seed)
    t0 = 1_773_580_000.0
    events: list[Event] = []

    # --- benign background: web browsing + normal SSH + flows ---
    internal = [f"10.0.0.{i}" for i in range(2, 2 + benign_users)]
    for _ in range(2000):
        ip = rng.choice(internal)
        ts = t0 + rng.uniform(0, duration)
        events.append(Event(ts, "web", "web", "http_request", "success",
                            source_ip=ip, url_path=rng.choice(["/", "/products", "/api/health"]),
                            http_status=200, user_agent="Mozilla/5.0", bytes=int(rng.integers(200, 4000)),
                            extra={"label": None}))
    for _ in range(300):
        ip = rng.choice(internal)
        ts = t0 + rng.uniform(0, duration)
        failed = rng.random() < 0.1
        events.append(Event(ts, "auth", "authentication", "ssh_login",
                            "failure" if failed else "success",
                            source_ip=ip, user=rng.choice(["alice", "bob"]), host=VICTIM_HOST,
                            extra={"label": None}))

    stages = {}

    # --- stage 1: recon scan (T1595) ~ t0+600 ---
    stages["recon"] = t0 + 600
    for i, path in enumerate(["/.env", "/.git/config", "/wp-admin", "/admin", "/backup.sql"]):
        events.append(Event(t0 + 600 + i * 4, "web", "web", "http_request", "success",
                            source_ip=ATTACKER, url_path=path, http_status=404,
                            user_agent="gobuster/3.6", bytes=200, extra={"label": "attack"}))

    # --- stage 2: SSH brute force (T1110) ~ t0+900 ---
    stages["bruteforce"] = t0 + 900
    for i in range(40):
        events.append(Event(t0 + 900 + i * 2, "auth", "authentication", "ssh_login", "failure",
                            source_ip=ATTACKER, user=rng.choice(["root", "admin"]), host=VICTIM_HOST,
                            extra={"label": "attack", "invalid_user": True}))

    # --- stage 3: successful login — the guess landed (T1078) ---
    stages["compromise"] = t0 + 980
    events.append(Event(t0 + 982, "auth", "authentication", "ssh_login", "success",
                        source_ip=ATTACKER, user="root", host=VICTIM_HOST,
                        extra={"label": "attack"}))

    # --- stage 4: exfiltration (T1048) ~ t0+1100 ---
    stages["exfil"] = t0 + 1100
    events.append(Event(t0 + 1100, "network", "network", "flow",
                        source_ip=ATTACKER, dest_ip=EXFIL_DST, dest_port=443,
                        bytes=45_000_000, protocol="tcp", extra={"label": "attack"}))

    events.sort(key=lambda e: e.timestamp)
    return events, stages
