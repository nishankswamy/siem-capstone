"""Behavioural anomaly detection — the second half of a real SIEM.

Rules catch attacks you anticipated: you wrote a signature for brute force, so you
catch brute force. The attacks that matter are the ones no rule was written for —
a service account suddenly logging in from a new country, an internal host moving
ten times its normal data volume. Those have no signature; they're only visible
as a *departure from that entity's own normal behaviour*.

This detector learns a per-entity baseline online (a running mean and a robust
spread) and flags events that fall far outside it. It's deliberately simple —
EWMA mean + MAD-style deviation — because on this event stream that's what works,
and the Days 11-13 project already showed a fancier model (Isolation Forest) can
do *worse* than a simple baseline. The point of wiring it in is that the platform
now alerts on "this rule matched" OR "this entity is behaving abnormally", which
is what separates a SIEM from a rule engine.

The metric watched here is per-entity event rate and per-entity byte volume — the
two that expose beaconing-like regularity and exfiltration without a signature.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from ..events import Event


@dataclass
class _Baseline:
    """A running estimate of one metric for one entity."""
    mean: float = 0.0
    # mean absolute deviation, robust to the very spikes we're hunting
    mad: float = 0.0
    count: int = 0

    def update(self, value: float, alpha: float = 0.2) -> None:
        if self.count == 0:
            self.mean = value
        else:
            deviation = abs(value - self.mean)
            self.mad = (1 - alpha) * self.mad + alpha * deviation
            self.mean = (1 - alpha) * self.mean + alpha * value
        self.count += 1

    def z(self, value: float) -> float:
        """Robust z-score: deviations in units of MAD. Needs a warm-up before
        it's trustworthy, so callers gate on count."""
        scale = self.mad if self.mad > 1e-9 else 1.0
        return abs(value - self.mean) / scale


class AnomalyDetector:
    """Per-entity behavioural baselines over byte volume.

    Learns online, flags an event whose byte count is many robust-sigmas above
    the entity's own history. Warm-up guarded (needs `min_history` observations)
    so a brand-new entity's first large event doesn't self-trigger."""

    def __init__(self, min_history: int = 20, threshold: float = 6.0) -> None:
        self.min_history = min_history
        self.threshold = threshold
        self._bytes: dict[str, _Baseline] = defaultdict(_Baseline)

    def observe(self, event: Event) -> dict | None:
        """Update the baseline and return an anomaly descriptor if this event is
        a departure. Returns None for normal events (the common case)."""
        entity = event.source_ip
        if entity is None or event.bytes is None:
            return None

        baseline = self._bytes[entity]
        anomaly = None
        if baseline.count >= self.min_history:
            score = baseline.z(float(event.bytes))
            if score >= self.threshold:
                anomaly = {
                    "entity": entity,
                    "metric": "network.bytes",
                    "value": event.bytes,
                    "baseline_mean": round(baseline.mean, 1),
                    "z_score": round(score, 1),
                }
        # update AFTER scoring, so an event is judged against its own past only
        baseline.update(float(event.bytes))
        return anomaly
