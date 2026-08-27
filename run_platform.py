"""End-to-end: ingest the attack scenario, detect, investigate, measure.

    python run_platform.py
"""

from __future__ import annotations

import time

from siem.detect.engine import DetectionEngine
from siem.investigate.investigation import Investigation
from siem.scenario import ATTACKER, build_scenario
from siem.store.eventstore import EventStore


def main() -> None:
    events, stages = build_scenario()
    print(f"Scenario: {len(events):,} events, "
          f"{sum(1 for e in events if e.extra.get('label') == 'attack')} attack, "
          f"across auth/web/network\n")

    store = EventStore(retention_hours=24)
    engine = DetectionEngine()

    # --- ingest + detect, measuring per-event latency ---
    latencies = []
    ingest_start = time.perf_counter()
    for event in events:
        t = time.perf_counter()
        store.append(event)
        engine.process(event)
        latencies.append((time.perf_counter() - t) * 1e6)  # microseconds
    total = time.perf_counter() - ingest_start

    latencies.sort()
    p50 = latencies[len(latencies) // 2]
    p99 = latencies[int(len(latencies) * 0.99)]
    print("Ingestion + detection")
    print(f"  {len(events):,} events in {total*1000:.0f} ms "
          f"({len(events)/total:,.0f} events/sec)")
    print(f"  per-event latency: p50 {p50:.1f}µs, p99 {p99:.1f}µs")
    print(f"  {len(engine.alerts)} alerts fired\n")

    inv = Investigation(store, engine.alerts)

    print("Triage queue (what the analyst sees first)")
    for a in inv.triage_queue(limit=6):
        print(f"  [{a.severity:12}] {a.title:26} {a.entity:14} {a.attack}")
    print(f"\n  queue: {inv.queue_summary()}\n")

    print("Investigation: pivot on the critical alert's entity")
    critical = next(a for a in inv.triage_queue() if a.severity == "critical")
    print(f"  critical alert entity: {critical.entity}")
    act = inv.entity_activity("ip", critical.entity)
    print(f"  -> {act['event_count']} events across {act['sources']}")
    print(f"  -> exfiltrated to {act['connected_ips']}")
    print(f"  -> {len(act['alerts'])} alerts tie to this entity\n")

    print("Incident timeline (the postmortem writes itself)")
    print(inv.timeline("ip", ATTACKER).render())

    # --- did we catch every stage? ---
    print("\nCoverage: which attack stages produced an alert")
    alert_techniques = {a.attack.split(".")[0] for a in engine.alerts
                        if a.entity == ATTACKER}
    stage_map = {"recon": "T1595", "bruteforce": "T1110", "compromise": "T1110",
                 "exfil": "T1048"}
    for stage, technique in stage_map.items():
        caught = technique in alert_techniques
        print(f"  {stage:12} ({technique}): {'✓ detected' if caught else '· missed'}")

    # --- query latency at volume: entity pivot vs full scan ---
    print("\nQuery latency: entity pivot (indexed) vs full scan")
    n = 50
    t = time.perf_counter()
    for _ in range(n):
        list(store.by_entity("ip", ATTACKER))
    indexed = (time.perf_counter() - t) / n * 1e6
    t = time.perf_counter()
    for _ in range(n):
        [e for e in store.scan() if e.source_ip == ATTACKER]
    scan = (time.perf_counter() - t) / n * 1e6
    print(f"  indexed pivot: {indexed:.0f}µs | full scan: {scan:.0f}µs "
          f"({scan/indexed:.0f}x faster to pivot)")


if __name__ == "__main__":
    main()
