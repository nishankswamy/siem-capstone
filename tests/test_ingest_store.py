"""Ingestion into the columnar event store: normalisation, partitioning, entity
indexes, retention."""

from siem.events import Event
from siem.ingest.parsers import parse_flow, parse_nginx, parse_ssh
from siem.store.eventstore import PARTITION_SECONDS, EventStore


def test_all_sources_normalise_to_one_schema():
    ssh = parse_ssh("Mar 15 14:22:01 h sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2")
    web = parse_nginx('1.2.3.4 - - [15/Mar/2026:14:22:05 +0000] "GET /x HTTP/1.1" 401 5 "-" "curl"')
    flow = parse_flow('{"timestamp": 1773584525, "src_ip": "1.2.3.4", "dst_ip": "8.8.8.8", "bytes": 100}')
    # Same field accessor works across all three.
    for e in (ssh, web, flow):
        assert e.get("source.ip") == "1.2.3.4"
    assert ssh.get("event.category") == "authentication"
    assert web.get("event.category") == "web"
    assert flow.get("event.category") == "network"


def test_parsers_ignore_junk():
    assert parse_ssh("not a log line") is None
    assert parse_nginx("garbage") is None
    assert parse_flow("{bad json") is None


def test_events_partition_by_hour():
    store = EventStore()
    base = 1_773_580_000.0
    store.append(Event(base, "auth", "authentication", "ssh_login", "success", source_ip="a"))
    store.append(Event(base + PARTITION_SECONDS + 1, "auth", "authentication",
                       "ssh_login", "success", source_ip="a"))
    assert store.partition_count == 2


def test_scan_skips_partitions_outside_range():
    store = EventStore()
    base = 1_773_580_000.0
    for h in range(5):
        store.append(Event(base + h * PARTITION_SECONDS, "auth", "authentication",
                           "ssh_login", "success", source_ip="a"))
    # Query one hour; should see one event.
    got = list(store.scan(start=base + PARTITION_SECONDS, end=base + PARTITION_SECONDS + 10))
    assert len(got) == 1


def test_entity_index_links_across_sources():
    store = EventStore()
    base = 1_773_580_000.0
    store.append(Event(base, "auth", "authentication", "ssh_login", "failure", source_ip="1.2.3.4"))
    store.append(Event(base + 1, "web", "web", "http_request", "success", source_ip="1.2.3.4"))
    store.append(Event(base + 2, "network", "network", "flow", source_ip="1.2.3.4", dest_ip="8.8.8.8"))

    events = list(store.by_entity("ip", "1.2.3.4"))
    assert len(events) == 3
    assert {e.source for e in events} == {"auth", "web", "network"}


def test_retention_drops_old_partitions():
    store = EventStore(retention_hours=2)
    base = 1_773_580_000.0
    for h in range(6):
        store.append(Event(base + h * PARTITION_SECONDS, "auth", "authentication",
                           "ssh_login", "success", source_ip="a"))
    # Only the last ~2 hours' partitions survive.
    assert store.partition_count <= 3
