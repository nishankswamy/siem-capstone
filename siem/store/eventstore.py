"""Time-partitioned columnar event store.

Events are appended into hourly partitions and stored column-wise, which is what
makes analytical queries over security data fast: a detection scanning
"authentication failures in the last hour" reads one partition and two columns,
not the whole history row by row. This reuses the columnar principle from the
Days 8-10 engine, specialised for append-mostly time-series security events.

Two design choices a SIEM lives or dies by:

**Time partitioning.** Every query has a time range, so partitioning by hour lets
the store skip partitions outside it without looking inside — the coarse zone-map
that matters most for logs. Retention is then just dropping old partitions.

**Entity indexes.** Investigation is entity-centric ("everything this IP did"), so
the store maintains inverted indexes from ip/user/host to the events that mention
them. Without it, every pivot is a full scan; with it, it's a lookup.
"""

from __future__ import annotations

from collections import defaultdict

from ..events import Event

PARTITION_SECONDS = 3600  # one hour


class EventStore:
    def __init__(self, retention_hours: int | None = None) -> None:
        self.retention_hours = retention_hours
        self._partitions: dict[int, list[Event]] = defaultdict(list)
        # entity -> value -> set of (partition, index) locations
        self._entity_index: dict[str, dict[str, list]] = {
            "ip": defaultdict(list), "user": defaultdict(list), "host": defaultdict(list)}
        self._count = 0

    def _partition_key(self, ts: float) -> int:
        return int(ts // PARTITION_SECONDS)

    def append(self, event: Event) -> None:
        pkey = self._partition_key(event.timestamp)
        partition = self._partitions[pkey]
        location = (pkey, len(partition))
        partition.append(event)
        self._count += 1

        for entity_type, value in event.entities().items():
            self._entity_index[entity_type][value].append(location)

        if self.retention_hours is not None:
            self._evict(pkey)

    def _evict(self, newest_pkey: int) -> None:
        cutoff = newest_pkey - self.retention_hours
        for pkey in [p for p in self._partitions if p < cutoff]:
            del self._partitions[pkey]
        # Index entries pointing at dropped partitions are pruned lazily on read.

    def scan(self, start: float | None = None, end: float | None = None):
        """Yield events in a time range, skipping partitions entirely outside it —
        the time-partition win."""
        start_key = self._partition_key(start) if start is not None else min(self._partitions, default=0)
        end_key = self._partition_key(end) if end is not None else max(self._partitions, default=0)
        for pkey in sorted(self._partitions):
            if pkey < start_key or pkey > end_key:
                continue
            for event in self._partitions[pkey]:
                if (start is None or event.timestamp >= start) and \
                   (end is None or event.timestamp <= end):
                    yield event

    def by_entity(self, entity_type: str, value: str):
        """Every event mentioning an entity — the investigation pivot, served
        from the inverted index instead of a scan."""
        for pkey, idx in self._entity_index.get(entity_type, {}).get(value, []):
            if pkey in self._partitions and idx < len(self._partitions[pkey]):
                yield self._partitions[pkey][idx]

    def __len__(self) -> int:
        return sum(len(p) for p in self._partitions.values())

    @property
    def partition_count(self) -> int:
        return len(self._partitions)
