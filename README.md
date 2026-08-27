# CAPSTONE — Security Data Platform

A working SIEM: multi-source ingestion into a time-partitioned columnar store,
continuous detection with dedup and MITRE ATT&CK mapping, and an investigation
layer that turns an alert into a reconstructed incident. Days 23–26 — the first
capstone, assembling the security track into one platform.

```bash
pip install -r requirements.txt
python run_platform.py   # ingest an attack scenario end to end
pytest                   # 26 tests
```

## What it does, in one run

`run_platform.py` replays a full attack campaign — recon scan → SSH brute force →
a landed login → data exfiltration — buried in 2,300 benign events across auth,
web, and network logs. The platform ingests it, detects every stage, and hands an
analyst a reconstructed incident:

```
2,347 events in 13 ms (175,000 events/sec), per-event p50 5.3µs, p99 13.6µs
5 alerts fired, all tied to the attacker

Triage queue (worst first):
  [critical] SSH brute force succeeded  45.13.37.9  T1110.001
  [high    ] Large data egress          45.13.37.9  T1048
  [high    ] SSH brute force            45.13.37.9  T1110.001
  [medium  ] Sensitive path access      45.13.37.9  T1595.003
  [low     ] Scanning tool user agent   45.13.37.9  T1595

Coverage: recon ✓  bruteforce ✓  compromise ✓  exfil ✓   (all 4 stages)
Entity pivot: 6µs indexed vs 159µs full scan — 26x faster to reach evidence
```

## The findings

**Ingest-to-alert is microseconds, because detection runs inline.** The whole
2,347-event campaign is detected in one 13 ms pass — every event is scored as it's
stored, so there's no batch delay between an event landing and its alert. p99
per-event latency is 13.6µs. The bottleneck at scale wouldn't be detection; it'd
be the single-threaded ingest loop, which is the honest next thing to shard.

**The investigation layer is where the platform earns its keep.** Firing alerts is
the easy 20%; answering "what actually happened" is the 80% most tools skip. An
analyst here goes alert → entity → full timeline in **one indexed lookup each**,
because the store maintains inverted indexes from IP/user/host to events. That
pivot is **26x faster than scanning** the store — the difference between an
investigation and a grep.

**One entity, the whole story.** Because every source normalises to one schema and
every alert carries its entity, the attacker's SSH brute force (auth), scan
(web), and exfil (network) all collapse onto one IP. The timeline interleaves
events and alerts in time order, and the incident postmortem writes itself.

## How it's built

```
ingest → normalise (ECS) → columnar store → detect (inline) → investigate
         auth/web/network   time-partitioned  rules+correlation  triage/pivot/timeline
                            + entity indexes   + dedup + ATT&CK
```

### Ingestion & storage

Three source parsers (sshd, nginx, JSON flows) normalise into one ECS-named
`Event`. The store partitions by hour — every query has a time range, so a
detection over "the last hour" reads one partition, not all history — and
maintains **inverted entity indexes** (ip/user/host → events) so investigation
pivots are lookups, not scans. Retention is dropping old partitions.

### Detection

Match rules fire on one event; threshold rules fire when N events share an entity
in a window (brute force, stuffing). Alerts dedup — a 40-event brute force is one
alert. A correlation rule catches the successful login after a brute force from
the same IP (the guess that landed) as a distinct critical. Every rule maps to an
ATT&CK technique, so alerts group into a campaign by tactic. Detection runs
**inline with ingestion**, which is what makes ingest-to-alert latency a
per-event microsecond figure rather than a batch interval.

### Investigation

The layer that answers the analyst's real questions:

- **Triage queue** — open alerts, severity then recency. The front page.
- **Evidence pivot** — from an alert to the raw events behind it, one call.
- **Entity view** — everything one IP/user/host did, across all sources, plus its
  connected IPs and every related alert.
- **Timeline** — events and alerts interleaved in time order: the incident story.

## Depth questions

**How long from event ingestion to alert? Where's the bottleneck?**
Microseconds — detection is inline, so an event is scored the instant it's stored
(p99 13.6µs per event, 175k events/sec single-threaded). There's no ingest→detect
queue to add latency. The bottleneck at real volume is the single-threaded ingest
loop and the in-memory store; the fix is partitioning ingest across workers by
entity (so per-entity threshold windows stay local) and spilling cold partitions
to disk. Detection itself is cheap and embarrassingly parallel by partition.

**An analyst gets an alert. How many clicks to the raw evidence?**
One. `evidence(alert)` returns the raw events behind it directly, because the
alert carries its entity and the store indexes by entity — no query to write, no
time range to guess. That's deliberate: the number-of-clicks-to-evidence is the
metric that decides whether a SIEM gets used or worked around, and most tools make
it many (pick an index, write a query, join manually). Here entity → timeline is
also one call.

**What does your platform do that Splunk doesn't, and honestly, what does Splunk
do that you don't?**
It doesn't out-feature Splunk — Splunk is a decade of distributed indexing,
alerting, RBAC, and a mature query language (SPL). What this does well is the
*shape*: normalisation to one schema so a detection is source-agnostic, inline
detection so alerts have no batch delay, and an entity-first investigation model
where the pivot is a first-class indexed operation rather than a query you
assemble. What Splunk does that this doesn't: scale to petabytes, distribute
across a cluster, survive node failure, retain for years, and let an analyst
express an arbitrary ad-hoc query. This is the correct *architecture* at a size
you can hold in your head — which is exactly what makes it a good thing to have
built and be able to explain.

**Why normalise to one schema instead of querying each source's native format?**
Because a detection written against native formats is N detections — one per
source — and they drift. Normalising once means "authentication failure" is one
condition whether it came from sshd, a Windows 4625, or an nginx 401, so a rule,
an anomaly model, and the investigation views are all written once and work
everywhere. The cost is the parser layer and a schema that must evolve carefully;
the payoff is that everything above it is source-agnostic.

## Layout

```
siem/
  events.py            the normalised Event (ECS) + entity extraction
  ingest/parsers.py    sshd / nginx / flow -> Event
  store/eventstore.py  time-partitioned columnar store + entity indexes
  detect/rules.py      match & threshold rules, ATT&CK-mapped
  detect/engine.py     inline detection, dedup, correlation, alert store
  investigate/         triage queue, evidence pivot, entity view, timeline
  scenario.py          a full multi-stage attack in benign traffic
run_platform.py        the end-to-end replay + latency measurement
tests/                 26 tests
```

## What I'd do differently

I led with rules for a clean demo and left the Days 11–13 anomaly detectors
unwired, which means the platform shows signature detection but not behavioural
detection — and a real SIEM needs both, since the interesting attacks are the
ones no rule anticipates. I'd integrate the statistical/autoencoder detectors
into the same event stream so an alert can come from "this rule matched" *or*
"this entity's behaviour is anomalous." The timeline output is also too verbose —
it lists all forty brute-force events; I'd collapse repeated events into a count
with expand-on-demand, because a wall of identical lines is exactly the noise the
investigation layer is supposed to remove.

## Known gaps

- In-memory, single process. The architecture is faithful (partitioning, indexes,
  inline detection) but the scale story is simulated — real volume needs sharded
  ingest, on-disk partitions, and a distributed index.
- No anomaly detectors wired in yet. The Days 11–13 statistical/ML detectors plug
  into the same event stream; this capstone leads with rules for a clean demo.
- Rules are code, not a query language. Splunk's SPL / Sigma-as-config is the
  real interface; here rules are Python objects.
- No RBAC, audit log, or alert lifecycle beyond open/triaged/closed. Real SOC
  tooling needs all three.
- The entity index grows unbounded with the store; production ties it to the
  retention window.
