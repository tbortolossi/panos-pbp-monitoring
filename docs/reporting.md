# Incident report anatomy

What the standalone HTML report contains, section by section, and how to read
each one during a packet-buffer incident. Every report is a single
self-contained file: no script, no external asset, and the SHA-256 digest of
the JSONL capture it was built from.

Related pages: [Installation](installation.md) · [Operations](operations.md) ·
[Troubleshooting](troubleshooting.md) · [Back to the README](../README.md)

![A complete incident report, from the at-a-glance block through offender
attribution, pressure over time, dataplane CPU tracking, the timeline and the
raw batch details](images/incident-report.png)

> Every screenshot in this repository is generated from a fictitious
> incident by `tools/generate_demo_stack.py`. No firewall, address, or
> serial shown is real.

## Layout and conventions

Reports contain a bounded two-axis timeline with sticky headers and batch
identifiers. Empty `error: null` fields are omitted from HTML while JSONL keeps a
stable schema. Opening a command displays its extracted `result` immediately;
the exact `raw_response` remains available in a nested section collapsed by
default. Command status and timing fields are presented as compact metadata,
the summary separates capture facts, incident state, and peak utilization, and
its peak metrics are grouped into packet buffers, packet descriptors, and
system load. Every section folds from its heading — a native disclosure,
no script — so a section already read can be put away; all open by default
except the lower-level event metadata, which is collapsed.

## At a glance and probable cause

The report opens with an **At a glance** block that names the severity from
the peak packet-buffer pressure against the PAN-OS PBP defaults (low below the
50% alert level, elevated between alert and the 80% activate level, critical at
or above it), lists the key figures (peak, duration, batches, triggers, top
offender, denied packets, PBP state, stop reason), and carries the
**Probable cause** sentences: the peak buffer usage, the strongest offender
with its flow and rate, the denied-traffic correlation, and the session-table
verdict, composed into a few sentences ready for a TAC case. The header shows
formatted start and end times, the duration, and the stop reason in words with
its slug underneath; a sticky navigation bar links every section, and each
section starts with the question it answers. Peak cards and timeline cells turn
amber above the alert level and red above the activate level, a metric the
firewall never returned reads "Not collected" and is hidden from the timeline
columns, batch summaries show their buffer reading without being opened, time
columns show the clock time with the full timestamp on hover, and the per-core
CPU tables fold away when no core came close to saturation.

## Top sources and pressure over time

A **Top sources** table above the attribution ranking rolls ranked sessions up
by source address — a scan or flood spread over hundreds of short sessions is
attributed to the source that owns them. Both tables list at most 50 rows in
ranking order and state how many lower-ranked entries were left out; the JSONL
capture keeps every ranked entity, and the stop marker and probable cause are
computed from all of them. A **Pressure over time** chart
plots packet-buffer, descriptor, and session-table utilization batch by batch
so the offender's first appearance can be aligned with the pressure curve. Its
vertical axis fits the data (10, 25, 50, or 100%) so a lightly loaded firewall
is not a flat line, the PBP alert and activate levels are drawn when they fit,
the peak is labelled, and one triangle marks each syslog trigger received
during the capture.

## Denied and dropped traffic

The **Denied and dropped traffic** section aggregates the `drop` severity global
counters returned by `show counter global filter delta yes` over the whole
capture, with the total packet count, the peak per-second rate, and the number
of batches each counter appeared in. Counters are grouped by their PAN-OS aspect
and name prefix — policy deny, DoS or zone protection, PBP RED drops,
forwarding, parse, resource exhaustion — so a counter renamed or added by a
later PAN-OS release is still classified instead of being dropped from the
report. The `flow_dos_pbp_*` counters are packet buffer protection's own RED
drops: they measure the mitigation, not traffic refused before session setup,
so they form their own family and are reported in the verdict without being
added to the denied total. A batch whose delta
baseline was untrusted is excluded from the totals, because its sampling window
is unknown, and the report says how many batches were counted and excluded.

That section answers a question the offender table cannot. A UDP or GRE flood
denied by a Security policy rule never reaches session setup, so the firewall
creates no session for it: the PBP table can attribute the pressure to a source
IP only, and `show session id` has nothing to enrich. When denied packets are
counted while a source IP is ranked without an enriched session, the report
states that correlation explicitly. The **Denied packets** summary card carries
the same total, adding policy deny to DoS and zone-protection drops.

## Live sessions and traffic-log evidence

For exactly those sources, the collector recovers the missing flow detail from
the firewall itself at monitor stop, bounded to the top 3 ranked sources.
First their live sessions: a filtered count then a listing capped at 20
entries per source enumerates a flood that passes policy (destinations,
ports, applications, zones) without scanning the session table, rendered as
**Live sessions of top sources**. Then one bounded, read-only traffic-log
query per source (20 entries) recovers what never created a session, rendered
as **Traffic log evidence for unenriched sources** with destinations, ports,
applications, rules, and actions — the part of the answer no session command
can provide for denied traffic. The raw responses are preserved in the JSONL
capture, and a failed lookup never delays the stop marker or the report.

## Session table

The **Session table** section follows `show session info` batch by batch: the
allocated sessions and the table utilization, the split by protocol with the
remainder shown as `Other`, the new connection rate, the packet rate, the
throughput, and the number of sessions created between two batches, derived from
the since-bootup counter. Peaks are summarized as cards above the table.

The section states what the session table did while the buffers were under
pressure. A table above 80% of its capacity is a constraint of its own, because
PAN-OS then accelerates session aging and can refuse new sessions. A packet rate
that multiplies while the session count barely moves means packets arrived
without sessions being created, which is what a flood denied before session
setup looks like from the session table, and it must be read together with the
denied and dropped traffic section. Sessions growing with the load point back to
the offender attribution table instead. PAN-OS prints the utilization truncated
to a whole percent, so the report derives it from allocated over supported to
keep the movement of a lightly loaded table visible.

## Largest sessions

The **Largest sessions** section answers a question no other section can: was
one very large transfer occupying the link while the buffers filled? It follows
`show session all filter min-kb <threshold> min-age <seconds>`, issued once per
batch, and lists what matched with its flow, its application, its zones, its
ingress and egress interfaces, and four figures:

- **Open for** — the session age, measured against the firewall clock collected
  in the same batch, never against the collector clock.
- **Volume** — the cumulative byte counter PAN-OS reports for the session.
- **Avg Mbit/s** — that volume spread over the whole life of the session.
- **Peak Mbit/s** — the fastest interval measured between two consecutive
  batches, which is the only figure that describes what the session was doing
  during the incident.

Read the two rates together. A session that moved 40 GB but has been open since
yesterday shows a low average, and a low peak means it was idle while the
buffers filled: it is volume, not a cause. A high peak on a session whose
average is far lower is a transfer that started with the incident. A session
listed in every batch with a peak comparable to the link speed is the elephant.

This section exists because such a session is invisible everywhere else. PAN-OS
writes the traffic log when a session closes, so nothing appears in the log
while the transfer runs; an offloaded session is barely visible on the
management plane; and PAN-OS never names it as a packet-buffer offender, so the
offender ranking cannot rank it. The section states instead of showing an empty
table when nothing matched, when the query is disabled, or when the capture
predates the feature. A session index PAN-OS recycled during the incident
appears as a separate row rather than inheriting the volume of its predecessor.

## Dataplane CPU

Each batch requests `show running resource-monitor second last N`, where `N` is
`ceil(poll_seconds) + 2`, bounded to 60 seconds. The two-second margin avoids
missing CPU spikes because of command duration or scheduling jitter. Every
returned per-core average and maximum is preserved, together with the latest
value, window average, window peak, hot-point count, and sample count. Adjacent
windows intentionally overlap and must not be summed as unique seconds.

The HTML report draws one section per dataplane, so a chassis with several
dataplanes produces one set of charts per DP. Each section states whether the
load rose on every comparable core or on only a few of them, then shows a
heatmap of core by batch, which stays readable at 64 cores, and a line chart of
the hottest cores against the median of their peers. Both are inline SVG: the
report stays a single self-contained file with no script and no external asset.
The per-core summary table and the batch imbalance timeline remain underneath as
the detailed evidence.

The distinction the charts are built for is the one that matters
operationally. Every comparable core rising together is aggregate load. One core
saturated while its peers stay cold is flow-hash concentration, which is what a
single very high-rate session looks like from the dataplane. This corroborates
possible flow-hash concentration; it does not prove that one session alone is
responsible, so it must be read alongside session rates, PBP offenders, and
ingress backlogs.

Dataplane cores are not interchangeable, so the comparison is restricted to
cores that actually forward traffic. Cores are labelled by what distinguishes
them from their peers, such as `flow_mgmt`, `flow_ctrl`, or `pan_timer`, and
only cores carrying `flow_fastpath` are compared: a timer core sitting
permanently at 0% is not a sign of imbalance.

## Where the dataplane core map comes from

That map comes from `show statistics`, which PAN-OS answers with one entry per
core. Because the assignment is fixed for a platform and PAN-OS release, the
command runs **once per firewall**, when the firewall is saved in the admin UI,
next to the `show system info` call that already validates the API key. The
result is stored with the firewall and the release it was captured on, so an
incident spends no API call on a firewall that is already under pressure. The
save confirmation reports how many cores were mapped.

A PAN-OS upgrade can reassign function groups, so a stored map is only trusted
while the model and PAN-OS version still match what the incident reads from
`show system info`. On a mismatch the collector reads the map again for that
incident and logs that the firewall should be saved again to refresh the stored
copy. Each `monitor_started` record carries the map it used and a
`dp_core_functions_source` field naming where it came from, `configuration` or
`firewall`, so incident evidence stays self-contained. `--check-api` always
calls the command, because its purpose is to prove that the configured API
administrator can run everything the collector needs.

A firewall that cannot answer the command is still saved normally. The incident
records a `dataplane core function groups could not be read` warning, and the
charts still render with cores labelled by number.

