# Incident report anatomy

What the standalone HTML report contains, section by section, and how to read
each one during a packet-buffer incident. Every report is a single
self-contained file: no external asset, the SHA-256 digest of the JSONL
capture it was built from, and a single hash-pinned script that does nothing
but fold the report's own sections.

Related pages: [Installation](installation.md) · [Operations](operations.md) ·
[Troubleshooting](troubleshooting.md) · [Back to the README](../README.md)

![A complete incident report, from the diagnosis block through pressure over
time, offender attribution, the ingress backlog, dataplane CPU tracking and the
folded appendices](images/incident-report.png)

> Every screenshot in this repository is generated from a fictitious
> incident by `tools/generate_demo_stack.py`. No firewall, address, or
> serial shown is real.

## Opening a report from the dashboard

Clicking anywhere on a completed run's row in **Recent runs** opens that run's
report. That is the only way in, and it is why the row no longer carries a
column of export links: the report page itself offers them, named by weight.
A run still being collected has no report yet, so its row stays plain and shows
a single **JSONL** link under its status, for the records written so far.

The report opened that way carries an evidence bar above it: a **Back to
dashboard** button, the firewall and the run the page belongs to, then the
run's exports, each named by format and by weight — **HTML** with its size,
**JSONL** with its size, **TXT** with its number of batch files, **ZIP** as the
support archive and **ZIP** anonymized. The bar is where you decide, having read
the report, that the case needs its raw evidence.

**HTML** downloads the report you are reading, as the single self-contained file
stored beside the capture. That is the file to attach to a mail or to a TAC
case: it opens on a workstation that has no access to this deployment, and it
needs neither Docker nor a network. It is named for the run it documents
(`pbp-report-<firewall>-<run_id>.html`), so several reports collected for one
case stay distinguishable. Print it from the browser to obtain a PDF instead.

Do not use the browser's own **Save page as** for this: the bar is added while
the page is served, and a manual save would keep it, together with links that
resolve only inside your deployment. The `report.html` file stored beside the
capture never contains the bar, which is exactly what the **HTML** export hands
over. The bar is also hidden when the page is printed.

## Layout and conventions

Reports contain a bounded two-axis timeline with sticky headers and batch
identifiers. Empty `error: null` fields are omitted from HTML while JSONL keeps a
stable schema. Opening a command displays its extracted `result` immediately;
the exact `raw_response` remains available in a nested section collapsed by
default. Command status and timing fields are presented as compact metadata,
the summary separates capture facts, incident state, and peak utilization, and
its peak metrics are grouped into packet buffers, packet descriptors, and
system load. Every section folds from its heading — Diagnosis included, a
native disclosure. The Diagnosis is the only part open by default: the
evidence sections sit folded under a **Going further — the evidence** heading,
each stating its one-line verdict on its summary ("buffers peaked at 4.5%",
"6 sessions + 9 sources RED", "no session at 2%", "no hot core"), and the
appendices (summary, timeline, batches, events) sit folded under
**Appendix — the complete capture**. The step numbering lives only in the
diagnosis; the sections carry plain names. Following an evidence link or a
navigation entry opens the targeted section: that is the report's single
hash-pinned script at work, and a report whose script is stripped simply
leaves the section to be opened by hand.

**Collapse all** sits at the right of the section navigation and folds every
section at once, except Diagnosis, which is the verdict block and stays open.
The same control then reads **Expand all** and opens them all — the way to
unfold the whole report, including before printing it, since a folded section
prints folded; each heading keeps working individually. It is the report's only script, allowed by its SHA-256
hash in the report's own Content-Security-Policy and in the one the Web UI
serves the page with, so nothing else can run in that page. The button is
created by that script, so a report whose script a mail gateway strips, or a
reader's policy blocks, shows exactly the page it always did, with every
section unfolded and no dead control.

## Diagnosis: the investigation, step by step

The report opens with a **Diagnosis** block that walks the questions an
engineer asks when a customer's PBP fires, in order, and answers each one from
the capture. Every step states what it found *or* that it found nothing, and
the closing **Conclusion for the case** is composed only from the steps that
were reached, so the report cannot claim a flood on one line and low pressure
on the next. The headline names the outcome: *Low pressure*, *Offender named
by the firewall*, *Offender in the ingress backlog*, one of the wider
hypotheses, or *No responsible party identified*. A row of chips recalls the
context: model and hardware family (Cavium gen3 such as PA-3200, PA-5200 and
PA-7000; x86 gen4 such as PA-400, PA-1400, PA-3400 and PA-5400; virtual),
PAN-OS version, PBP mode, and the thresholds the firewall itself reported.

**Step 1 — How much pressure, on which resource?** The packet-buffer peak, the
on-chip packet-descriptor peak on a Cavium chassis (an x86 platform never
returns that pool, and the report says so instead of showing "Not collected"),
the packet-descriptor and SW-tag peaks, the buffer latency peak, and the
thresholds. The alert and activate thresholds come from the PBP settings read
from the running configuration at monitor start and again at stop — the read
at stop wins when a commit landed during the incident, and a start read that
PBP's own mitigation contradicts (mitigating below the activate threshold it
reports, which happens when the monitor starts mid-commit) is named as such
rather than quoted; when a capture predates that
read, the alert threshold is taken from the firewall's own congestion log
(`alert threshold is N%`) if a trigger carried it, and the lowest utilization
at which PBP was seen mitigating bounds the activate threshold. The buffer
latency (`show session packet-buffer-protection buffer-latency`, per batch)
is read against the latency thresholds: latency at or above the activate
threshold with low buffers is the latency case, and the step says whether this
firewall runs latency-based PBP, which acts on it, or buffer-based PBP, which
does not see it. A disabled measurement is stated. The Pressure section
tabulates the latency per batch and dataplane. Pressure is judged against the
PAN-OS levels: buffers at or above 80% are *exhausted*, descriptors at or
above 80% with low buffers are *the latency case* the PBP TOI describes,
buffers between 50% and 80% are *elevated*, and anything below 50% is *low
pressure* — if PBP still activated, the trigger is a lowered threshold, not
resource exhaustion, and every later step is read in that light: the entries
PBP ranked are the ordinary traffic mix, not an attack.

**Step 2 — Did the firewall already name the offender?** The entries of
`show session packet-buffer-protection` with `Drop State = Yes`, which are the
entries whose dataplane work PBP learned as the largest and the ones its threat
logs 8507, 8508 and 8509 report: the firewall's own designation and the place
to start, not a proof by itself. A session is named with its tuple,
application, rule and zone from `show session id`; a source address alone is
slowpath work, traffic that never completed session setup, and the traffic log
recovered at monitor stop says whether it was denied and by which rule. The
PBP threat logs of the incident window, queried once at stop, confirm the
list: the step counts them by ID, names the sources placed in the block table
(8509) and the sessions discarded (8508), and designates from them alone when
no batch caught an entry marked for RED, because PBP had acted before or
between the batches. They appear in full in a **PBP threat logs** section under
step 2, and a failed query is stated. When PBP never activated (alert only) and
logged nothing, the step says no offender was learned; when it activated but
marked nothing for RED, the work was spread over many small entries.

**Step 3 — Does the ingress backlog hold a session?** The sessions holding at
least 2% of the work queue in `show running resource-monitor
ingress-backlogs`, with the queue's peak ATOMIC and TOTAL usage. This view is
independent of the PBP learning: it is the queue of packets waiting for a
dataplane core, where the on-chip descriptors are consumed. An `undecided` or
`unknown` application at a high share is called out as the signature of attack
traffic, and a session queued in `flow_slowpath` that `show session id` does
not know (`Bad Key`) is the policy-deny case: the same six-tuple, typically UDP
syslog, denied and re-evaluated packet by packet on one core. An empty result
on an x86 platform is stated as not being proof, because PAN-OS documents the
command for the hardware queue of the Cavium chassis.

**Step 4 — If not, where else?** Five hypotheses, each with its own verdict:

- *Elephant session* — one `flow_fastpath` core hot against the median of its
  peers, or a session above the largest-sessions threshold listed through most
  of the capture at 100 Mbit/s or more.
- *Burst of denied sessions* — `flow_policy_deny` and DoS or zone-protection
  drops at 100 packets per second or 5,000 packets over the capture, a packet
  rate that rises while the session count stays flat, PBP tracking source
  addresses without a session, or a zone-protection flood log received during
  the capture.
- *Storm of new sessions* — 500 new connections per second, or a source that
  PBP tracks owning 100 or more ranked sessions.
- *Interface errors* — receive discards, missed frames or transmit errors
  growing on the interfaces the evidence named.
- *Aggregate load* — every comparable core rising together to 60% or more, or
  the session table at 80% of its capacity.

At low pressure the signals are listed but not blamed. When the pressure is
real and nothing names a cause, the headline says so and the conclusion points
at the software-defect scenario of the PAN-OS guidance: a Tech Support File
taken while the pressure lasts, with the PBP threat logs and the buffer latency
reading.

The evidence sections follow in the same order — pressure, offenders named by
PBP, ingress backlog, then the four wider views — each with its own verdict
sentence, and the appendices (summary cards, timeline, batch details, events)
start folded. The header shows formatted start and end times, the duration,
and the stop reason in words with its slug underneath; a sticky navigation bar
links every section, and each section starts with the question it answers.
Peak cards and timeline cells turn amber above the alert level and red above
the activate level, a metric the firewall never returned reads "Not collected"
and is hidden from the timeline columns, batch summaries show their buffer
reading without being opened, time columns show the clock time with the full
timestamp on hover, and the per-core CPU tables fold away when no core came
close to saturation.

## Top sources and pressure over time

A **Top sources** table above the attribution ranking rolls ranked sessions up
by source address — a scan or flood spread over hundreds of short sessions is
attributed to the source that owns them. Both tables list at most 50 rows in
ranking order and state how many lower-ranked entries were left out; the JSONL
capture keeps every ranked entity, and the stop marker and the diagnosis are
computed from all of them. A **Pressure over time** chart
plots packet-buffer, descriptor, and session-table utilization batch by batch
so the offender's first appearance can be aligned with the pressure curve. Its
vertical axis fits the data (10, 25, 50, or 100%) so a lightly loaded firewall
is not a flat line, the PBP alert and activate levels are drawn when they fit,
the peak is labelled, and one triangle marks each syslog trigger received
during the capture. A **Diagnostic pools** table under the pressure evidence
lists the worst occupancy observed per dataplane for the pools whose state
diagnoses an incident by itself — the on-chip `PKI POOL DFLT` (the pool the
firewall's `Packet buffer congestion` alert measures on ASIC platforms), the
proxy `Timer Pool` an SSL-proxy leak consumes, the decryption load pools
(`proxy_flow`, `ssl_st`, `fptcp_seg`), and any other pool seen at 80% used or
more. A pool held near full while the dataplane CPU idles means the resource
is leaked or parked, not processed.

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

Under the drop table, a **Root-cause counter signals** part surfaces counter
families that are mostly informational and therefore never appear in a
drop-severity table, yet each is the fingerprint of one known way a packet
buffer fills: PBP's own mitigation under both naming families
(`flow_dos_pbp_*` on PAN-OS 10.2/11.x, `pkt_buf_protect_*` elsewhere), the
blocked-source collateral (`flow_dos_drop_ip_blocked` — the size of the silent
outage a block-ip causes when it hits shared infrastructure), ARP/L2 storms
(`flow_arp_pkt_rcv` with its gratuitous share — a flood PBP cannot name or
block because it creates no session), IP fragmentation tied to buffer
exhaustion (`flow_ipfrag_*` and its allocation errors), outright buffer
allocation failures, the decryption proxy's own retransmissions
(`tcp_fptcp_*`), out-of-order queues held by one-way or TAP feeds, and the
zone-protection flood counters whose silence while PBP drops climb means the
flood came through a zone with flood protection disabled. When a large share
of the PBP drops used the ingress interface's zone id
(`flow_dos_pbp_ifp_zone`), the section warns that the zone written on PBP
threat logs is not the session's real zone.

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
report stays a single self-contained file with no external asset, and no script
beyond the hash-pinned folding control.
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
cores that actually forward traffic. What distinguishes each core from its
peers, such as `flow_mgmt`, `flow_ctrl`, or `pan_timer`, is recalled once under
the dataplane heading; the charts and the verdict then name a core by its
number alone, which keeps the legend and the heatmap rows short. Only cores
carrying `flow_fastpath` are compared: a timer core sitting permanently at 0%
is not a sign of imbalance. The per-core summary table underneath still lists
the complete function groups of every core.

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

