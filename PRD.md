# PRD — PAN-OS PBP Incident Orchestrator

## 1. Summary

The product automatically captures the volatile evidence required to analyze
rising packet-buffer or on-chip packet-descriptor usage on a PAN-OS firewall.
It starts when a PAN-OS log is received, polls the firewall at short intervals,
identifies candidate sessions, and preserves timestamped evidence for network
engineers or TAC.

## 2. Problem

The `show session packet-buffer-protection` and
`show running resource-monitor ingress-backlogs` commands generally need to run
during the incident. After a session disappears or is discarded, its
`session-id` and 5-tuple may no longer be available. PBP logs alone may be
aggregated and do not always describe the original flow.

## 3. Goals

- Trigger collection without human intervention.
- Capture packet-buffer, packet-descriptor, and resource-monitor views together.
- Immediately enrich each candidate session with `show session id`.
- Identify and rank contributing sessions **or source IPs** without confusing
  primary PBP evidence with ingress corroboration.
- Derive candidate-session throughput from bounded cumulative byte-counter
  samples without scanning the complete session table.
- Continue while resource usage remains high.
- Produce a raw, structured, timestamped history.
- Correlate collector time with the firewall clock and identify the device.
- Produce a readable HTML view without replacing the JSONL evidence.
- Produce one human-readable raw TXT export per collection batch.
- Expose local, read-only reception and incident status without querying or
  changing the firewall.
- Configure collector behavior, monitored firewalls, and API credentials
  through an authenticated HTTPS admin page reachable remotely on a protected
  management network. One firewall IP declares both the API endpoint and the
  allowed Syslog source, and the device serial is read from the firewall rather
  than typed.
- Operate directly against a firewall or through Panorama.
- Route an HA or multi-firewall trigger to the emitting device without assuming
  which member is active.

## 4. Non-goals

- Automatically block an IP address or delete a session.
- Change PBP, Zone Protection, DoS Protection, or Security Policies.
- Replace a SIEM, Panorama, AIOps, or a long-term monitoring system.
- Automatically infer that a flow is malicious.

## 5. Triggers

The collector must recognize these messages by default:

| Message | PAN-OS log | Role |
|---|---|---|
| `Packet buffer congestion` | System / informational | Early trigger at the Alert threshold |
| `PBP Packet Drop` / 8507 | Threat / high | RED active |
| `PBP Session Discarded` / 8508 | Threat / high | Session discarded |
| `PBP IP Blocked` / 8509 | Threat / high | Source blocked |

These product-specific trigger signatures are fixed in code so deployment
configuration cannot accidentally disable incident detection. A trigger
received while a monitor is active must reinforce or extend that monitor rather
than create a concurrent one.

## 6. Functional flow

1. The firewall sends a System or Threat log to the Syslog collector.
2. The listener filters the message. The raw trigger, original Syslog source,
   sequence number, and extracted forensic fields are correlated with the
   incident `run_id`. A THREAT trigger's positional CSV fields are the primary
   extraction: source and destination address, ports, application, rule, zones,
   ingress interface, and session ID are read from their fixed comma-separated
   positions (validated individually; a field that does not validate is
   absent). Labelled forms remain a fallback for non-CSV relays. The extracted
   session ID feeds immediate session enrichment and the source address feeds
   the offender ranking. In multi-target mode, source IP first defines the allowed
   candidate set and device serial must then be one of the serials registered
   for that set: PAN-OS positions the serial in the third comma-separated field
   of every log, so a message that carries no serial, or a serial belonging to
   no candidate, is refused. A candidate saved without a serial on record
   disables that second gate for its source and keeps the source-only rule. A
   source shared by several targets is probed read-only across those candidates
   and ambiguous results safely fan out only within that allowlist. A THREAT
   log of subtype flood that is not itself a PBP trigger (zone protection, DoS
   protection) corroborates an active incident through the same acceptance
   gates: it extends the trigger-inactivity window, feeds its extracted flow
   into the offender evidence, and is copied into the capture; it never starts
   a monitor and never affects the recovery decision.
3. Each enabled firewall is verified read-only every `target_check_hours`, 24 by
   default and 0 to disable: `show system info` for reachability, API key
   validity and release drift, and `show statistics` only when the stored core
   map is missing or was captured on a different model or release. No capture is
   written, and a firewall with an active incident is skipped. An administrator
   can request the full validation batch for one firewall from the admin UI; the
   request travels through the configuration database because the Web service
   mounts the evidence volume read-only and the collector exposes no port.
4. At startup, the monitor runs `show system info` once without delaying the
   first diagnostic batch. The dataplane core-to-function-group map returned by
   `show statistics` is captured once per firewall, when the firewall is saved,
   and stored with the model and PAN-OS release it was captured on. An incident
   reuses it and spends no API call unless that identity no longer matches, in
   which case it is read again for that incident. A firewall that cannot answer
   the command records a parse warning and keeps collecting.
5. At incident startup, the monitor primes the global-counter delta baseline
   separately. At the start of each batch, it starts `show clock`, then collects
   the following commands in parallel every five seconds without waiting for
   the clock request to time out:
   - `show session packet-buffer-protection`;
   - `show session info`;
   - `show running resource-monitor ingress-backlogs`;
   - `show running resource-monitor`;
   - `debug dataplane pool statistics`;
   - `show counter global filter delta yes`.
6. The PBP table is structured without losing rows or directions: session or
   source-IP type, zone, rank, samples, percentage, `Drop State`, packets, and
   time until discard. Both output forms are accepted: the pipe-delimited CLI
   table and the structured XML `<entry>` form returned by the API on current
   PAN-OS releases, whose fields map one for one onto the same columns. `ingress-backlogs` separately preserves slot/DP,
   ATOMIC/TOTAL, groups, counts, and flow details. `show session info` is parsed
   per dataplane and summed device-wide into `session_info`: sessions supported
   and allocated, the protocol mix, the sessions created since bootup, the new
   connection rate, the packet rate, and the throughput. Its utilization is
   derived from allocated over supported, because PAN-OS returns no utilization
   field through the API and truncates it to a whole percent in the CLI. No
   parsed view ever replaces the raw output kept in the JSONL.
7. Entities are ranked by RED evidence, contribution, and corroboration. The
   collector immediately calls `show session id <id>` for priority sessions,
   including an ID explicitly supplied by the trigger, with bounded concurrency,
   fair selection, and retry delays. Repeated snapshots derive c2s, s2c, and
   total bit rates while detecting reset counters and reused session IDs. A
   source IP alone remains valid attribution evidence but does not cause a
   session command.
8. The complete cycle, raw XML API responses, and partial errors are written to
   a JSONL file. The ingress interfaces the evidence itself names (THREAT
   trigger fields, enriched sessions) additionally get hardware counter
   snapshots, bounded to two interfaces and sampled on the first batch then
   every third batch; only a pattern-validated interface name reaches the
   command.
9. The monitor stops after N consecutive complete measurements below the
   recovery threshold, after the configurable time-to-live since the last
   matching alert, or after the maximum duration. A new trigger resets the
   recovery sequence and the alert inactivity timer. At stop (except on
   service shutdown), the collector recovers flow detail for the top ranked
   source IPs, bounded to 3 sources: first their live sessions (a filtered
   count, then a listing capped at 20 entries, so a flood passing policy is
   enumerated without scanning the session table), then one bounded read-only
   traffic-log query per source (20 entries, fixed query template
   interpolating only a validated address) for traffic that never created a
   session — denied before setup or RED-blocked. Raw responses are preserved
   as evidence and a failed lookup never blocks the stop marker or the
   report.
10. After the stop marker is written, a standalone HTML report is generated in
   the background from the JSONL file.
11. Each completed batch also writes an atomic TXT view of its command and
    session outputs. A Web UI displays bounded Syslog reception status and
    read-only artifact links. The dashboard and every artifact route require
    the administrator session: incident evidence carries device serials,
    addresses, and raw command output, so it is protected by the same
    authentication as the configuration and fails closed. The admin area
    writes only to the separate configuration store.
12. The admin area renders the PAN-OS Syslog forwarding commands for the
    operator to review and run themselves, pre-filled with the address the
    administrator reached the page on, an editable Syslog port, and an editable
    log forwarding profile name. It is text generation only: the collector never
    writes to PAN-OS.
13. Saving a firewall in the admin area performs at most two outbound calls: an
    optional HTTPS key generation from temporary credentials, then one
    read-only `show system info`. The second call validates the API key and
    supplies the stored device serial, hostname, model, and PAN-OS version. Neither call changes firewall state, and
    a failure of either leaves the configuration unchanged.

## 7. Functional requirements

The numbered functional requirements are tracked as GitHub issues, which are the
living list: <https://github.com/tbortolossi/panos-pbp-monitoring/issues?q=label%3Arequirement>

Each requirement carries the `requirement` label; `implemented` marks those
delivered in a release. FR-01 to FR-51 were imported at public launch and cover
release v0.4.1. New requirements are opened there, not added to this document.

This section is kept as a stable anchor so existing issue links resolve. The
sections around it stay authoritative: section 6 defines the functional flow,
section 8 the non-functional requirements, section 9 the produced data, and
section 11 the acceptance criteria a release is validated against.

## 8. Non-functional requirements

- Python 3.10+. Runtime code uses the standard library plus `cryptography` for
  audited authenticated secret encryption; no custom cipher is permitted.
- Package application code under `src/pbp_monitoring/` and expose documented
  console entry points through `pyproject.toml`.
- TLS verification configured per firewall and disabled by default, with an
  explicit system-trust or internal-CA option recommended for production.
- Reject every redirect of an authenticated API request.
- Never expose secrets in diagnostic output.
- An API failure must not terminate the listener.
- Files must remain readable line by line after an abrupt shutdown.
- JSONL and HTML artifacts must be created with private permissions.
- HTML must use no JavaScript or network resource and must escape all data from
  the firewall.
- The Web UI must use no JavaScript or external resource, escape received data,
  reject path traversal, and publish HTTPS for remote management by default.
  Evidence is mounted read-only; only the separate configuration volume is
  writable by the admin process.
- Require TLS 1.2 or newer, mark the administrator session cookie Secure, and
  send HSTS. Never expose the generated private key in the UI,
  logs, support archives, or evidence volume.
- Initial administrator setup requires a one-time setup code printed in the
  webui container log. Failed sign-in and setup attempts are throttled per
  source address, and concurrent password verifications are capped.
- The service must run under an unprivileged Linux account.

## 9. Produced data

`syslog-triggers.jsonl` preserves trigger messages with their `run_id`. The same
trigger is copied into the incident as an event. Each incident creates
`incidents/<run_id>/incident.jsonl`, containing per cycle: timestamp, duration, metrics,
firewall clock, ranked candidate entities, PBP rows, ingress details, normalized
session snapshots and rates, dataplane pool headroom, global/flow/significant
counter views, parsing status, and raw XML command responses. A
`monitor_started` record preserves the identity returned by `show system info`
and the `dp_core_functions` core-to-function-group map with the
`dp_core_functions_source` field naming where that map came from, and a
`monitor_stopped` record gives the stop reason together with a run summary
(peak packet-buffer percentage and top ranked sources) that the dashboard
reads from its bounded tail read to compare runs. Multi-target mode roots
these files below `targets/<target-name>/` and adds `syslog-routing.jsonl` for
probe and routing evidence.

`incidents/<run_id>/report.html` is a derived view containing a summary, timeline,
offender ranking, denied and dropped traffic counters, the session table
evolution, per-dataplane CPU core charts, partial errors, and all
collapsible raw outputs. It contains
the JSONL SHA-256 digest; JSONL remains the source of truth. Validation mode
similarly produces `api-checks/<run_id>/api-check.jsonl` and
`api-checks/<run_id>/report.html`.

`incidents/<run_id>/raw/startup.txt` and `raw/batch-NNNN.txt` provide readable
command-by-command exports, including result, error, exact raw XML response, and
session lookups. The startup export also states the dataplane
core-to-function-group map and its source, which an incident reusing the stored
map does not carry as a command payload. `syslog-received.jsonl` is a compacted status journal for the
dashboard, not a replacement for incident evidence. A message from a host that
is not a declared Syslog source of any enabled firewall is journalled without
its payload: the timestamp, the transport peer, the observed source address, the
trigger flag and `target_names: []` are kept, the record is marked
`suppressed: "source_not_registered"`, and neither the message text nor the
metadata extracted from it is persisted. The reception stays visible so a new
firewall can be identified and registered, and the collector never stores the
content of a log nobody expected. The same rule applies to a message whose
device serial is not the one read from the firewall when it was saved, marked
`device_serial_not_registered`, and to a message carrying no serial at all while
a serial is registered for its source, marked `device_serial_missing`. Those
slugs are persisted and stable.
The Web UI streams a ZIP support export containing these run artifacts and a
versioned checksum manifest.

Stored runs are retained until an operator deletes them. The dashboard offers a
per-run deletion and a delete-all across every firewall, both requiring the
administrator session and its CSRF token. No automatic retention, age limit or
size cap exists. Because the Web service mounts the evidence volume read-only,
a deletion is queued in the configuration database and executed by the collector
on its periodic tick; a run still being collected or reported is skipped and the
request retried, and only `incidents/<run_id>/` is removed.

The separate configuration volume contains `config.db` and `master.key`.
The database contains settings, target metadata, a salted PBKDF2 admin-password
verifier, authenticated ciphertext for each API key, and the pending
incident-run deletions the collector has yet to carry out. Database and master
key must be backed up and restored together.

## 10. Security

- Dedicated least-privilege PAN-OS API account.
- Verified management certificates are strongly recommended for production.
- Persistent configuration volume readable only by the service account.
- Installation master key generated once at first startup, never during image
  build, and never stored in the database or image.
- Network ACL allowing Syslog only from authorized management IP addresses.
- The Docker deployment places syslog-ng in front of the local listener for
  TCP and UDP. Use an appropriately configured TLS-capable gateway when Syslog
  transport encryption is required.
- No automatic mitigation action in this version.
- Stored evidence is deleted only by an authenticated operator request, never
  automatically.
- Only a fixed XML allowlist is available; arbitrary `type=op` commands supplied
  by a user or log are never executed.

## 11. Acceptance criteria

1. A log without a PBP pattern triggers no collection.
2. Each of the four default messages from an allowlisted source starts a monitor.
3. Two closely spaced triggers create only one monitor.
4. Every cycle contains the six diagnostic results and the clock, or an explicit error
   for each call, with the raw response when available.
5. An ID found in output causes a `show session id` call.
6. An IPv4 address in the PBP table is not interpreted as an ID.
7. Numeric or textual GRP-ID values (`flow_slowpath`) and decimal percentages
   are recognized.
8. When candidates exceed the limit, a strongly contributing RED session is
   enriched before a numerically lower ID with no evidence, and retries do not
   starve new candidates.
9. A PBP row containing an IP is preserved as `source_ip` without an incorrect
   `show session id` call; `Bad Key` is presented as a disappeared or
   non-installed session.
10. Three complete measurements below the default threshold stop collection;
    an error or unrecognized format does not count as a low measurement.
11. The maximum duration stops an incident that never recovers.
12. `show system info` runs once per incident and `show clock` once per batch.
13. A firewall unchanged since its last check costs one API call per check
    interval, a firewall with an active incident is not checked at all, and a
    failed check is recorded and visible without interrupting Syslog reception.
14. Each dashboard firewall card states Syslog freshness, the outcome of the last
    read-only check, and whether a monitoring run is in progress on that
    firewall. The run state is derived from the run files already written; no
    additional firewall call is made to determine it.
    `show statistics` runs once per firewall at save time, is not called during
    an incident whose stored map still matches the running release, and is
    always called by `--check-api`.
15. The report charts each dataplane separately and states whether the load rose
    on every comparable core or on a few of them. Only cores carrying
    `flow_fastpath` are compared, because PAN-OS assigns some cores to
    management, control, or timer duties that make them permanently busier or
    quieter than their peers.
16. The HTML report escapes hostile output and does not modify the JSONL file.
17. Unit tests and Python compilation succeed.
18. The service starts without root privileges after documented installation.
19. A serial-labelled trigger routes only to its configured target.
20. The Syslog gateway preserves the original sender address for source routing.
21. Concurrent triggers from one shared allowlisted source cause one parallel probe,
    then reinforce the selected target incident.
22. An affected member discovered by probe is selected without polling a healthy
    member for the full incident; an ambiguous probe fans out without losing the
    trigger.
23. `--check-api` validates every configured target and returns failure if any
    target validation fails.
24. A matching trigger from an unlisted source, with no device serial, or with a
    serial inconsistent with that source's candidates, causes no API call,
    starts no monitor, and is journalled without its payload.
25. Two valid snapshots of one candidate session produce c2s, s2c, and total
    throughput; a counter decrease or changed start time produces no false rate.
26. The global-counter primer is preserved separately and the first recorded
    cycle identifies whether its delta interval was successfully primed.
27. Every startup and batch can be opened as a standalone TXT file containing
    its command results, raw responses, errors, and session details.
28. Both ordinary and triggering Syslog datagrams update the bounded reception
    journal without causing ordinary messages to start a monitor.
29. The Web UI reports fresh/stale Syslog state, recent runs, and only serves
    artifacts contained below a validated incident directory.
30. Every timeline column remains reachable on a narrower display.
31. The stack starts in setup mode without `.env` or `targets.json`, and the
    collector begins routing after an administrator adds an enabled target.
32. Plaintext API keys and admin passwords do not occur in SQLite, logs, HTML,
    or exception messages.
33. Global reception may be green while a configured firewall with no recent
    attributable log is independently red.
34. The first authenticated administrator can retrieve the installation
    recovery key and acknowledge its secure backup; subsequent pages no longer
    render the key.
35. A support ZIP contains the complete run and a manifest with application
    version, sizes, valid SHA-256 hashes, run triggers, and retained Syslog
    messages attributed to that target during the run.
36. TLS verification can differ between two firewalls and defaults to disabled
    for a newly created firewall.
37. An eight-character administrator password is accepted and a shorter one is
    rejected.
38. A default installation requires no `.env`, publishes remote HTTPS, creates
    one persistent matching self-signed certificate/key pair, and permits remote
    initial administrator setup. Requested IP/DNS SANs survive rebuilds.
39. An authenticated password change requires the current password, accepts a
    new password of at least eight characters, and invalidates all sessions.
40. `http://<host>/path` returns a permanent redirect to
    `https://<host>:8088/path`; malformed Host headers are rejected and the HTTP
    listener exposes no dashboard or administrative content.
41. Saving a firewall stores the serial, hostname, model, and PAN-OS version
    returned by `show system info`, and its single IP as both API endpoint and
    allowed Syslog source. A name left blank takes the PAN-OS hostname, and a
    later save without a refreshed identity keeps the stored one. A rejected key,
    an unreachable address, or a missing serial reports an error and writes
    nothing. Additional Syslog sources imported from a legacy configuration are
    preserved across an edit.
42. The report aggregates the `drop` severity global counters over the capture,
    groups them by counter aspect and name prefix, and excludes a batch whose
    delta baseline was untrusted from the totals. When packets were denied
    before session setup and a source IP was ranked without an enriched
    session, the report states that the pressure is consistent with traffic
    denied by policy, DoS protection, or zone protection, which creates no
    session to collect.
43. Every batch records the session table view returned by `show session info`,
    and the report shows its evolution: allocated sessions, derived utilization,
    protocol mix, new connection rate, packet rate, throughput, and the sessions
    created between two batches. A packet rate that multiplies while the session
    count stays flat is reported as traffic that created no session, and a table
    above 80% of its capacity is reported as a constraint of its own.

44. The configuration page renders the PAN-OS `set` block that forwards System
    logs and PBP Threat IDs 8507-8509 to this collector, with the collector
    address defaulted to the address the page was reached on and the log
    forwarding profile name replaceable, so an existing profile is extended
    instead of replaced. An unusable address, port, or profile name falls back
    to its default and is reported rather than rendered into a command. The same
    block downloads as plain text from an authenticated session only.
45. The report opens with a probable-cause block composing the peak buffer
    usage, the strongest offender with its flow, the denied-traffic
    correlation, and the session-table verdict. Ranked sessions are rolled up
    by source address in a top-sources table, and a pressure chart plots
    packet-buffer, descriptor, and session-table utilization per batch.

46. When a webhook URL is configured in the settings, the collector POSTs a
    JSON notification at incident start (run, firewall, trigger metadata) and
    at incident stop (stop reason, batches, top ranked sources, report path).
    The call is best effort with a bounded timeout; a failing endpoint is
    logged and never delays or blocks collection. An empty URL disables the
    feature, and a non-HTTP(S) value is rejected at save time.

47. The report is readable at a glance: it opens with a severity classified
    from the peak packet-buffer pressure against the PAN-OS PBP defaults (low
    below 50%, elevated from 50%, critical from 80%) and the key figures,
    shows formatted times, the duration, and the stop reason in words, links
    every section from a navigation bar, explains under each heading which
    question the section answers, colours peak cards and timeline cells by
    the same thresholds, distinguishes "Not collected" from zero and hides
    never-returned metrics from the timeline, fits the pressure chart's axis
    to the data with the PBP levels and each received trigger marked, and
    folds the per-core CPU tables away when no core approached saturation.
    None of this changes the JSONL, the commands, or the CSP: the report stays
    a single static file with no script.

48. A signed-in operator can delete stored incident runs from the dashboard,
    one run at a time or all of them at once, and nothing else deletes them:
    there is no retention window, age limit, or size cap. Because the Web
    service mounts the evidence volume read-only, the request is queued in the
    configuration database and executed by the collector on its periodic tick.
    A run being collected or reported is skipped and retried, and offers no
    button while it is active. Only `incidents/<run_id>/` is removed; the
    `api-checks/` artifacts and the trigger and reception journals are kept.
    Requested names are validated on both sides, so no request can reach a path
    outside `targets/<firewall>/incidents/`, and each removal is logged.

## 12. Possible enhancements

- Native TCP/TLS Syslog reception.
- Prometheus export and Grafana correlation.
- Slack or email notification with an incident summary.
- PAN-OS-family-specific XML parsers after collecting real samples.
- Feature-probed extended diagnostic profile: PBP `buffer-latency`, initial and
  final PBP counters, and occasional `pow performance`. It remains disabled
  until the operational XML is validated with `debug cli on` on the target
  release.
