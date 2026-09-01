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
   first diagnostic batch, together with one read of the PBP settings of the
   running configuration (`show config running xpath
   devices/entry/deviceconfig/setting/session`): enable flag, alert and
   activate percentages, latency alert, activate, max-tolerate and block
   countdown. No operational command exposes those thresholds, so this is the
   collector's single, declared exception to the operational-command rule; it
   reads and never writes, and a value left at its default is absent from the
   answer and read as the PAN-OS default. The dataplane core-to-function-group map returned by
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
   - `show counter global filter delta yes`;
   - `show session all filter min-kb <threshold> min-age <seconds>`, unless the
     volume threshold is set to `0`;
   - `show session packet-buffer-protection buffer-latency`, the dataplane
     processing latency in milliseconds per dataplane (latest, last ten
     seconds average and maximum), which latency-based PBP acts on.
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
7bis. Every batch also lists the largest, longest-lived sessions. The
   `min-kb` and `min-age` filters are what keep the query affordable: they are
   applied by the firewall, so the management plane returns a short list
   instead of the session table. Each returned session already carries its
   index, start time, cumulative byte counter, state, application, zones, and
   ingress and egress interfaces, so no per-session follow-up call is made. The
   collector keeps the largest ones, measures each session's age against the
   firewall clock collected in the same batch, and derives its current
   throughput from the delta of the cumulative counter between two batches. A
   session index PAN-OS recycled is detected by its start time and never
   inherits the volume of its predecessor.
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
   session — denied before setup or RED-blocked. One further bounded
   threat-log query (50 entries) captures the PBP threat logs 8507, 8508 and
   8509 of the incident window, expressed on the firewall clock read in the
   first batch with a one-minute margin, so the firewall's own designations
   are in the capture even when its threat log is not forwarded to the
   collector. Raw responses are preserved as evidence and a failed lookup
   never blocks the stop marker or the report.
10. After the stop marker is written, two standalone HTML reports are
   generated in the background from the same JSONL file: the layered
   `report-v2.html` (FR 59) and the flat `report.html`. Their offender ranking
   and top-sources tables are bounded to 50 rows each and state what was left
   out, and every section can be folded from its heading without script. The
   flat report opens with the investigation itself (FR 56). One renderer
   failing never prevents the other from writing its file.
11. Each completed batch also writes an atomic TXT view of its command and
    session outputs. A Web UI displays bounded Syslog reception status and
    read-only artifact links. A report served by the Web UI is shown with an
    evidence bar offering the same run artifacts as the dashboard row, each
    named by its format and its weight, plus the report itself as a standalone
    HTML download named for its run; the bar
    is added when the page is served, so the stored file stays standalone and a
    copy sent outside the deployment carries neither dead links nor an offer to
    download a bundle that names the network. The dashboard and every artifact route require
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
  webui container log, and that code is what opens the first session. Failed sign-in and setup attempts are throttled per
  source address, and concurrent password verifications are capped.
- Persisted process logs and support bundles are subject to the same rule as
  evidence: no API key, administrator password material, recovery key or
  one-time setup code may appear in them.
- The service must run under an unprivileged Linux account.

## 9. Produced data

`syslog-triggers.jsonl` preserves trigger messages with their `run_id`. The same
trigger is copied into the incident as an event. Each incident creates
`incidents/<run_id>/incident.jsonl`, containing per cycle: timestamp, duration, metrics,
firewall clock, ranked candidate entities, PBP rows, ingress details, normalized
session snapshots and rates, dataplane pool headroom, global/flow/significant
counter views, parsing status, and raw XML command responses. A
`monitor_started` record preserves the identity returned by `show system info`,
the `pbp_settings` read from the running configuration, and the
`dp_core_functions` core-to-function-group map with the
`dp_core_functions_source` field naming where that map came from; each cycle
carries its `buffer_latency` report; a `pbp_threat_logs` event carries the
PBP threat logs captured at stop with the query and its window; and a
`monitor_stopped` record gives the stop reason together with a run summary
(peak packet-buffer percentage and top ranked sources) that the dashboard
reads from its bounded tail read to compare runs. Multi-target mode roots
these files below `targets/<target-name>/` and adds `syslog-routing.jsonl` for
probe and routing evidence.

`incidents/<run_id>/report.html` and `incidents/<run_id>/report-v2.html` are
two derived views of the same records, containing a summary, timeline,
offender ranking, denied and dropped traffic counters, the session table
evolution, per-dataplane CPU core charts, partial errors, and all
collapsible raw outputs. Both contain
the JSONL SHA-256 digest; JSONL remains the source of truth. Neither travels in
a support archive, since both regenerate from the capture the archive carries.
Validation mode similarly produces `api-checks/<run_id>/api-check.jsonl` and
the same two reports.

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
versioned checksum manifest. The export also carries the deployment context a
remote diagnosis needs: the Syslog messages of the run window including the ones
the collector refused, an environment fingerprint (application, Python and
`cryptography` versions, platform, timezone), and the collector settings and
firewall inventory with every credential removed. Read-only API validation runs
under `api-checks/<run_id>/` export identically, so a credential, TLS or
unsupported-command problem is diagnosable even when no incident was collected.

The collector and the Web UI each keep a rotating process log inside a volume,
capped in size and generations, relocatable with `PBP_LOG_DIR`. The one-time
administrator setup code is excluded from those files by construction.

An authenticated **support bundle**, downloadable from the admin page or with
`pbp-support` from a shell, packages the deployment rather than one run: the
process logs, the environment fingerprint, the redacted settings and firewall
inventory, the run inventory, the capture-volume usage, the tail of the Syslog
reception, routing and trigger journals including refused messages with a
summary by outcome, firewall and sender, the most recent read-only API
validation of each firewall with its raw PAN-OS XML, the most recent incident
runs of each firewall (capture and raw XML, without the HTML report) newest
first under a per-firewall count and a global size budget, and a description of
the web certificate actually served. It carries a checksum manifest, makes no
call to any firewall, and must never contain a PAN-OS API key, the
administrator password or its verifier, the installation recovery key, or the
setup code. It does contain management addresses, hostnames, serials and
offender source addresses; the documentation states so where the action is
offered.

A host-side script, `pbp-support.sh`, gathers what the container cannot see —
service state and restart counts, the effective Compose configuration and
published ports, the container output including the Syslog gateway, the image
digest, the Docker and host versions — and streams it into `pbp-support
--host-evidence` so it lands under `host/` in the same archive, bounded in count
and size, scrubbed of credential-shaped values and anonymized with the rest.
The script runs read-only commands only, falls back to a one-off container when
the collector is not running, and to a host-only archive when the image is
absent.

Every support export, bundle and run archive alike, is also offered in an
anonymized form. Addresses, MAC addresses, serial numbers and firewall names are
replaced by tokens in the contents, the archive paths and the manifest, which
records which form it describes. Tokens derive from a salt generated once per
installation and held in the configuration volume, so a value keeps one token
within an export and across successive exports, and the recipient cannot invert
it. Loopback and unspecified addresses, and a name equal to the platform model,
are left readable because tokenizing them would remove diagnostic value without
concealing anyone. The token mapping is available to the operator alone and is
never placed inside an archive.

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
    firewall. Each of the three signals carries its own coloured dot: green when
    it is nominal, amber for a check that is queued, never run, or overdue by
    more than twice its interval, red for stale Syslog reception, a failed check,
    or a run in progress. The card's general dot is red when Syslog or the API
    signal is red, amber while a run is in progress, and green otherwise. The run
    state is derived from the run files already written; no additional firewall
    call is made to determine it. Reception is reported by these cards only. A
    single global reception card replaces them while no firewall is registered,
    so a fresh installation still sees whether messages arrive.
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
34. The first administrator can retrieve the installation recovery key and
    acknowledge its secure backup on the page that follows setup; subsequent
    pages no longer render the key.
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
    delta baseline was untrusted from the totals. Packet buffer protection's
    own RED drops (`flow_dos_pbp_*`) form their own family, reported but never
    added to the denied total. When packets were denied
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
    None of this changes the JSONL or the commands. The report stays a single
    static file whose only active content is its own Collapse all control: one
    inline script, pinned by SHA-256 in the report's own Content-Security-Policy
    and in the policy the Web UI serves it with, that folds every section except
    Diagnosis and reopens them. It builds its own button, so a report whose
    script is stripped or blocked shows the page unchanged rather than a dead
    control, and it reads nothing, stores nothing, and sends nothing.

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

49. Every batch lists the sessions above a cumulative-volume and a minimum-age
    threshold, and the report ranks them with their age, their cumulative
    volume, their average rate since the session started, and the fastest rate
    measured between two batches. This is the only evidence path for a single
    high-volume transfer: while such a session is open PAN-OS writes no traffic
    log, an offloaded session shows little on the management plane, and the
    session is never named as a PBP offender, so the offender ranking cannot
    see it. Both thresholds are operator settings; the volume threshold accepts
    `0` to switch the query off entirely, and any other value must stay above
    the floor that keeps the session-table walk bounded on a loaded firewall.
    A capture taken before this feature renders as such rather than as an empty
    table.
50. A deployment can be diagnosed remotely from artifacts alone. The support
    bundle carries the collector and dashboard process logs, the versions
    actually running, every setting, the firewall and run inventories, the
    Syslog journals including refused messages and their summary, the latest
    read-only API validation with its raw XML, the most recent incident runs
    with their raw XML under a size budget, and the facts of the served web
    certificate; it carries no credential of any kind, and building it issues
    no firewall command. Read-only API validation runs export as a run archive
    like incidents do, and every run archive states the environment and the
    redacted configuration it was produced under. `pbp-support.sh` adds the
    Docker layer from the host — service state, published ports, gateway
    output, image digest — into the same archive, so a deployment whose Syslog
    never reaches the collector is diagnosable without walking the operator
    through Docker commands.
51. An operator whose policy forbids disclosing addresses can still obtain a
    diagnosable export. The anonymized bundle and the anonymized run archive
    carry the same evidence with every address, MAC address, serial and
    firewall name replaced by a token that is stable within the export and
    across successive exports, irreversible without the installation's salt,
    and translatable by the operator through a mapping no archive contains.
52. The raw XML preserved in any capture can be replayed through the shipped
    parsers offline, reporting which command a parser fails on, so a customer
    archive becomes a fixture and a regression test without access to the
    firewall it came from.
53. The dashboard's received-log table names the firewall each message is
    attributed to and can be filtered to one declared firewall, or to the
    messages no firewall claims, so a refused sender is diagnosed without
    reading past the ordinary traffic of the other firewalls. The filter is
    carried by the URL, so it survives the page refresh, and it never applies
    to the per-firewall cards.
54. A completed run's dashboard row opens that run's layered report wherever it
    is clicked, falling back to the flat one when only that exists, its
    **Delete** cell keeping its own action, and the report's
    evidence bar carries a button back to the dashboard and offers both
    reports as **HTML v2** and **HTML v1** downloads — the stored files, free
    of the bar, so they open outside the deployment. The run table lists no
    export of its own: the report page is the single place where a run's
    evidence is chosen. A run with no report to open — an active monitor, or a
    run whose report could not be produced — keeps a plain row and offers the
    records collected so far as a **JSONL** link under its status. Both are
    plain HTML and CSS: the Web UI serves `script-src 'none'`.
55. An unauthenticated request lands on the authentication page. A successful
    sign-in opens the dashboard once the installation is complete, and the
    configuration page while the recovery key is unacknowledged or no firewall
    is declared. Creating the administrator with the one-time setup code opens
    the session directly, so the first run continues into the recovery key and
    the first firewall without a second authentication.

56. The report is organised as the PBP investigation rather than by data
    source. It opens with a Diagnosis block of four steps, each answered from
    the capture and each stating what it found or that it found nothing:
    (1) the pressure level and the exhausted resource, judged against the
    PAN-OS levels (buffers exhausted from 80%, descriptors exhausted from 80%
    with low buffers, elevated from 50%, low below) and read together with the
    alert threshold the firewall printed in its own congestion log and the
    lowest utilization at which PBP was seen mitigating, with the hardware
    family derived from the model so an x86 platform's missing on-chip
    descriptor pool is stated rather than shown as not collected; (2) the
    entries PBP marked for RED, sessions with their flow from `show session
    id` and source addresses with their recovered traffic log, presented as
    the firewall's designation and not as proof; (3) the sessions holding at
    least 2% of the ingress backlog, calling out unidentified applications and
    the `flow_slowpath` + `Bad Key` policy-deny signature; (4) five wider
    hypotheses — elephant session, burst of denied sessions, storm of new
    sessions, interface errors, aggregate load — each with its own verdict. At
    low pressure the later steps are read as the ordinary traffic mix and
    nothing is blamed; when the pressure is real and no step names a cause, the
    conclusion points at the software-defect scenario and a Tech Support File.
    The conclusion is composed only from the steps reached, the evidence
    sections follow the same order, and the summary cards, timeline, batch
    details and events become folded appendices. Collection, the JSONL, the
    commands and the exports do not change.

57. Three pieces of evidence the firewall gives read-only reach the capture and
    the diagnosis. The PBP settings of the running configuration are read once
    per incident and once per API check (the collector's only configuration
    read, declared in the flow), so step 1 judges the pressure against the
    alert and activate thresholds the firewall actually runs with and states
    them; the syslog text and the PAN-OS defaults remain the fallbacks. The
    buffer latency is collected every batch and read against the latency
    thresholds: latency at or above the activate threshold with low buffers is
    the latency case, stated differently for a firewall running latency-based
    PBP and for one running buffer-based PBP that does not see it; a disabled
    measurement is stated. The PBP settings are read a second time at stop and
    the record says whether they moved: a monitor started while a commit is
    landing reads the old configuration while the dataplane already applies
    the new thresholds, so the read at stop wins when it differs, and when PBP
    was seen mitigating below the activate threshold read, the diagnosis
    states that the read was taken during a commit and does not quote it as
    the threshold in force. The PBP threat logs of the incident window are
    queried once at stop and feed step 2: they confirm the entries marked for
    RED, name the sources placed in the block table (8509) and the sessions
    discarded (8508), and designate on their own when no batch caught a RED
    entry, always presented as the firewall's own list and not as proof; a
    failed query is stated. Every new command is replayable and exported with
    the capture.

58. The report is two-part: the Diagnosis is the only section open by
    default, and every evidence section starts folded under a visible
    "Going further" heading, its one-line verdict readable on the folded
    summary, with the appendix (summary cards, timeline, batch details,
    events) under its own heading. The step numbering appears only in the
    diagnosis; the evidence sections carry plain names. The report's single
    hash-pinned script additionally opens the section a followed hash link
    targets, so the diagnosis evidence links and the navigation land on an
    open section; without the script the sections open by hand and nothing
    else changes. Expand all remains the way to unfold everything, including
    before printing.

59. Each run also produces a layered report, `report-v2.html`, from the same
    records and the same diagnosis as the flat one, so the two can never
    disagree on a fact. It is read in three layers. Layer 1 is the verdict:
    the headline, the peak packet-buffer and packet-descriptor levels, the
    buffer latency and the level PBP mitigated from when collected, the batch
    count, and the case chips; it stays open and Collapse all never folds it.
    Layer 2 states only the causes the capture supports, ranked, each naming
    its entities and linking to the section that proves it, with the rejected
    causes folded behind one "N other causes ruled out" line, the
    non-evaluable ones behind "N causes not evaluable", and the four-step walk
    and the conclusion paragraph folded under their own names; when nothing is
    supported the layer says so and points at the ruled-out list. Layer 3
    carries the evidence sections and the raw appendix, folded. The layered
    report is self-sufficient for a TAC case: same raw command responses, same
    capture digest, same identity block. Its Collapse all reaches the sections
    and the layer-2 blocks and stops there, never opening every raw command
    response. It is served under its own hash-pinned script, allowed alongside
    the flat report's in the Web UI Content-Security-Policy and nothing else.

## 12. Possible enhancements

- Native TCP/TLS Syslog reception.
- Prometheus export and Grafana correlation.
- Slack or email notification with an incident summary.
- PAN-OS-family-specific XML parsers after collecting real samples.
- Feature-probed extended diagnostic profile: PBP `buffer-latency`, initial and
  final PBP counters, and occasional `pow performance`. It remains disabled
  until the operational XML is validated with `debug cli on` on the target
  release.
