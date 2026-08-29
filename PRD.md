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
- Configure collector behavior, monitored firewalls, API credentials, and
  allowed Syslog sources through an authenticated HTTPS admin page reachable
  remotely on a protected management network.
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
   sequence number, and explicitly labeled fields are correlated with the
   incident `run_id`. In multi-target mode, source IP first defines the allowed
   candidate set and device serial may select within it. A source shared by
   several targets is probed read-only across those candidates and ambiguous
   results safely fan out only within that allowlist.
3. At startup, the monitor runs `show system info` once without delaying the
   first diagnostic batch.
4. At incident startup, the monitor primes the global-counter delta baseline
   separately. At the start of each batch, it starts `show clock`, then collects
   the following commands in parallel every five seconds without waiting for
   the clock request to time out:
   - `show session packet-buffer-protection`;
   - `show running resource-monitor ingress-backlogs`;
   - `show running resource-monitor`;
   - `debug dataplane pool statistics`;
   - `show counter global filter delta yes`.
5. The PBP table is structured without losing rows or directions: session or
   source-IP type, zone, rank, samples, percentage, `Drop State`, packets, and
   time until discard. `ingress-backlogs` separately preserves slot/DP,
   ATOMIC/TOTAL, groups, counts, and flow details.
6. Entities are ranked by RED evidence, contribution, and corroboration. The
   collector immediately calls `show session id <id>` for priority sessions,
   including an ID explicitly supplied by the trigger, with bounded concurrency,
   fair selection, and retry delays. Repeated snapshots derive c2s, s2c, and
   total bit rates while detecting reset counters and reused session IDs. A
   source IP alone remains valid attribution evidence but does not cause a
   session command.
7. The complete cycle, raw XML API responses, and partial errors are written to
   a JSONL file.
8. The monitor stops after N consecutive complete measurements below the
   recovery threshold, after the configurable time-to-live since the last
   matching alert, or after the maximum duration. A new trigger resets the
   recovery sequence and the alert inactivity timer.
9. After the stop marker is written, a standalone HTML report is generated in
   the background from the JSONL file.
10. Each completed batch also writes an atomic TXT view of its command and
    session outputs. A Web UI displays bounded Syslog reception status and
    read-only artifact links; its authenticated admin area writes only to the
    separate configuration store.

## 7. Functional requirements

- **FR-01** — Listen on a configurable, unprivileged UDP Syslog port.
- **FR-02** — Match the four fixed PBP trigger signatures case-insensitively.
- **FR-03** — Query operational commands through XML API `type=op`.
- **FR-04** — Send the key in the `X-PAN-KEY` header.
- **FR-05** — Support per-target `target_serial` for Panorama.
- **FR-06** — Preserve every raw output, including partial errors.
- **FR-07** — Extract IDs without mistaking an IPv4 address for an ID.
- **FR-08** — Enrich no more than the configured number of sessions per cycle.
- **FR-09** — Prevent concurrent monitors.
- **FR-10** — Enforce a mandatory maximum duration.
- **FR-11** — Create a separate Syslog trigger journal.
- **FR-12** — Shut down cleanly on SIGINT and SIGTERM.
- **FR-13** — Capture `show system info` once at incident startup.
- **FR-14** — Start `show clock` before the diagnostics in every batch.
- **FR-15** — Count a recovery measurement only when the required packet-buffer
  and packet-descriptor metrics were extracted.
- **FR-16** — Generate a standalone HTML report that can be rebuilt from JSONL.
- **FR-17** — Provide a single-batch API validation mode without a Syslog
  trigger, restricted to the read-only command allowlist.
- **FR-18** — Correlate each trigger with the `run_id` and preserve its order,
  reinforcement status, and explicitly labeled metadata.
- **FR-19** — Rank session/IP candidates using PAN-OS evidence and prioritize
  new offenders ahead of retries within the batch limit.
- **FR-20** — Normalize the 5-tuple, zones, application, rule, state, interfaces,
  and available counters from `show session id` while preserving the complete
  raw response.
- **FR-21** — Persist every incident in its own directory with its JSONL source
  and derived HTML report.
- **FR-22** — Provide a Docker Compose deployment accepting Syslog over TCP and
  UDP on port 514 through a non-privileged Syslog gateway.
- **FR-23** — Stop an active monitor after a configurable period without a
  matching alert, while retaining a separate absolute maximum duration.
- **FR-24** — Preserve and normalize dataplane pool availability, including
  packet-buffer used/free percentages and the low-free limit state.
- **FR-25** — Preserve global counter deltas and normalize flow-category rows.
- **FR-26** — Load a private, gitignored target inventory for standalone and
  multi-firewall modes. A target IP may derive both its HTTPS API URL and
  allowed Syslog source; explicit URL/source overrides and named environment
  variables remain available for advanced topologies.
- **FR-27** — Preserve the original sender through the Syslog gateway and route
  by device serial before Syslog source IP.
- **FR-28** — Probe unresolved targets concurrently without duplicating probes
  for concurrent triggers from the same unresolved sender.
- **FR-29** — Maintain independent incident state, deduplication, TTL, recovery,
  evidence directories, and reports for every selected target.
- **FR-30** — Route a one-entry standalone inventory directly without an
  unnecessary discovery probe.
- **FR-31** — Require every target to resolve at least one normalized Syslog
  source IP, derived from `ip` or declared explicitly, and reject unmatched
  sources or serial/source identity conflicts before any API collection starts.
- **FR-32** — Re-sample only bounded PBP/ingress candidate sessions and derive
  directional and total throughput from cumulative byte-counter deltas.
- **FR-33** — Prime the global-counter baseline before the first recorded delta,
  preserve that raw baseline, and expose warn/error/drop rows separately without
  discarding informational raw evidence.
- **FR-34** — Write private `startup.txt` and `batch-NNNN.txt` files beside each
  incident without replacing JSONL as the source of truth, and support rebuilding
  those files from an existing capture.
- **FR-35** — Maintain a bounded reception-status journal for matching and
  non-matching Syslog messages so transport freshness is observable.
- **FR-36** — Provide a Web service with a health endpoint, the 20 latest
  received logs, recent run state, and read-only artifact links. It has no
  writable evidence access; credential access is restricted to authenticated
  configuration operations.
- **FR-37** — Keep wide timeline columns reachable through a bounded two-axis
  scrolling region with sticky headers and batch identifiers.
- **FR-38** — Persist runtime settings and the target inventory in SQLite so a
  normal Compose deployment requires neither `.env` nor `targets.json`.
- **FR-39** — Encrypt PAN-OS API keys with an authenticated installation-specific
  master key generated at first startup and persisted independently of images.
  Deliver that key to an authenticated administrator until explicit backup
  acknowledgement, then stop rendering it in the UI.
- **FR-40** — Protect remotely available Web administration with HTTPS, a salted
  password derivation, authenticated sessions, CSRF tokens, and management-network
  access controls. Permit remote initial password setup and authenticated password
  changes; a change invalidates existing administrator sessions.
- **FR-41** — Generate a PAN-OS API key from temporary credentials in the admin
  page without storing the username or password or putting either in the URL.
- **FR-42** — Show global Syslog freshness and independent freshness for every
  configured firewall. Unattributable logs may update only the global state.
- **FR-43** — Reload valid configuration revisions between incidents. A change
  received during a run must be deferred until that run completes.

- **FR-44** — Show extracted command results and non-empty errors immediately in
  HTML reports while keeping the exact raw API response in a nested disclosure
  collapsed by default.
- **FR-45** — Query a per-second resource-monitor window covering the configured
  poll interval plus a two-second margin, bounded to 60 seconds. Preserve every
  returned per-core average and maximum, summarize the overlapping windows over
  the run, and expose CPU imbalance as corroborating evidence rather than
  deterministic offender attribution.
- **FR-46** — Download a complete run as a compressed support archive containing
  its evidence, run-correlated trigger logs, retained target-attributed Syslog
  received during the run, and a versioned SHA-256 manifest without persisting
  a duplicate.
- **FR-47** — Offer an authenticated CSV download of the installation recovery
  key until backup acknowledgement, then stop serving it.
- **FR-48** — Store TLS verification independently for each firewall. New
  firewalls default to disabled verification; existing global values migrate to
  their current targets.
- **FR-49** — Identify the application version in the UI, captures, reports, and
  support archives.
- **FR-50** — Always serve the dashboard and administration over TLS. Use an
  explicit certificate/key pair when configured; otherwise create a persistent,
  installation-specific self-signed certificate with configurable DNS/IP subject
  alternative names without requiring `.env`.
- **FR-51** — Publish a separate HTTP listener that serves no application data
  and redirects every valid request to the same host on the configured public
  HTTPS port. Reject malformed Host headers instead of reflecting them.

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
- The service must run under an unprivileged Linux account.

## 9. Produced data

`syslog-triggers.jsonl` preserves trigger messages with their `run_id`. The same
trigger is copied into the incident as an event. Each incident creates
`incidents/<run_id>/incident.jsonl`, containing per cycle: timestamp, duration, metrics,
firewall clock, ranked candidate entities, PBP rows, ingress details, normalized
session snapshots and rates, dataplane pool headroom, global/flow/significant
counter views, parsing status, and raw XML command responses. A
`monitor_started` record preserves the identity returned by `show system info`,
and a `monitor_stopped` record gives the stop reason. Multi-target mode roots
these files below `targets/<target-name>/` and adds `syslog-routing.jsonl` for
probe and routing evidence.

`incidents/<run_id>/report.html` is a derived view containing a summary, timeline,
offender ranking, partial errors, and all collapsible raw outputs. It contains
the JSONL SHA-256 digest; JSONL remains the source of truth. Validation mode
similarly produces `api-checks/<run_id>/api-check.jsonl` and
`api-checks/<run_id>/report.html`.

`incidents/<run_id>/raw/startup.txt` and `raw/batch-NNNN.txt` provide readable
command-by-command exports, including result, error, exact raw XML response, and
session lookups. `syslog-received.jsonl` is a compacted status journal for the
dashboard, not a replacement for incident evidence.
The Web UI streams a ZIP support export containing these run artifacts and a
versioned checksum manifest.

The separate configuration volume contains `config.db` and `master.key`.
The database contains settings, target metadata, a salted PBKDF2 admin-password
verifier, and authenticated ciphertext for each API key. Database and master
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
- Only a fixed XML allowlist is available; arbitrary `type=op` commands supplied
  by a user or log are never executed.

## 11. Acceptance criteria

1. A log without a PBP pattern triggers no collection.
2. Each of the four default messages from an allowlisted source starts a monitor.
3. Two closely spaced triggers create only one monitor.
4. Every cycle contains the five diagnostic results and the clock, or an explicit error
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
12. `show system info` runs once and `show clock` once per batch.
13. The HTML report escapes hostile output and does not modify the JSONL file.
14. Unit tests and Python compilation succeed.
15. The service starts without root privileges after documented installation.
16. A serial-labelled trigger routes only to its configured target.
17. The Syslog gateway preserves the original sender address for source routing.
18. Concurrent triggers from one shared allowlisted source cause one parallel probe,
    then reinforce the selected target incident.
19. An affected member discovered by probe is selected without polling a healthy
    member for the full incident; an ambiguous probe fans out without losing the
    trigger.
20. `--check-api` validates every configured target and returns failure if any
    target validation fails.
21. A matching trigger from an unlisted source, or with a serial inconsistent
    with that source's candidates, causes no API call and starts no monitor.
22. Two valid snapshots of one candidate session produce c2s, s2c, and total
    throughput; a counter decrease or changed start time produces no false rate.
23. The global-counter primer is preserved separately and the first recorded
    cycle identifies whether its delta interval was successfully primed.
24. Every startup and batch can be opened as a standalone TXT file containing
    its command results, raw responses, errors, and session details.
25. Both ordinary and triggering Syslog datagrams update the bounded reception
    journal without causing ordinary messages to start a monitor.
26. The Web UI reports fresh/stale Syslog state, recent runs, and only serves
    artifacts contained below a validated incident directory.
27. Every timeline column remains reachable on a narrower display.
28. The stack starts in setup mode without `.env` or `targets.json`, and the
    collector begins routing after an administrator adds an enabled target.
29. Plaintext API keys and admin passwords do not occur in SQLite, logs, HTML,
    or exception messages.
30. Global reception may be green while a configured firewall with no recent
    attributable log is independently red.
31. The first authenticated administrator can retrieve the installation
    recovery key and acknowledge its secure backup; subsequent pages no longer
    render the key.
32. A support ZIP contains the complete run and a manifest with application
    version, sizes, valid SHA-256 hashes, run triggers, and retained Syslog
    messages attributed to that target during the run.
33. TLS verification can differ between two firewalls and defaults to disabled
    for a newly created firewall.
34. An eight-character administrator password is accepted and a shorter one is
    rejected.
35. A default installation requires no `.env`, publishes remote HTTPS, creates
    one persistent matching self-signed certificate/key pair, and permits remote
    initial administrator setup. Requested IP/DNS SANs survive rebuilds.
36. An authenticated password change requires the current password, accepts a
    new password of at least eight characters, and invalidates all sessions.
37. `http://<host>/path` returns a permanent redirect to
    `https://<host>:8088/path`; malformed Host headers are rejected and the HTTP
    listener exposes no dashboard or administrative content.

## 12. Possible enhancements

- HTTP webhook endpoint in addition to Syslog.
- Native TCP/TLS Syslog reception.
- Prometheus export and Grafana correlation.
- Slack or email notification with an incident summary.
- PAN-OS-family-specific XML parsers after collecting real samples.
- Feature-probed extended diagnostic profile: PBP `buffer-latency`, initial and
  final PBP counters, and occasional `pow performance`. It remains disabled
  until the operational XML is validated with `debug cli on` on the target
  release.
