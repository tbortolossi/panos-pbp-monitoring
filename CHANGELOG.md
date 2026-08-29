# Changelog

All notable changes to this project are documented in this file. The project
follows [Semantic Versioning](https://semver.org/).

## [0.15.0] - Unreleased

### Added

- Zone-protection and DoS flood THREAT logs now corroborate an active
  incident: they extend the trigger-inactivity window, feed their extracted
  flow (source, destination, ingress interface) into the offender evidence,
  are copied into the capture as `flood_corroboration` events, and are
  mentioned with their targets in the report's probable-cause block. A flood
  log alone never starts a monitor and never delays the recovery decision.
  No congestion-cleared System message exists on the lab release, so nothing
  wrongly extends an incident.
- The ingress interfaces named by the evidence (THREAT trigger fields and
  enriched sessions) get bounded hardware counter snapshots
  (`show counter interface`, validated read-only on the lab PA-440): at most
  two interfaces, sampled on the first batch then every third batch, persisted
  per cycle as `interface_counters` with the raw responses. When session
  evidence is thin, input bytes and drops say where the flood enters.
- Top offender sources with live sessions are enumerated at monitor stop:
  one bounded filtered count then a capped listing per source (validated
  read-only on the lab PA-440) yields their destinations, ports, and
  applications without scanning the session table, and the report gains a
  "Live sessions of top sources" section.
- The dashboard's recent-runs table now compares incidents side by side:
  each completed run shows its peak packet-buffer percentage and its top
  ranked sources, read from a summary the stop marker now carries, so a
  recurring offender across days is visible without opening each report.
- Optional webhook notifications: a **Webhook URL** setting makes the
  collector POST a JSON payload when an incident opens (run, firewall,
  trigger metadata with the extracted flow) and when it closes (stop reason,
  batches, top ranked sources, report path). Best effort with a five-second
  timeout; a failing endpoint never delays collection. Empty disables it.
- The HTML report opens with a **Probable cause** block composing the
  verdicts that were previously scattered (peak buffer usage, strongest
  offender with its flow, denied-traffic correlation, session-table
  behavior) into a few sentences an engineer can paste into a TAC case.
- A **Top sources** rollup above the attribution table groups ranked
  sessions by their source address, so a scan or flood spread over many
  short sessions is attributed to the source that owns them (session count,
  RED state, max PBP contribution, aggregate peak rate, applications,
  zones, distinct destinations).
- A **Pressure over time** chart plots packet-buffer, descriptor, and
  session-table utilization per batch, so the operator can align an
  offender's first appearance with the pressure curve.
- Unenriched offender sources now get flow detail from the firewall's own
  traffic log. When a ranked source IP had no session to inspect (flood
  denied before session setup, RED-blocked source), the collector runs one
  bounded read-only log query per top source at monitor stop and the HTML
  report gains a "Traffic log evidence for unenriched sources" section with
  the recovered destinations, ports, rules, and actions. Raw responses are
  preserved in the capture as TAC evidence.
- The responsible flow is now extracted from the trigger itself. A PBP THREAT
  log (8507/8508/8509) positionally carries the source and destination
  address, ports, application, rule, zones, ingress interface, and session ID
  of the flow the firewall acted on; the collector reads those fixed CSV
  positions (each value validated individually) instead of relying on
  labelled forms PAN-OS never emits. The extracted session ID feeds immediate
  `show session id` enrichment and the source address feeds the offender
  ranking, so the source/destination/port/application answer is available
  from the first second of an incident.

### Security

- Initial administrator setup now requires a one-time setup code printed in
  the webui container log, so a freshly deployed collector cannot be claimed
  by whoever reaches the port first.
- Failed sign-in and setup attempts are throttled per source address (five
  failures per fifteen minutes), and concurrent password verifications are
  capped so a login flood cannot exhaust the CPU with key derivations.
- Monitoring-run starts are capped at 12 per firewall per rolling hour. UDP
  Syslog is unauthenticated and the device serial is public in every PAN-OS
  log, so a forged trigger stream could cycle collection runs indefinitely;
  excess triggers are journalled as `trigger_rate_limited` and reinforcements
  of an active run are never limited. The Syslog trust model is now documented
  in the README and SECURITY policy.
- The firewall form now warns that password-based key generation over an
  unverified TLS connection (the compatibility default) exposes the PAN-OS
  admin password to interception, and recommends the pre-generated-key method
  or enabling verification first.
- PAN-OS API responses are now read with an 8 MB ceiling and refused when they
  carry an XML document type declaration, closing memory-exhaustion paths from
  a misbehaving or intercepted endpoint (TLS verification defaults to disabled
  for appliance-certificate compatibility, which makes this boundary matter).
- The dashboard, HTML reports, JSONL captures, TXT exports, and support ZIP
  archives now require the administrator sign-in. Incident evidence carries
  device serials, addresses, session tuples, and raw command output; it was
  previously served to anyone who could reach the web port. Only `/healthz`
  stays open for the container health check. The admin session cookie scope
  widened from `/admin` to the whole site; an existing session may need one
  new sign-in after the upgrade.

### Fixed

- A shared Syslog source without a registered serial no longer probes every
  candidate firewall on each trigger during an active incident: the routing
  decision is remembered while a selected monitor is running, so a trigger
  storm reinforces the current incident instead of adding continuous probe
  load on firewalls already under buffer pressure. The routing journal is now
  bounded like the reception journal.
- Reception-journal compaction now trims by size as well as by record count.
  When the newest 200 stored messages alone exceeded the 4 MB cap, every
  subsequent datagram re-read, rewrote, and fsynced the whole journal on the
  event loop, degrading UDP reception exactly under load.
- Two monitoring runs starting within the same wall-clock second no longer
  merge into one capture: the run identifier gains a monotonic suffix when its
  evidence directory already exists, so every incident keeps its own
  unambiguous JSONL file and report.
- A journal write failure (full disk, permissions) no longer prevents incident
  collection: the monitor starts even when the trigger cannot be journalled,
  the HTML report is generated even when the stop marker cannot be written,
  and the datagram handler survives any trigger failure.
- A crash in the middle of a JSONL append now costs exactly the truncated
  record: the next append closes the torn line instead of corrupting the
  following record too.
- The global-counter primer task is cancelled when a monitor stops before its
  first cycle completes.
- The firewall check loop reloads the configuration before resolving
  connection profiles. A firewall saved after daemon startup is now checked
  without waiting for an unrelated Syslog datagram, and an edited firewall is
  checked at its new address with its new credentials instead of the stale
  in-memory profile.

## [0.14.1] - 2026-08-29

### Fixed

- A refused Syslog message no longer stands in for the firewall it claims to
  come from. Its journal record kept the `target_names` derived from the source
  address, so the dashboard counted it as a healthy reception: a stray or
  spoofed sender could keep a firewall's Syslog indicator green while that
  firewall had actually stopped forwarding. Suppressed records now carry an
  empty `target_names` and are excluded from per-firewall reception health.

## [0.14.0] - 2026-08-29

### Fixed

- The device serial is now actually extracted from PAN-OS Syslog. The parser
  only looked for a labelled `serial=` form, which PAN-OS never emits: it
  positions the serial in the third comma-separated field, anchored by the log
  type in the fourth. The serial check was therefore dead code on real traffic.
  The labelled form is kept as a fallback, and the positional field wins because
  it is structural rather than a string that can appear anywhere in a payload.

### Changed

- A Syslog message is stored, and can start a monitor, only when its source
  address is a declared Syslog source **and** its device serial is one of the
  serials read from that firewall when it was saved. A refused message is
  journalled as a bounded trace with no payload, marked
  `source_not_registered`, `device_serial_missing`, or
  `device_serial_not_registered`, and causes no API call and no incident. A
  spoofed or stray sender can therefore no longer make the collector write
  incident captures to the capture volume. A firewall saved without a serial on
  record keeps the previous source-only rule for its source, so an existing
  deployment does not silently stop collecting. Refs #87.

## [0.13.0] - 2026-08-29

### Changed

- The Syslog reception journal no longer stores the content of a message sent by
  a host that is not a declared Syslog source of any enabled firewall. Such a
  record keeps its timestamp, transport peer, observed source address, trigger
  flag and `target_names: []`, is marked `suppressed: "source_not_registered"`,
  and carries neither the message text nor the metadata extracted from it. The
  reception stays visible, so pointing a new firewall at the collector is still
  diagnosable from the journal and the dashboard, which renders those rows as
  *not stored: source is not a registered firewall*. A registered source, and a
  deployment configured with a single target from the environment, keep the full
  record unchanged. Routing is untouched: the allowlist rejection in the
  multi-target router still refuses to start a monitor for an undeclared source.
  Refs #84.

## [0.12.0] - 2026-08-29

### Added

- The configuration page gained a **PAN-OS Syslog forwarding** section that
  renders the `set` commands to run on the firewall, so a newly added firewall
  can be pointed at the collector without leaving the UI. The collector address
  is pre-filled from the address the administrator reached the page on, the
  Syslog port and the log forwarding profile name are editable, and the block
  downloads as plain text. The Threat match list restricted to PBP IDs
  8507-8509 is added to the profile you name, so a profile already applied to
  every security rule keeps its existing destinations, and the System match list
  carries both packet-buffer congestion alerts and ordinary System logs. An
  unusable address, port, or profile name falls back to its default and is
  reported instead of being rendered into a command. The page generates text
  only: the collector still never writes to PAN-OS. Refs #82.

## [0.11.0] - 2026-08-29

### Added

- Every batch now collects `show session info` and persists it under
  `session_info`, per dataplane and summed device-wide: sessions supported and
  allocated, the session table utilization, the protocol mix, the sessions
  created since bootup, the new connection rate, the packet rate, and the
  throughput. The report gained a **Session table** section showing that
  evolution batch by batch with its peaks. It answers, from the session table
  itself, whether the traffic that filled the buffers created sessions at all: a
  packet rate that multiplies while the session count stays flat is traffic
  denied before session setup, while a table above 80% of its capacity is a
  constraint of its own. The utilization is derived from allocated over
  supported because PAN-OS truncates it to a whole percent. Refs #77.

### Fixed

- The packet-buffer-protection offender table is now parsed in its structured
  XML form, not only as the pipe-delimited CLI table. Current PAN-OS releases
  return one `<entry>` per monitored session or blocked source IP through the
  API, so on those firewalls the collector was ranking no offender at all: the
  candidate session list stayed empty, no `show session id` enrichment ran, and
  the report showed an empty attribution table with `—` in the Timeline
  `Sessions` column even though the firewall had reported entries in
  `Drop State: Yes`. Only captures collected after this fix carry offenders: the
  report renders the ranking persisted in the JSONL and does not re-parse the raw
  command output, so regenerating the report of an older capture changes nothing.
  Refs #76.

### Changed

- Each batch now issues one additional read-only API call, `show session info`.
  No firewall state is changed.

## [0.10.0] - 2026-08-29

### Added

- The incident and API-check reports gained a **Denied and dropped traffic**
  section. It aggregates the `drop` severity global counters already collected
  by `show counter global filter delta yes` over the whole capture, grouped by
  PAN-OS counter aspect and name prefix into policy deny, DoS or zone
  protection, forwarding, parse, resource exhaustion, and other drops, with the
  total packets, the peak per-second rate, and the number of batches each
  counter appeared in. A batch whose delta baseline was untrusted is excluded
  from the totals and the exclusion is stated.
- When packets were denied before session setup and a source IP is ranked
  without an enriched session, the report now says so: that is the signature of
  a UDP or GRE flood denied by a Security policy rule, which creates no session,
  so PAN-OS can attribute the buffer pressure to a source IP only and
  `show session id` has nothing to return. A **Denied packets** card was added
  to the incident-state summary. Refs #74.

### Changed

- No firewall interaction changed. The section is derived from evidence already
  present in the JSONL, so it costs no additional API call and no new command,
  and existing captures render the new section when their report is regenerated.

## [0.9.1] - 2026-08-29

### Fixed

- The configuration page kept showing `Validation queued` after the collector
  had already finished the requested validation, because the page never
  refreshed. It now reloads itself every five seconds while at least one
  firewall has a queued validation, and stops as soon as none is pending. The
  reload is suspended while a firewall form is open for editing so it cannot
  discard what is being typed. Refs #72.

## [0.9.0] - 2026-08-29

### Added

- Each dashboard firewall card now carries three live signals instead of one:
  Syslog reception freshness, the outcome of the last read-only API check, and
  whether a monitoring run is in progress on that firewall. A card turns amber
  while a run is active and red when Syslog is stale or the last check failed.
  The run state is derived from the run files the collector already writes, so
  nothing polls the firewall to determine it. Refs #69.

### Changed

- The firewall card headline reports the overall state (`healthy`,
  `monitoring run in progress`, `needs attention`) rather than Syslog reception
  alone, which is now one of the lines beneath it.

## [0.8.0] - 2026-08-29

### Added

- A periodic read-only check per enabled firewall, every `target_check_hours`
  (24 by default, 0 disables it). It runs `show system info` for reachability,
  API key validity and PAN-OS release drift, and `show statistics` only when the
  stored dataplane core map is missing or was captured on a different model or
  release, refreshing the stored copy in place. A firewall in steady state costs
  one API call a day and no capture file is written. Until now a revoked key or
  an unreachable firewall was only discovered during an incident, when evidence
  was already being lost. Refs #69.
- A **Test** button beside each firewall in the admin UI, running the full
  read-only validation for that firewall: every collection command, every parser,
  and a capture plus HTML report the dashboard already serves. The Web service
  mounts the evidence volume read-only and the collector exposes no port, so the
  request travels through the shared configuration database and the collector
  executes it on its next tick, a few seconds later.
- A **Last check** column reporting when either check last ran, whether it
  passed, and a short reason when it did not.
- Persisted `last_check_at`, `last_check_kind`, `last_check_status`,
  `last_check_detail` and `check_requested_at` columns, migrated in place
  (schema version 5), and a `target_check_hours` setting.

### Changed

- A firewall with an active incident is never checked. It is already polled every
  few seconds while under packet-buffer pressure, and no check may compete with
  the diagnostic batches. A routing probe in flight suspends checks as well.
- A failed check is recorded and logged without interrupting Syslog reception or
  any other firewall's check.

## [0.7.1] - 2026-08-29

### Fixed

- `raw/startup.txt` states the dataplane core-to-function-group map and where it
  came from. The text export renders an explicit field list plus commands and
  session lookups, and the map was in none of them; before 0.7.0 it reached the
  file only as a side effect of the `show statistics` response being carried in
  `commands`. Reusing the stored map removed that payload, so an exported run,
  and the support ZIP that bundles it, no longer said which cores carry
  `flow_fastpath` and therefore which cores were comparable. The JSONL and the
  HTML report were unaffected. Refs #67.

## [0.7.0] - 2026-08-29

### Changed

- The dataplane core-to-function-group map is captured once per firewall instead
  of once per incident. `show statistics` now runs when a firewall is saved in
  the admin UI, next to the `show system info` call that already validates the
  API key, and the result is stored with the firewall. An incident reuses it and
  spends no API call on a firewall that is already under packet-buffer pressure
  and being polled every five seconds. The save confirmation reports how many
  cores were mapped. Refs #65.
- A stored map is trusted only while the model and PAN-OS release still match
  what the incident reads from `show system info`, because an upgrade can
  reassign function groups. On a mismatch the collector reads the map again for
  that incident and logs that the firewall should be saved again. `--check-api`
  always calls the command, since it exists to prove the API administrator can
  run everything the collector needs.
- `monitor_started` records gain `dp_core_functions_source`, naming whether the
  map came from `configuration` or from the `firewall`, and carry the map they
  used either way, so incident evidence stays self-contained.

### Added

- Persisted `dp_core_functions_json` and `dp_core_functions_identity` columns,
  migrated in place (schema version 4). Existing firewalls keep working with an
  empty map until they are next saved; their incidents read the map as before.

## [0.6.1] - 2026-08-29

### Fixed

- CPU tracking table headings render their intended symbols. Three characters
  had been stored double-encoded, so reports showed `Hot points â‰¥ 90%` and
  `maxâ€"min spread` instead of `Hot points ≥ 90%` and `max–min spread`, and a
  missing timestamp rendered as `â€"` instead of `—`. Only rendered text is
  affected; no captured evidence changes.

## [0.6.0] - 2026-08-29

### Added

- HTML reports draw the dataplane CPU per core instead of only tabulating it.
  Each dataplane gets its own section with a heatmap of core by batch, which
  stays readable on a chassis with 64 cores, and a line chart of the hottest
  cores against the median of their comparable peers. Both are inline SVG, so
  the report remains a single self-contained file with no script and no
  external asset.
- A stated verdict per dataplane distinguishing an isolated hot core, which is
  what flow-hash concentration from a single high-rate session looks like, from
  a collective rise, which is aggregate load. The verdict is corroborating
  evidence and does not on its own prove that one session is responsible.
- The core-to-function-group map is collected once per incident with
  `show statistics` and persisted as `dp_core_functions` in the
  `monitor_started` record. PAN-OS assigns fixed function groups to each core,
  so a core carrying `flow_mgmt`, `flow_ctrl`, or `pan_timer` is not comparable
  to a pure fastpath core. Cores are labelled with what distinguishes them, and
  only cores carrying `flow_fastpath` are compared. Refs #62.

### Changed

- The per-core summary table gains a Function groups column.
- A firewall that cannot answer `show statistics` records a
  `dataplane core function groups could not be read` warning and still renders
  the charts, with cores labelled by number. Device identity completeness is
  unaffected.

## [0.5.1] - 2026-08-29

### Fixed

- Packet Buffer Protection activation state is read from the structured
  operational XML returned by current PAN-OS releases. `extract_pbp_status`
  matched only the CLI text form, so a firewall actively dropping traffic was
  recorded as `active: null` and `mode: "unknown"`, and HTML reports rendered
  the PBP state as unknown. `enabled`, `active`, `mode`, and `monitor_only` now
  come from `is-module-enabled`, `is-running`, `use-buffer`/`use-latency`, and
  `is-monitor-only`, with the text form kept as a fallback. On a chassis, one
  dataplane in mitigation marks the firewall as active. This also restores
  incident attribution, which treats `active is True` as evidence that a
  candidate firewall is affected. Refs #59.

## [0.5.0] - 2026-08-29

### Added

- The admin firewall form reads the device identity from a single read-only
  `show system info` call: the API key is validated, and the serial, hostname,
  model, and PAN-OS version are stored instead of typed. A blank name takes the
  PAN-OS hostname.
- Persisted `hostname`, `model`, and `sw_version` columns, migrated in place
  (schema version 3), shown in the firewall list.

### Changed

- One **Firewall IP** field replaces the management URL and the allowed Syslog
  source, which are the same address. Additional sources configured earlier are
  preserved on save.
- **TLS verify** is a Yes/No list; a CA bundle path imported from a legacy
  configuration stays selectable for that firewall.
- The authentication method is an explicit choice between generated
  credentials, an existing API key, and the stored key, and only the fields of
  the selected method are displayed.
- The Panorama target serial left the admin form; it remains supported in the
  data model, the legacy import, and Panorama operation mode.

### Security

- `show system info` sends the API key as an unredirected `X-PAN-KEY` header
  through an opener that refuses redirects.
- An unreachable firewall, an untrusted certificate, or a rejected key reports
  an error and writes nothing.

## [0.4.1] - 2026-08-29

### Added

- Event-driven collection for PAN-OS packet-buffer and on-chip packet-descriptor incidents.
- Direct-firewall and Panorama target modes with multi-firewall Syslog routing.
- Bounded session enrichment, throughput derivation, and read-only API validation.
- JSONL evidence, standalone HTML reports, TXT exports, and support ZIP archives.
- Docker Compose deployment with an HTTPS dashboard and authenticated administration.
- Encrypted target credentials, per-firewall TLS policy, and persistent configuration.

### Fixed

- HTML export index rendering remains compatible with the declared Python 3.10 minimum.
- Require a non-vulnerable `cryptography` 50.0.1 release line.

[0.5.0]: https://github.com/tbortolossi/panos-pbp-monitoring/releases/tag/v0.5.0
[0.4.1]: https://github.com/tbortolossi/panos-pbp-monitoring/releases/tag/v0.4.1
