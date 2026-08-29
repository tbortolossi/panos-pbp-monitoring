# Changelog

All notable changes to this project are documented in this file. The project
follows [Semantic Versioning](https://semver.org/).

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
