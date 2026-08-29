# Changelog

All notable changes to this project are documented in this file. The project
follows [Semantic Versioning](https://semver.org/).

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
