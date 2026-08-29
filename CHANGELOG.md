# Changelog

All notable changes to this project are documented in this file. The project
follows [Semantic Versioning](https://semver.org/).

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
