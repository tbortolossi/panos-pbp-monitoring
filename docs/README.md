# Documentation

| Page | What it covers |
|---|---|
| [installation.md](installation.md) | Host preparation, TLS certificate, administrator creation, adding a firewall, PAN-OS Syslog forwarding, host firewall rules, validation, controlled lab trigger |
| [operations.md](operations.md) | Collector settings, webhook notifications, persistent volumes and evidence layout, run archives, support bundle and `pbp-support.sh`, anonymized exports, Syslog acceptance and trust model, run deletion, backup and recovery, updates, legacy migration |
| [reporting.md](reporting.md) | Anatomy of the HTML incident report, section by section |
| [troubleshooting.md](troubleshooting.md) | Symptom-driven checks for Syslog, attribution, API, and admin access; remote diagnosis of a deployment from its support bundle and replaying a capture through the parsers |

The project overview, quick start, and security model are in
[../README.md](../README.md). Product behavior and acceptance criteria are in
[../PRD.md](../PRD.md), and the version history in
[../CHANGELOG.md](../CHANGELOG.md).

Repository-wide contributor and vulnerability-handling instructions live in
[../CONTRIBUTING.md](../CONTRIBUTING.md) and [../SECURITY.md](../SECURITY.md).

The `private/` subdirectory is ignored by Git. It is reserved for working
documents or references that must not be published, particularly material that
may contain internal information or be subject to distribution restrictions.
