# PAN-OS PBP Monitoring — Packet Buffer Protection incident collector

[![CI](https://github.com/tbortolossi/panos-pbp-monitoring/actions/workflows/ci.yml/badge.svg)](https://github.com/tbortolossi/panos-pbp-monitoring/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.21.0-blue.svg)](https://github.com/tbortolossi/panos-pbp-monitoring/releases/latest)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776ab.svg)](https://www.python.org/downloads/)
[![Deployment](https://img.shields.io/badge/deployment-Docker%20Compose-2496ed.svg)](compose.yaml)
[![Read-only](https://img.shields.io/badge/firewall%20impact-read--only-brightgreen.svg)](#safety-guarantees)
[![License](https://img.shields.io/badge/license-proprietary-red.svg)](LICENSE)

**PBP Monitoring is a self-hosted, event-driven diagnostic collector for Palo
Alto Networks firewalls under packet-buffer pressure.** It listens to PAN-OS
Syslog, recognizes Packet Buffer Protection (PBP) and on-chip packet-descriptor
events, and — only then — opens a bounded investigation on the firewall that
raised the alert: read-only operational XML API commands, sampled every few
seconds while the pressure lasts, written as JSONL, HTML, and plain-text
evidence you can attach to a Palo Alto Networks TAC case.

It answers the question a packet-buffer incident always raises and that nobody
can answer after the fact: **what was flooding the firewall while the buffers
were full, and where did it enter?**

![The dashboard, showing Syslog freshness, one card per firewall, the latest
received logs, and the completed incident runs](docs/images/dashboard.png)

> Every screenshot in this repository is generated from a fictitious
> incident by `tools/generate_demo_stack.py`. No firewall, address, or
> serial shown is real.

More captures: the [incident report](docs/images/incident-report.png), the
[configuration page](docs/images/admin-configuration.png), the
[firewall form](docs/images/admin-firewall-form.png), the
[first-run setup](docs/images/admin-setup.png), the
[sign-in page](docs/images/admin-sign-in.png), and the
[TXT export index](docs/images/text-exports.png).

## Safety guarantees

The collector is observational. It never changes firewall configuration or
state:

- it never commits, never edits configuration, and calls no configuration API;
- it never clears a session, blocks an address, or restarts a process;
- it never generates test traffic against a firewall;
- it runs a fixed allowlist of `show` and `debug` commands, nothing else;
- it authenticates with the `X-PAN-KEY` header and refuses HTTP redirects.

A dedicated least-privilege XML API administrator is all it needs.

## Contents

- [Quick start](#quick-start)
- [What is included](#what-is-included)
- [What starts a diagnostic run](#what-starts-a-diagnostic-run)
- [What you get out of it](#what-you-get-out-of-it)
- [Documentation](#documentation)
- [Security model](#security-model)
- [Development](#development)
- [Limitations](#limitations)

## Quick start

A Linux host with Docker Engine and the Docker Compose plugin, reachable from
the firewall's Syslog service route. No `.env` file and no configuration file
have to be created:

```bash
git clone https://github.com/tbortolossi/panos-pbp-monitoring.git
cd panos-pbp-monitoring
docker compose build
docker compose up -d
docker compose ps                       # the three services must be healthy
docker compose logs webui | grep "setup code"
```

Open `https://<docker-host>:8088/admin`, enter the one-time setup code from the
log, create the administrator password, then add a firewall and paste the
generated PAN-OS Syslog configuration into the firewall. The full sequence,
including PAN-OS forwarding profiles and host firewall rules, is in
[docs/installation.md](docs/installation.md).

## What is included

The Docker Compose stack contains three non-root services:

| Service | Purpose | Container port | Published host port |
|---|---|---|---|
| `syslog-gateway` | Accept PAN-OS Syslog over UDP or TCP and preserve the observed sender | `1514/udp`, `1514/tcp` | `${SYSLOG_PORT:-514}` |
| `collector` | Route triggers, query PAN-OS, and write incident evidence | none, internal only | none |
| `webui` | HTTPS dashboard, authenticated configuration, evidence downloads | `8080/tcp` | `${WEB_PORT:-8088}` |
| `webui` | HTTP-to-HTTPS redirect only | `8081/tcp` | `${WEB_HTTP_PORT:-8090}` |

Every service runs as UID 10001 with all Linux capabilities dropped, so nothing
inside a container can bind a port below 1024. The published Web ports default
to `8088` and `8090` rather than `443` and `80` because those, along with `8080`
and `8443`, are frequently already taken on a management host. **The defaults
are not a recommendation: publish the standard ports when the host allows it**,
without editing `compose.yaml`:

```bash
WEB_PORT=443 WEB_HTTP_PORT=80 docker compose up -d
```

The redirect target follows `WEB_PORT` automatically. Always read the mapping a
given deployment actually uses from `docker compose ps`.

Runtime configuration lives in the named Docker volume
`pbp-monitoring-config`; evidence lives in `pbp-monitoring-data`. Both survive
image rebuilds.

## What starts a diagnostic run

Four fixed, case-insensitive PAN-OS log signatures, and nothing else:

| PAN-OS log | Trigger |
|---|---|
| System / informational | `Packet buffer congestion` |
| Threat / high / 8507 | `PBP Packet Drop` |
| Threat / high / 8508 | `PBP Session Discarded` |
| Threat / high / 8509 | `PBP IP Blocked` |

A message starts a run only when its source address is a declared Syslog source
of a configured firewall **and** the device serial it carries is the one read
from that firewall when it was saved. Anything else is journalled as a bounded
trace, with no stored text and no API call.

One trigger starts one run. Further matching alerts reinforce the active run
instead of starting concurrent polling. A run ends after the configured number
of complete low-resource samples, the trigger inactivity TTL, or the mandatory
maximum duration. Each `run_id` is the UTC incident start time in
`YYYYMMDDTHHMMSSZ` format.

Zone-protection and DoS flood THREAT logs (SYN/UDP/ICMP flood events) are
corroborating evidence only: during an active incident they extend the
inactivity window and contribute their source, destination, and ingress
interface to the offender evidence. They never start a run by themselves and
never delay the recovery decision.

### What each batch collects

```text
show clock
show session packet-buffer-protection
show session info
show running resource-monitor ingress-backlogs
show running resource-monitor
debug dataplane pool statistics
show counter global filter delta yes
show session all filter min-kb 1048576 min-age 600
```

`show system info` runs once at incident startup to identify the device.
`show statistics`, which returns the function groups assigned to each dataplane
core, runs when a firewall is saved in the admin UI rather than during an
incident, so a firewall already under pressure spends no API call on it.

The last command hunts the elephant session: one transfer large enough and old
enough to fill a link on its own. It needs its own query because such a session
writes no traffic log until it closes, shows little on the management plane
when it is offloaded, and is never named as a PBP offender. Both filters are
applied by the firewall, so it returns a short list rather than its session
table; the thresholds are settings, and `0` on the volume one disables the
query. Each listed session gets its age from the firewall clock of the same
batch and its throughput from the delta of its byte counter between two
batches.

Candidate sessions are enriched with `show session id <session-id>`, and
consecutive cumulative byte counters are sampled to derive c2s, s2c, and total
bit rates without scanning the session table. The ingress interfaces named by
the evidence additionally get `show counter interface` snapshots — at most two
interfaces, on the first batch then every third batch — so input bytes and
drops say where the flood enters when session evidence is thin. At monitor
stop, the top ranked sources get their live sessions listed
(`show session all filter source <ip>`, capped) and, for what never created a
session, one bounded traffic-log query each.

## What you get out of it

**A dashboard** at `https://<docker-host>:8088` showing global Syslog reception
freshness, one card per firewall with its three live signals (Syslog freshness,
last read-only API check, monitoring run in progress), each carrying its own
green, amber or red dot beside the general state of the card, the 20 latest received
logs, and the active and completed runs — each completed run carrying its peak
packet-buffer percentage and top ranked sources, so a recurring offender across
incidents is visible without opening a single report.

**Per-incident evidence**, under `/data/targets/<firewall>/incidents/<run_id>/`:

| Artifact | Content |
|---|---|
| `incident.jsonl` | Authoritative structured records and exact raw command output |
| `report.html` | Standalone human report, single file, no script, carrying the JSONL SHA-256 digest |
| `raw/startup.txt`, `raw/batch-NNNN.txt` | Human-readable export of every command and response |
| ZIP support archive | All of the above plus the deployment environment, the redacted configuration, the Syslog messages of the run including refused ones, and `manifest.json` with version, sizes, and digests, for a TAC case |

Read-only API validation runs, under `api-checks/<run_id>/`, export the same
way: a credential, TLS or unsupported-command problem is diagnosable from an
archive even when no incident was ever collected.

**Deployment support bundle.** The admin page offers a **Download support
bundle** action that packages the whole deployment rather than one run: the
collector and dashboard log files, the running application, Python and
`cryptography` versions, every collector setting and every registered firewall
without credentials, the run inventory and storage usage, and the tail of the
Syslog reception, routing and trigger journals including the messages the
collector refused. It is what makes a remote installation diagnosable without
access to its host. The same archive is available from a shell when the
dashboard is itself the problem:

```bash
docker compose exec -T collector pbp-support > pbp-support.zip
```

The bundle never carries PAN-OS API keys, the administrator password or its
hash, the installation recovery key, or the one-time setup code. It does carry
firewall management addresses, hostnames, serial numbers and the source
addresses recorded as offenders; review it before sending it if that matters.
Producing it makes no call to any firewall.

The report opens with an **At a glance** block — severity read against the
PAN-OS PBP defaults, key figures, and probable-cause sentences ready for a
support case — then ranks the offender sources, plots pressure over time,
aggregates denied and dropped traffic, follows the session table, and charts
per-dataplane CPU. The section-by-section reading guide is in
[docs/reporting.md](docs/reporting.md).

The dashboard, the reports, and every evidence download require the
administrator sign-in: captures contain device serials, addresses, session
tuples, and raw command output. Only `/healthz` answers without
authentication.

Evidence is kept until you remove it. The **Recent runs** table carries a
**Delete** button per completed run and a **Delete all N runs** button for the
whole set, both signed-in actions. There is no automatic retention or purge: a
run disappears only when an operator asks for it, and a run still being
collected is never touched.

## Documentation

| Page | What it covers |
|---|---|
| [docs/installation.md](docs/installation.md) | Host preparation, TLS certificate, administrator creation, adding a firewall, PAN-OS Syslog forwarding, host firewall rules, validation, controlled lab trigger |
| [docs/operations.md](docs/operations.md) | Collector settings, webhook notifications, persistent volumes and evidence layout, Syslog acceptance and trust model, backup and recovery, updates, legacy migration |
| [docs/reporting.md](docs/reporting.md) | Anatomy of the HTML incident report, section by section |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Symptom-driven checks for Syslog, attribution, API, and admin access |
| [PRD.md](PRD.md) | Authoritative product behavior and acceptance criteria |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
| [CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) | Change validation and confidential vulnerability reporting |

## Security model

- PAN-OS API requests use HTTPS POST and the `X-PAN-KEY` header; authenticated
  requests reject redirects.
- Only fixed operational XML commands can execute.
- API keys are encrypted with authenticated encryption using an
  installation-specific persistent master key.
- Admin passwords use salted PBKDF2 verification; sessions use Secure,
  HttpOnly, SameSite cookies and CSRF tokens.
- Failed sign-in and setup attempts are throttled per source address, and the
  collector starts at most 12 monitoring runs per firewall per hour.
- The built-in Web server always uses TLS, generating a persistent self-signed
  certificate unless an explicit certificate/key pair is configured.
- Evidence is mounted read-only in the Web service; only the separate
  configuration volume is writable there.
- Services run as an unprivileged UID with all Linux capabilities dropped and
  `no-new-privileges` enabled.
- Dashboard and admin publication defaults to all host interfaces. Restrict the
  published Web ports with a host firewall or upstream management ACL.
- PAN-OS TLS verification is configurable per firewall. New firewalls default to
  disabled verification for appliance certificates; the UI and the logs make
  that reduced assurance visible.

Encryption protects a copied database without the master key. It does not
protect against an attacker who controls the running container or obtains the
entire configuration volume. UDP Syslog carries no source authentication:
the source and serial gates *attribute* a message to a firewall, they do not
*authenticate* it. Run the Syslog path over a trusted segment, exactly like the
API path — see the trust model in
[docs/operations.md](docs/operations.md#persistent-data-and-artifacts).

Raw evidence, configuration backups, and recovery keys are confidential.

## Development

Python 3.10 or newer. The only runtime dependency outside the standard library
is `cryptography`, used for audited authenticated encryption.

Run the test suite against the sources with `PYTHONPATH=src` rather than
installing the package: an editable install would replace the pinned
`cryptography` version that actually applies inside the containers.

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -t . -v
python3 -m compileall -q src/pbp_monitoring tools
docker compose config --quiet
```

Console entry points:

```text
pbp-orchestrator
pbp-report
pbp-export-text
pbp-web
pbp-config
```

### Regenerating the documentation screenshots

The images under `docs/images/` are not taken from a running deployment. They
are rendered from a fictitious incident, so no real serial, address, or
hostname can reach the repository. Regenerate them after any change to the
dashboard, the administration pages, or the HTML report, then review the
result before committing:

```bash
PYTHONPATH=src python3 tools/generate_demo_stack.py
```

The tool builds the demo capture, serves it with the real web server on the
loopback interface, and captures each page with a headless Chromium found on
the host. It contacts no firewall. `--check` builds and verifies every page
without rendering, which is what CI runs: images are reviewed by eye, never
compared pixel by pixel, because headless rendering differs between
distributions.

## Limitations

- The collector is diagnostic, not a SIEM or long-term metrics platform.
- The Compose gateway accepts plain UDP and TCP; native Syslog TLS requires a
  separately configured TLS frontend.
- Parsers cover documented and observed PAN-OS output variants. Validate each
  new model/release with a read-only API check and, when necessary, `debug cli
  on` to confirm operational XML.
- An offender session may disappear before enrichment. The original PBP or
  ingress evidence is still preserved.
- Derived per-session throughput is a delta between cumulative byte counters,
  not a native instantaneous PAN-OS rate.
- `buffer-latency` and `pow performance` remain outside the short batch until
  their model/release-specific operational XML and load are validated.

## License

This project is proprietary and distributed only under a separate written
agreement with the copyright holder. See [LICENSE](LICENSE).
