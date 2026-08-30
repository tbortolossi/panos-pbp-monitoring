# Operations

Day-to-day operation of a running collector: settings, where the evidence
lives, what the Syslog acceptance rules store, backups, updates, and migration
from a legacy file-based installation.

Related pages: [Installation](installation.md) ·
[Incident report anatomy](reporting.md) ·
[Troubleshooting](troubleshooting.md) · [Back to the README](../README.md)

## Admin configuration

Collector settings are stored in SQLite and validated before their revision is
published:

| Setting | Default | Meaning |
|---|---:|---|
| Poll seconds | `5` | Delay between diagnostic batches |
| Maximum monitor seconds | `900` | Absolute incident duration limit |
| Incident idle TTL seconds | `300` | Stop after no matching alert reinforcement |
| Recovery threshold | `40` | Resource percentage considered recovered |
| Low samples to stop | `3` | Consecutive complete low measurements |
| Request timeout | `15` | PAN-OS API timeout per request |
| Maximum session lookups | `10` | Bounded session enrichments per cycle |
| Session retry seconds | `5` | Minimum resampling interval per candidate |
| Large session min kb | `1048576` | Cumulative volume above which a session is tracked; `0` disables the query |
| Large session min age seconds | `600` | Minimum session age for the same query; `0` removes the age filter |
| Generate HTML report | `true` | Build the standalone incident report |
| Generate text export | `true` | Write startup and batch TXT files |
| Syslog fresh seconds | `300` | Green/red dashboard freshness window |
| Target check hours | `24` | Interval of the read-only firewall check; `0` disables it |
| Webhook URL | *(empty)* | Incident notifications; empty disables them |

The two large-session thresholds are the cost control of the largest-session
query: `show session all filter` walks the session table on the management
plane, and the filters are what keep the returned list short on a firewall
carrying hundreds of thousands of sessions. Lower them and the query matches
more, costs more, and fills the report with ordinary sessions; raise them and
only the real elephants remain. The volume threshold accepts `0`, which stops
the query being issued at all, or a value of at least `1000` kilobytes. Note
that the age filter also hides a session younger than the threshold, so lower
it when hunting a short, very fast transfer rather than a long-running one.

When a webhook URL is configured, the collector POSTs a JSON payload at
incident start (run, firewall, trigger metadata including the extracted flow)
and at incident stop (stop reason, batch count, top ranked sources, report
path). The call is best effort with a five-second timeout: a failing or slow
endpoint is logged and never delays collection. Use an HTTPS endpoint on a
trusted network; the payload contains addresses and device names.

Configuration changes are loaded at the next received datagram. When an
incident is active, the new revision is deliberately deferred until the run
ends so a single report never mixes two configurations.

## Persistent data and artifacts

Two named volumes survive container replacement and image rebuilds:

| Volume | Contents |
|---|---|
| `pbp-monitoring-config` | `/config/config.db`, `/config/master.key` |
| `pbp-monitoring-data` | Syslog journal, routing evidence, API checks, incidents, reports |

Evidence layout:

```text
/data/
├── syslog-received.jsonl
├── syslog-routing.jsonl
└── targets/
    └── <target-name>/
        ├── syslog-triggers.jsonl
        ├── api-checks/<run_id>/{api-check.jsonl,report.html,raw/}
        └── incidents/<run_id>/{incident.jsonl,report.html,raw/}
```

Each incident contains:

- `incident.jsonl`: authoritative structured and exact raw evidence;
- `report.html`: standalone human report with the JSONL SHA-256 digest;
- `raw/startup.txt`: startup commands and raw HTTP/XML response, plus the
  dataplane core-to-function-group map and where it came from, so an exported run
  explains its own CPU charts;
- `raw/batch-NNNN.txt`: human-readable export for every batch.

The dashboard's **ZIP support** action downloads the complete run as one
compressed archive. It includes the JSONL, HTML and TXT evidence plus a
`manifest.json` containing the application version, file sizes, and SHA-256
digests for transfer to another workstation or a support case. It also contains:

- `support/syslog-triggers.jsonl`: trigger records matching the run ID;
- `support/syslog-received.jsonl`: retained Syslog messages attributed to the
  target between the first and last run timestamps.

### Deleting stored runs

Incident evidence is never removed on its own: there is no retention window, no
age limit, and no size cap. A run leaves the volume only when a signed-in
operator asks for it, from the **Recent runs** table on the dashboard:

- **Delete** on a row removes that one run directory, with its JSONL, its HTML
  report and its TXT exports;
- **Delete all N runs** in the section header removes every run of every
  firewall, including those beyond the twenty the table lists.

The Web service mounts the evidence volume read-only, so it records the request
in the configuration database and the collector performs the removal on its next
ten-second tick — the same path the per-firewall **Test** button already uses.
Until then the row shows *Deleting…* instead of the button. A run that is still
being collected or whose report is still being written is skipped and retried,
so a monitor in progress can never lose its evidence mid-write; that is also why
an active run offers no **Delete** button at all.

Deletion covers `incidents/<run_id>/` only. The `api-checks/` validation
artifacts, `syslog-triggers.jsonl` and `syslog-received.jsonl` are left alone.
The collector logs each removal with the run ID and the firewall:

```bash
docker compose logs collector | grep "at operator request"
```

Deleting a run is irreversible and destroys TAC evidence. Download the ZIP
support archive first if the incident may still be needed.

The reception journal records every datagram the collector receives, but it
stores the text of a message only when the sender passes two gates: the source
address must be a declared Syslog source of a firewall, and the device serial the
message carries must be the one read from that firewall when it was saved. PAN-OS
positions the serial in the third comma-separated field of every log, so this
costs nothing to check on real traffic.

Anything else is kept as a bounded trace carrying its source address, so the
firewall can be recognized and added in the admin UI, and nothing else:

| `suppressed` | Meaning | Dashboard |
| --- | --- | --- |
| `source_not_registered` | the sender is not a declared Syslog source | *not stored: source is not a registered firewall* |
| `device_serial_missing` | no device serial in the message | *not stored: no device serial in the message* |
| `device_serial_not_registered` | the serial is not the registered one | *not stored: device serial is not the registered one* |

The same rule gates monitoring: a refused message starts no incident and causes
no API call, so a spoofed or stray sender cannot make the collector fill the
capture volume. A firewall saved without a serial on record keeps the
source-only rule until it is saved again.

**Trust model.** UDP Syslog carries no source authentication, and the device
serial appears in every PAN-OS log and support case: the two gates *attribute*
a message to a firewall, they do not *authenticate* it. Someone who knows a
registered firewall's address and serial can forge accepted triggers. Run the
Syslog path over a trusted network segment (management VLAN, tunnel, or a
tightly filtered path), exactly like the API path. As a damage limit, the
collector starts at most 12 monitoring runs per firewall per hour; triggers
beyond that are journalled as `trigger_rate_limited` without starting a run,
and reinforcements of an active run are never limited.

The reception journal is intentionally bounded, so the second file contains the
matching messages still retained when the ZIP is downloaded. The authoritative
trigger copies remain in `incident.jsonl` and the target trigger journal. A ZIP
may contain sensitive addresses, device identifiers, policies, and traffic
metadata; transfer and store it as confidential diagnostic evidence.

Copy one incident to the Linux host without modifying the volume:

```bash
docker compose cp \
  collector:/data/targets/<target>/incidents/<run_id> \
  ./incident-export
```

![The TXT export index of one run, listing the startup and batch files with
their sizes](images/text-exports.png)

> Every screenshot in this repository is generated from a fictitious
> incident by `tools/generate_demo_stack.py`. No firewall, address, or
> serial shown is real.

## Backup and recovery

Back up `config.db` and `master.key` together. A database without its matching
key cannot decrypt the PAN-OS API keys. A recovery key without the database does
not contain the target inventory.

For a consistent offline configuration-volume backup:

```bash
mkdir -p backups
docker compose stop collector webui
docker run --rm \
  -v pbp-monitoring-config:/source:ro \
  -v "$PWD/backups:/backup" \
  alpine:3.22 sh -c 'tar czf /backup/pbp-monitoring-config.tgz -C /source .'
docker compose up -d
```

Back up evidence separately when retention is required:

```bash
docker run --rm \
  -v pbp-monitoring-data:/source:ro \
  -v "$PWD/backups:/backup" \
  alpine:3.22 sh -c 'tar czf /backup/pbp-monitoring-data.tgz -C /source .'
```

Store backups as confidential operational data. They may contain API-key
ciphertext, network identifiers, session tuples, rule names, and raw PAN-OS
responses.

## Updating the deployment

The configuration key and evidence are in named volumes, not in the image.
Normal rebuilds preserve them:

```bash
docker compose build --pull
docker compose up -d
docker compose ps
```

After an update, verify the dashboard, the per-firewall cards, and a read-only
API check. Do not use `docker compose down -v`; `-v` deletes both
persistent volumes.

## Migrating an older file-based installation

The runtime no longer needs `.env` or `targets.json`, but a one-time importer is
retained for upgrades. Point it to private files stored outside the repository:

```bash
docker compose run --rm --no-deps \
  -v /secure/legacy:/legacy:ro \
  collector pbp-config import-legacy \
  --targets /legacy/targets.json --env-file /legacy/.env
```

The importer resolves legacy environment references, encrypts API keys, copies
supported collector settings, and refuses to run if the database already
contains a firewall. Securely remove the legacy plaintext files after validating
the imported targets and read-only API check.

