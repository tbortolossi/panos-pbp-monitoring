# PAN-OS PBP Monitoring & Diagnostic Collector

[![CI](https://github.com/tbortolossi/panos-pbp-monitoring/actions/workflows/ci.yml/badge.svg)](https://github.com/tbortolossi/panos-pbp-monitoring/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.9.0-blue.svg)](https://github.com/tbortolossi/panos-pbp-monitoring/releases/tag/v0.9.0)
[![License](https://img.shields.io/badge/license-proprietary-red.svg)](LICENSE)

PBP Monitoring is an event-driven, read-only diagnostic collector for PAN-OS
packet-buffer and on-chip packet-descriptor incidents. It receives PAN-OS
Syslog, starts a bounded investigation when a PBP event is recognized, queries
only allowlisted operational XML API commands, and produces JSONL, HTML, and
human-readable TXT evidence.

The collector never changes firewall configuration or state. It does not
commit, clear sessions, block addresses, restart processes, or generate test
traffic.

## What is included

The Docker Compose stack contains three non-root services:

| Service | Purpose | Exposure |
|---|---|---|
| `syslog-gateway` | Accept PAN-OS Syslog over UDP or TCP and preserve the observed sender | Host TCP/UDP `514` |
| `collector` | Route triggers, query PAN-OS, and write incident evidence | Internal UDP `5514` |
| `webui` | HTTPS dashboard, authenticated configuration, and HTTP-to-HTTPS redirect | Host TCP `8088` (HTTPS) and `80` (redirect only) |

Runtime configuration is stored in the named Docker volume
`pbp-monitoring-config`. A normal installation requires neither `.env` nor
`config/targets.json`.

The dashboard provides:

- global Syslog reception freshness;
- one card per configured firewall carrying its three live signals: Syslog
  reception freshness, the outcome of the last read-only API check, and whether a
  monitoring run is in progress on that firewall;
- the 20 latest received logs;
- active and completed runs, including their UTC start time;
- links to HTML reports, JSONL evidence, and TXT batch exports;
- an authenticated admin area for collector settings and firewall inventory.

## Triggered diagnostics

The fixed, case-insensitive trigger signatures are:

| PAN-OS log | Trigger |
|---|---|
| System / informational | `Packet buffer congestion` |
| Threat / high / 8507 | `PBP Packet Drop` |
| Threat / high / 8508 | `PBP Session Discarded` |
| Threat / high / 8509 | `PBP IP Blocked` |

Each collection batch runs:

```text
show clock
show session packet-buffer-protection
show running resource-monitor ingress-backlogs
show running resource-monitor
debug dataplane pool statistics
show counter global filter delta yes
```

`show system info` runs once at incident startup to identify the device.
`show statistics`, which returns the function groups assigned to each dataplane
core, runs when a firewall is saved in the admin UI rather than during an
incident. Candidate sessions are
enriched with `show session id <session-id>`. Consecutive cumulative byte
counters are sampled to derive c2s, s2c, and total bit rates without scanning
the complete session table.

One trigger starts one run. Further matching alerts reinforce the active run
instead of starting concurrent polling. A run ends after the configured number
of complete low-resource samples, the trigger inactivity TTL, or the mandatory
maximum duration.

Each `run_id` is the UTC incident start time in `YYYYMMDDTHHMMSSZ` format.

## First installation on Linux

### 1. Prepare the host

Recommended platform:

- a dedicated Linux host or VM;
- Docker Engine with the Docker Compose plugin;
- connectivity from the firewall Syslog service route to host port 514;
- HTTPS connectivity from the Docker host to the PAN-OS management API;
- persistent storage for the two named Docker volumes;
- accurate host time through NTP.

Confirm Docker is available:

```bash
docker version
docker compose version
```

Clone the repository, then enter its directory. No configuration file needs to
be created:

```bash
git clone https://github.com/tbortolossi/panos-pbp-monitoring.git
cd panos-pbp-monitoring
docker compose config --quiet
docker compose build
docker compose up -d
docker compose ps
```

All three services must become `healthy`. The expected published endpoints are:

```text
0.0.0.0:514       TCP and UDP Syslog
0.0.0.0:80        HTTP redirect to HTTPS
0.0.0.0:8088      HTTPS dashboard and administration
```

The Web service always uses TLS. On first startup it creates an
installation-specific self-signed certificate and private key in the persistent
configuration volume. Remote administration, including initial password setup
and authenticated password changes, is enabled without a `.env` file. Restrict
TCP 80 and 8088 to the trusted management network with the host firewall or an
upstream ACL; the first administrator setup is intentionally reachable remotely.

Opening `http://<docker-host>` returns an HTTP 308 redirect to
`https://<docker-host>:8088`. The HTTP listener never serves the dashboard,
credentials, artifacts, or health data.

Open `https://<docker-host>:8088/admin`. The default certificate contains
`localhost` and `127.0.0.1`; a browser warning is therefore expected when the
service is first reached by another name or address. To generate the initial
certificate with the real management IP and DNS name, optionally set the SANs
for the first startup without creating `.env`:

```bash
WEB_TLS_HOSTNAMES=10.0.0.20,pbp-monitor.example.internal,localhost,127.0.0.1 \
docker compose up -d
```

Open `https://10.0.0.20:8088`. The certificate and private key are generated
once as `/config/web-tls.crt` and `/config/web-tls.key` in the persistent
configuration volume. Copy the public certificate over a trusted channel and
install it on the administration workstation to remove the browser warning and
protect against impersonation:

```bash
docker compose cp webui:/config/web-tls.crt ./pbp-monitoring-web.crt
```

Keep `web-tls.key` private. Changing `WEB_TLS_HOSTNAMES` does not replace an
existing certificate; remove or rotate the pair deliberately when its names
must change. HTTPS automatically marks the administrator session cookie
`Secure`.

To use an existing certificate instead, mount it through `certs/` and set
`WEB_TLS_CERT=/certs/web.crt` and `WEB_TLS_KEY=/certs/web.key`. Both values must
be supplied; otherwise startup fails closed.

To use different host ports without creating `.env`:

```bash
WEB_HTTP_PORT=8090 WEB_PORT=8443 docker compose up -d
```

The redirect automatically targets the selected `WEB_PORT`.

### 2. Create the administrator

Open `https://<docker-host>:8088/admin` and create a
password of at least 8 characters. The password is stored as a salted PBKDF2
verifier; the plaintext password is never stored.

An authenticated administrator can later change it in the configuration page.
The current password is required and all active administrator sessions are
invalidated after the change.

After the first authenticated sign-in, the admin page displays the installation
recovery key. Save it in a password manager or offline vault, then acknowledge
the backup in the page. It remains visible until acknowledgement and is not
rendered again afterwards. A CSV download is available before acknowledgement.

The key is generated once at first startup and persists across image rebuilds.
It is not generated during the Docker build. Anyone possessing both the
recovery key and `config.db` can decrypt the PAN-OS API keys, so treat it as a
privileged credential.

### 3. Add a firewall

In **Admin > Firewalls**, enter:

| Field | Description |
|---|---|
| Name | Stable local identifier, for example `PA-440`. Left blank, the PAN-OS hostname read from the firewall is used |
| Firewall IP | The firewall address, for example `192.0.2.10`. It is used both as the HTTPS API endpoint and as the allowed Syslog source |
| Authentication method | How the API key is obtained: username and password, an existing API key, or the stored key when editing |
| API key | Used by the *Existing API key* method |
| API username / API password | Used by the *Username and password* method; the password is never stored |
| TLS verify | Yes or No, per firewall; new firewalls default to No |
| Enabled | Whether the target participates in routing and collection |

Saving contacts the firewall once with `show system info`. That single read-only
call validates the API key and returns the device serial, hostname, model, and
PAN-OS version. All four are stored: the serial is what attributes an HA or
multi-firewall Syslog message to this target, and the hostname, model, and
version are shown in the **Device** column of the firewall list, so none of them
is typed by hand. The firewall must be reachable when the entry is saved: an
unreachable address, an untrusted certificate, or a rejected key is reported and
nothing is written.

### Keeping a saved firewall verified

A firewall is otherwise only contacted when an incident starts, so a revoked API
key, an address moved behind a new filter, or a deleted API administrator would
be discovered during an incident, exactly when evidence is being lost. The
collector therefore runs a small read-only check per enabled firewall every
`target_check_hours`, 24 by default, and 0 disables it:

- `show system info` for reachability, API key validity, and release drift;
- `show statistics` only when the stored dataplane core map is missing or was
  captured on a different model or PAN-OS release, refreshing it in place.

A firewall in steady state therefore costs one API call a day, and no capture
file is written. A firewall with an active incident is never checked: it is
already polled every few seconds while under packet-buffer pressure, and the
check must not compete with the diagnostic batches.

Each firewall card on the dashboard states the result of that check beside its
Syslog freshness, and turns amber while a monitoring run is in progress on that
firewall. The run state is read from the run files the collector already writes;
nothing polls the firewall to determine it.

The **Test** button beside each firewall runs the full read-only validation for
that firewall instead: every collection command and every parser, writing a
capture and an HTML report the dashboard already serves. The Web service mounts
the evidence volume read-only by design and the collector exposes no port, so
the button records the request in the shared configuration database and the
collector runs it on its next tick, a few seconds later. The **Last check**
column reports when either check last ran, whether it passed, and a short reason
when it did not.

Because HTTPS uses port 443 and Syslog uses port 514, one address covers both.
When an earlier configuration allowed additional Syslog sources for a target,
for example a PAN-OS service-route address, they are preserved on save and
listed under the form.

When temporary credentials are supplied, the Web service sends them by HTTPS
POST to PAN-OS key generation. They are never placed in the URL and the username
and password are not stored. The resulting API key is encrypted immediately.

Use a dedicated least-privilege XML API administrator. Prefer a management
certificate signed by an internal CA: copy its PEM bundle into `certs/` and set
**TLS verify** to *Yes*, with the container path of the bundle installed as the
system trust store. A per-firewall CA bundle path imported from a legacy
`targets.json`, for example `/certs/company-ca.pem`, is preserved and offered as
an extra choice in the list for that firewall.

New firewalls default to *No* for compatibility with self-signed management
certificates. Enable verification for production firewalls whenever possible;
the collector logs a warning whenever it is disabled.

### 4. Configure PAN-OS Syslog forwarding

Replace `<COLLECTOR_IP>` with the Linux Docker host address reachable from the
firewall. The following PAN-OS 12.2 CLI hierarchy creates the UDP/BSD server
profile:

```text
configure
set shared log-settings syslog PBP-Docker server PBP-Docker server <COLLECTOR_IP>
set shared log-settings syslog PBP-Docker server PBP-Docker transport UDP
set shared log-settings syslog PBP-Docker server PBP-Docker port 514
set shared log-settings syslog PBP-Docker server PBP-Docker format BSD
set shared log-settings syslog PBP-Docker server PBP-Docker facility LOG_USER
```

When security rules already use the Log Forwarding Profile named `default`, add
dedicated match lists without replacing existing destinations or built-in
actions:

```text
set shared log-settings system match-list PBP-Docker filter "All Logs"
set shared log-settings system match-list PBP-Docker send-syslog [ PBP-Docker ]

set shared log-settings profiles default match-list PBP-Docker log-type threat
set shared log-settings profiles default match-list PBP-Docker filter "((threatid eq 8507) or (threatid eq 8508) or (threatid eq 8509))"
set shared log-settings profiles default match-list PBP-Docker send-syslog [ PBP-Docker ]
```

The System entry forwards ordinary System logs as well as early packet-buffer
congestion alerts. Ordinary logs make transport freshness observable without
creating an incident. The Threat entry sends only PBP IDs 8507–8509.

Confirm that existing security rules reference the intended profile:

```text
show rulebase security rules | match log-setting
show shared log-settings syslog PBP-Docker
show shared log-settings system
show shared log-settings profiles default
```

Commit only after reviewing the candidate configuration:

```text
commit description "Forward PBP System and Threat logs to the diagnostic collector"
```

A firewall must send Syslog from the same address configured as **Firewall IP**.
If a service route makes it send from a different source, the collector logs
`source not allowlisted` for that address.

### 5. Restrict the Linux host firewall

Allow port 514 only from the firewall management or Syslog service-route
addresses. Prefer an upstream network ACL. Docker creates its own forwarding
rules for published ports, so a generic UFW rule is not sufficient on every
host.

With Docker's iptables backend, place restrictions in `DOCKER-USER` before
Docker's accept rules. Traffic is already DNATed there, so the gateway's
container port is `1514`:

```bash
sudo iptables -I DOCKER-USER 1 -i <EXTERNAL_INTERFACE> -p udp -s <FIREWALL_SYSLOG_SOURCE> --dport 1514 -j ACCEPT
sudo iptables -I DOCKER-USER 2 -i <EXTERNAL_INTERFACE> -p udp --dport 1514 -j DROP
sudo iptables -I DOCKER-USER 3 -i <EXTERNAL_INTERFACE> -p tcp -s <FIREWALL_SYSLOG_SOURCE> --dport 1514 -j ACCEPT
sudo iptables -I DOCKER-USER 4 -i <EXTERNAL_INTERFACE> -p tcp --dport 1514 -j DROP
```

Adapt and persist the rules using the host's actual firewall backend. Review
[Docker's packet-filtering guidance](https://docs.docker.com/engine/network/firewall-iptables/)
before deployment. Plain UDP/TCP Syslog is not encrypted; use a protected
management network, VPN, or TLS-capable frontend when transport confidentiality
is needed.

### 6. Validate the installation

Check the listeners and service logs:

```bash
sudo ss -lunpt | grep ':514'
docker compose ps
docker compose logs --tail 100 collector syslog-gateway webui
```

Run one complete read-only PAN-OS API validation batch:

```bash
docker compose run --rm --no-deps collector \
  pbp-orchestrator --env-file /dev/null --check-api
```

The command returns success only when the configured targets, commands, and
required parsers validate. It writes evidence under each target's `api-checks`
directory.

Generate or wait for an ordinary PAN-OS System event, such as an authorized
administrator login. Confirm all of the following on the dashboard:

- **Syslog reception is active** is green globally;
- the corresponding firewall shows **receiving logs**;
- the event appears in **20 most recent received logs**;
- no diagnostic run starts for an ordinary non-PBP event.

Then wait for a genuine PBP event or use the controlled injection described
below. Never generate a flood to test the collector.

## Controlled lab trigger

The following injection starts behind the network-facing gateway. It validates
routing, trigger recognition, API collection, persistence, and reporting, but
does not prove the firewall-to-host UDP path:

```bash
docker compose exec -T syslog-gateway sh -c \
  "printf '%s\n' 'PBP_SYSLOG_SOURCE=<ALLOWED_SOURCE> <14>Packet buffer congestion is 50000/86016 (58%)(alert threshold is 50%).' | nc -u -w1 collector 5514"
```

Inspect the lifecycle:

```bash
docker compose logs --since 5m collector
docker compose exec collector find /data/targets -maxdepth 4 -type f
```

A trigger using an unconfigured source must be rejected before any PAN-OS API
call. That is expected allowlist behavior.

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
| Generate HTML report | `true` | Build the standalone incident report |
| Generate text export | `true` | Write startup and batch TXT files |
| Syslog fresh seconds | `300` | Green/red dashboard freshness window |
| Target check hours | `24` | Interval of the read-only firewall check; `0` disables it |

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

The reception journal is intentionally bounded, so the second file contains the
matching messages still retained when the ZIP is downloaded. The authoritative
trigger copies remain in `incident.jsonl` and the target trigger journal. A ZIP
may contain sensitive addresses, device identifiers, policies, and traffic
metadata; transfer and store it as confidential diagnostic evidence.

Reports contain a bounded two-axis timeline with sticky headers and batch
identifiers. Empty `error: null` fields are omitted from HTML while JSONL keeps a
stable schema. Opening a command displays its extracted `result` immediately;
the exact `raw_response` remains available in a nested section collapsed by
default. Command status and timing fields are presented as compact metadata,
the summary separates capture facts, incident state, and peak utilization, and
its peak metrics are grouped into packet buffers, packet descriptors, and
system load. The lower-level event metadata is collapsed by default.

Each batch requests `show running resource-monitor second last N`, where `N` is
`ceil(poll_seconds) + 2`, bounded to 60 seconds. The two-second margin avoids
missing CPU spikes because of command duration or scheduling jitter. Every
returned per-core average and maximum is preserved, together with the latest
value, window average, window peak, hot-point count, and sample count. Adjacent
windows intentionally overlap and must not be summed as unique seconds.

The HTML report draws one section per dataplane, so a chassis with several
dataplanes produces one set of charts per DP. Each section states whether the
load rose on every comparable core or on only a few of them, then shows a
heatmap of core by batch, which stays readable at 64 cores, and a line chart of
the hottest cores against the median of their peers. Both are inline SVG: the
report stays a single self-contained file with no script and no external asset.
The per-core summary table and the batch imbalance timeline remain underneath as
the detailed evidence.

The distinction the charts are built for is the one that matters
operationally. Every comparable core rising together is aggregate load. One core
saturated while its peers stay cold is flow-hash concentration, which is what a
single very high-rate session looks like from the dataplane. This corroborates
possible flow-hash concentration; it does not prove that one session alone is
responsible, so it must be read alongside session rates, PBP offenders, and
ingress backlogs.

Dataplane cores are not interchangeable, so the comparison is restricted to
cores that actually forward traffic. Cores are labelled by what distinguishes
them from their peers, such as `flow_mgmt`, `flow_ctrl`, or `pan_timer`, and
only cores carrying `flow_fastpath` are compared: a timer core sitting
permanently at 0% is not a sign of imbalance.

That map comes from `show statistics`, which PAN-OS answers with one entry per
core. Because the assignment is fixed for a platform and PAN-OS release, the
command runs **once per firewall**, when the firewall is saved in the admin UI,
next to the `show system info` call that already validates the API key. The
result is stored with the firewall and the release it was captured on, so an
incident spends no API call on a firewall that is already under pressure. The
save confirmation reports how many cores were mapped.

A PAN-OS upgrade can reassign function groups, so a stored map is only trusted
while the model and PAN-OS version still match what the incident reads from
`show system info`. On a mismatch the collector reads the map again for that
incident and logs that the firewall should be saved again to refresh the stored
copy. Each `monitor_started` record carries the map it used and a
`dp_core_functions_source` field naming where it came from, `configuration` or
`firewall`, so incident evidence stays self-contained. `--check-api` always
calls the command, because its purpose is to prove that the configured API
administrator can run everything the collector needs.

A firewall that cannot answer the command is still saved normally. The incident
records a `dataplane core function groups could not be read` warning, and the
charts still render with cores labelled by number.

Copy one incident to the Linux host without modifying the volume:

```bash
docker compose cp \
  collector:/data/targets/<target>/incidents/<run_id> \
  ./incident-export
```

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

## Troubleshooting

### Global Syslog is red

```bash
docker compose ps
docker compose logs --tail 100 syslog-gateway collector
sudo ss -lunpt | grep ':514'
```

Verify the PAN-OS Syslog server profile, service route, Linux firewall, upstream
ACL, and destination address. A successful API check does not validate Syslog
transport.

### Global is green but one firewall is red

The collector receives logs but cannot attribute a recent one to that target.
Check:

- the target's **Firewall IP**, which is also its allowed Syslog source;
- the observed source in the latest-log table;
- PAN-OS service-route selection;
- device serial configuration;
- shared relay ambiguity.

### `source not allowlisted`

Use the source printed in the warning only after verifying it belongs to the
firewall or trusted relay. Never broadly allowlist arbitrary client networks.

### PAN-OS API failure

Run the read-only API check and review its generated report. Confirm HTTPS
reachability, certificate trust, key validity, least-privilege permissions, and
the target's enabled state. Re-saving the firewall in the admin page repeats the
`show system info` validation immediately.

### Admin page is not reachable remotely

The default publishes the HTTP redirect on TCP 80 and HTTPS on TCP 8088. Check
`docker compose ps`, the host firewall, and upstream management ACLs. Use an address from
`WEB_TLS_HOSTNAMES` when certificate validation is configured on the
administrator workstation.

### Recovery key was not backed up

Before acknowledging delivery, sign in again and the page will display it. Once
acknowledged, recover it only through protected access to the configuration
volume's `master.key`. Never print it into ordinary logs or support tickets.

## Security model

- PAN-OS API requests use HTTPS POST and the `X-PAN-KEY` header.
- Authenticated requests reject redirects.
- Only fixed operational XML commands can execute.
- API keys are encrypted with authenticated encryption using an
  installation-specific persistent master key.
- Admin passwords use salted PBKDF2 verification.
- Admin sessions use HttpOnly, SameSite cookies and CSRF tokens.
- The built-in Web server always uses TLS, generating a persistent self-signed
  certificate unless an explicit certificate/key pair is configured.
- Dashboard and admin publication defaults to all host interfaces. Protect TCP
  80 and 8088 with a host firewall or upstream management ACL; admin sessions use
  Secure, HttpOnly, SameSite cookies and CSRF tokens.
- Evidence is mounted read-only in the Web service; only the separate
  configuration volume is writable there.
- Services run as an unprivileged UID with all Linux capabilities dropped and
  `no-new-privileges` enabled.
- Raw evidence, configuration backups, and recovery keys are confidential.

Encryption protects a copied database without the master key. It does not
protect against an attacker who controls the running container or obtains the
entire configuration volume.

## Development

Python 3.10 or newer is required. The only runtime dependency outside the
standard library is `cryptography`, used for audited authenticated encryption.

```bash
python3 -m pip install --editable .
python3 -m unittest discover -s tests -t . -v
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

`PRD.md` defines product behavior and acceptance criteria. `CLAUDE.md` defines
the repository safety constraints. `CONTRIBUTING.md` and `SECURITY.md` describe
change validation and confidential vulnerability reporting.

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
agreement with the copyright holder. See `LICENSE`.
