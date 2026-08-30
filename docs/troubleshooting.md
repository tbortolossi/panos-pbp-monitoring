# Troubleshooting

Symptom-driven checks for a deployed collector. Each entry states what to run
and what the result means; none of them changes firewall state.

Related pages: [Installation](installation.md) · [Operations](operations.md) ·
[Incident report anatomy](reporting.md) · [Back to the README](../README.md)


## Global Syslog is red

```bash
docker compose ps
docker compose logs --tail 100 syslog-gateway collector
sudo ss -lunpt | grep ':514'
```

Verify the PAN-OS Syslog server profile, service route, Linux firewall, upstream
ACL, and destination address. A successful API check does not validate Syslog
transport.

## Global is green but one firewall is red

The collector receives logs but cannot attribute a recent one to that target.
Check:

- the target's **Firewall IP**, which is also its allowed Syslog source;
- the observed source in the latest-log table;
- PAN-OS service-route selection;
- device serial configuration;
- shared relay ambiguity.

## `source not allowlisted`

Use the source printed in the warning only after verifying it belongs to the
firewall or trusted relay. Never broadly allowlist arbitrary client networks.

## PAN-OS API failure

Run the read-only API check and review its generated report. Confirm HTTPS
reachability, certificate trust, key validity, least-privilege permissions, and
the target's enabled state. Re-saving the firewall in the admin page repeats the
`show system info` validation immediately.

## Reading the collector history beyond `docker logs`

Both services also write a rotating log file inside a volume, so a failure that
happened before the last container restart is still readable:

```bash
docker compose exec -T collector tail -n 200 /data/logs/collector.log
docker compose exec -T webui tail -n 200 /config/logs/webui.log
```

Each file is capped at 2 MB with three generations, and `PBP_LOG_DIR` moves it.
The one-time administrator setup code is never written there; it stays in the
container log only.

## Admin page is not reachable remotely

The default publishes the HTTP redirect on TCP 8090 and HTTPS on TCP 8088, not
on 80 and 443: an unprivileged container cannot bind a port below 1024, and the
defaults avoid ports a host usually already uses. Confirm the mapping actually
published with `docker compose ps`, then check the host firewall and upstream
management ACLs. Use an address from
`WEB_TLS_HOSTNAMES` when certificate validation is configured on the
administrator workstation.

## Hunting a large session by hand

The collector already lists the largest sessions in every batch, and the
incident report has a **Largest sessions** section for them. To look at a
firewall right now, outside any incident, the same query runs at the CLI:

```text
> show session all filter min-kb 1048576 min-age 600
> show session id <id>
```

`min-kb` is a cumulative-kilobyte threshold and `min-age` a minimum age in
seconds, both applied by the firewall, so raising them is what keeps the command
cheap on a busy device. `show session id` then gives the c2s and s2c counters in
bytes and packets, the start time, and the duration. Run
`show session all filter <tab>` to see the exact filters your PAN-OS release
accepts, as the list varies slightly between versions.

Bytes divided by duration is an average over the whole life of the session, not
what it is doing now: a 10 GB session open for eight hours may have been idle
for the last twenty minutes. For the instantaneous figure, poll the same query
twice through the XML API, five to ten seconds apart, index by session ID, and
compare the byte counters:

```text
/api/?type=op&cmd=<show><session><all><filter><min-kb>1048576</min-kb>
<min-age>600</min-age></filter></all></session></show>
```

That is exactly what the collector does between two batches, and it is the only
reliable way to answer "who is using the bandwidth right now". Keep the filters
aggressive on a firewall with hundreds of thousands of sessions: each call walks
the session table on the management plane.

When the question is which flow is saturating a link or the dataplane rather
than which is the largest, `show running resource-monitor ingress-backlogs`
names the sessions filling the ingress buffers. The collector already collects
it in every batch.

## Reporting a problem in a deployment you do not administer

When the collector runs at a site you cannot reach, ask the operator for the
support bundle rather than for a description of the symptom. Admin page,
**Support bundle** card, **Download support bundle**. If the dashboard itself is
the problem:

```bash
docker compose exec -T collector pbp-support > pbp-support.zip
```

The bundle carries the collector and dashboard logs, the running versions, every
setting, the firewall inventory, the run inventory, the Syslog journals
including refused messages, and the most recent read-only API validation of each
firewall with its raw PAN-OS XML. It carries no API key, no administrator
password, no recovery key and no setup code. Producing it makes no call to any
firewall.

If the problem is tied to one incident, ask for that run's **ZIP support**
archive as well: it holds the full raw XML of every command of every batch. Two
files, then: the bundle explains the collector, the run archive explains the
firewall.

If their policy forbids sending addresses and serial numbers, ask for the
anonymized forms instead — **Download anonymized bundle** and **ZIP
anonymized** — which carry the same evidence under stable tokens. Diagnosis
works the same way: an offender is followed by its token, and the operator
translates it back on their side with **Download token mapping** when a real
address is finally needed.

### Reproducing a parsing problem from an archive

A capture keeps the raw HTTP XML of every command, which is enough to reproduce
a parsing failure without any access to the firewall it came from:

```bash
PYTHONPATH=src python3 tools/replay_capture.py pbp-support.zip --failures-only
PYTHONPATH=src python3 tools/replay_capture.py run.zip --command packet_buffer_protection --format json
```

The tool replays every stored response through the parsers of the current
working tree, and exits non-zero when one raises. A command reported as
`unmapped` has no parser entry yet. Once the offending response is identified,
anonymize it, commit it as a fixture, and write the test that fails before the
fix. Nothing in the replay contacts a firewall.

## Recovery key was not backed up

Before acknowledging delivery, sign in again and the page will display it. Once
acknowledged, recover it only through protected access to the configuration
volume's `master.key`. Never print it into ordinary logs or support tickets.

