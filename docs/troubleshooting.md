# Troubleshooting

Symptom-driven checks for a deployed collector. Each entry states what to run
and what the result means; none of them changes firewall state.

Related pages: [Installation](installation.md) · [Operations](operations.md) ·
[Incident report anatomy](reporting.md) · [Back to the README](../README.md)

Before working through the symptoms below, produce a support bundle: one
command on the Docker host gathers the logs, the settings, the Syslog journals
and the service state that every check here reads one by one. See
[Reporting a problem in a deployment you do not administer](#reporting-a-problem-in-a-deployment-you-do-not-administer).


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

## Latest logs show *not stored: source is not a registered firewall*

The reception journal marks the message `source_not_registered`: the sending
address is not the **Firewall IP** of any saved firewall. Register that source
only after verifying it belongs to the firewall or to a trusted relay; never
register an arbitrary client network. The two other refusal slugs,
`device_serial_missing` and `device_serial_not_registered`, mean the source is
known but the serial in the message is not the one read when the firewall was
saved: re-save the firewall so the serial is read again. The three slugs are
described in [Operations](operations.md#persistent-data-and-artifacts), and
`syslog/summary.json` in the support bundle counts them by sender.

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

## Reading a packet-buffer incident

The incident report's diagnosis now names the incident classes below when their
evidence is present. They were derived from eight closed TAC packet-buffer
cases (PA-1420 to PA-7080, PAN-OS 10.2.9 to 11.2.10); this section is the
operator's map of the same knowledge, for reading a report or a firewall by
hand.

**Leak or burst is the first question.** A burst shows utilization *maxima*
spiking while the same minute's average stays low, full recovery to baseline
between events, and an offender or a schedule you can point at. A leak shows
the *average* pinned or a floor that only ratchets upward, high occupancy
persisting through idle hours (nights, weekends) with the session table at a
few percent, and a reset only at a dataplane restart. The
`Packet buffer congestion (utilization) is X/Y` System log line is the
long-term memory for this call: one line per minute above the alert threshold,
across weeks and reboots — and its denominator Y names the measured pool
(the software buffer pool on PA-400/1400/3400/5400, the on-chip
`PKI POOL DFLT` on PA-3200/5200/7000). An hour-of-day histogram of those
lines that clusters in the same window across days is a scheduler — usually
the backup window — not an attack.

**The classes the report can name**, and what proves each:

- **ARP / L2 storm** — buffers pegged, sessions and connection rate flat,
  no PBP offender, `flow_arp_pkt_rcv` at storm rate (gratuitous share near
  100% = gratuitous-ARP storm). PBP cannot mitigate a flood that creates no
  session, and a firewall reboot changes nothing. `show counter interface all`
  finds the port: rx-broadcast and rx-multicast dwarfing rx-unicast on one
  interface or AE group.
- **Fragmentation pressure** — `flow_ipfrag_recv` at hundreds per second or
  many fragments per reassembled packet, with `flow_ipfrag_pkt_alloc_err` or
  `pkt_alloc_failure` tying the fragments to the exhaustion. Fragmented UDP
  tunnels are the classic source.
- **Decryption proxy pressure** — `tcp_fptcp_*` retransmissions sustained
  under SSL forward proxy; on ASIC platforms the on-chip descriptors saturate
  while software buffers stay moderate, and the load is spread over many
  proxied sessions: blocking the sources PBP names punishes victims.
- **Held resources (leak)** — occupancy decoupled from session load, a
  diagnostic pool (`Timer Pool`, `PKI POOL DFLT`, `proxy_flow`, `ssl_st`,
  `fptcp_seg`) near full, or a buffer-latency maximum orders of magnitude
  above the average. The proof of the root cause usually lives in the
  dataplane `pan_task` logs, which rotate in about a minute at debug level —
  capture them within minutes of an episode, and check later maintenance
  releases for buffer-leak fixes before blaming the traffic.
- **Flood through an unprotected zone** — PBP dropping hard while the
  zone-protection flood counters stay silent. Confirm with
  `show zone-protection`: a zone whose profile has a flood mechanism disabled
  prints no line at all for it — absence means disabled, not zero.
- **Single-dataplane saturation** — on a multi-DP chassis, one dataplane at
  the activate threshold while the median idles: a flow group pinned by its
  hash. The fix is per-flow, not capacity.
- **Session-table collapse** — allocated sessions draining while the buffer
  stays high: the firewall has stopped admitting sessions, the stage where
  tunnels and routing adjacencies fail. Severe even at modest traffic rates.
- **Source blocking collateral** — a PBP block-ip (threat ID 8509) is silent
  for its whole duration; `flow_dos_drop_ip_blocked` counts what it cost.
  Before treating a blocked source as an attacker, check whether it is a NAT
  gateway, a proxy or a backup media server: blocking a convergence point is
  a site outage with no log of its own.
- **Recent boot or upgrade** — an incident starting within days of a boot
  raises the known-issue hypothesis; check the release notes of the running
  PAN-OS before treating the environment as the cause.

Two caveats the corpus proved. The zone written on PBP threat logs is the
ingress interface's zone whenever `flow_dos_pbp_ifp_zone` is a large share of
the PBP drops — do not attribute offenders by that label. And a tech-support
file cannot answer after the fact what the collector captures live: none of
the eight corpus TSFs contained `show session packet-buffer-protection`,
`ingress-backlogs`, threat logs, or the identity of blocked hosts. Keep the
collector's captures with the case.

## Reporting a problem in a deployment you do not administer

When the collector runs at a site you cannot reach, ask the operator for the
support bundle rather than for a description of the symptom. The most complete
form is one command on the Docker host, from the directory holding
`compose.yaml`:

```bash
./pbp-support.sh
```

It produces one archive with the collector's own bundle and the layer only the
host can see: `host/compose-ps.txt` (which services are up, healthy, or
restarting), `host/ports.txt` (the ports actually published and the listeners
found on 514, 1514 and 5514), `host/compose-config.yaml` (the effective
configuration, credentials redacted), `host/syslog-gateway.log`,
`host/collector-stdout.log` and `host/webui-stdout.log` (the container output,
which is the only trace of a crash before file logging started), and
`host/images.txt` (the image digest and labels, to confirm the version that is
really running). When `syslog/received.jsonl` is empty, those files are what
tells a firewall that does not send from a blocked host port, a dead gateway,
or a gateway forwarding to the wrong internal port.

If the operator cannot run the script, the admin page still offers the
container-side bundle — **Support bundle** card, **Download support bundle** —
and so does a shell when the dashboard itself is the problem:

```bash
docker compose exec -T collector pbp-support > pbp-support.zip
```

The bundle carries the collector and dashboard logs, the running versions, every
setting, the firewall inventory, the run inventory, the Syslog journals
including refused messages with `syslog/summary.json` counting them by refusal
slug and sender, the most recent read-only API validation of each firewall with
its raw PAN-OS XML, the three most recent incident runs of each firewall with
their raw XML, and the facts of the web certificate served. It carries no API
key, no administrator password, no recovery key and no setup code. Producing it
makes no call to any firewall.

`runs.json` says which incident runs travelled (`"bundled": true`). If the
incident of interest is older than those, ask for that run's **ZIP support**
archive as well: it holds the full raw XML of every command of every batch.

If their policy forbids sending addresses and serial numbers, ask for the
anonymized forms instead — `./pbp-support.sh --anonymize`, **Download
anonymized bundle** and **ZIP anonymized** — which carry the same evidence
under stable tokens; the dashboard's own hostnames are tokenized too. Diagnosis
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

