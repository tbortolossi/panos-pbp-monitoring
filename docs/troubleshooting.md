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

## Recovery key was not backed up

Before acknowledging delivery, sign in again and the page will display it. Once
acknowledged, recover it only through protected access to the configuration
volume's `master.key`. Never print it into ordinary logs or support tickets.

