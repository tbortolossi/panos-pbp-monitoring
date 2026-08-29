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

## Recovery key was not backed up

Before acknowledging delivery, sign in again and the page will display it. Once
acknowledged, recover it only through protected access to the configuration
volume's `master.key`. Never print it into ordinary logs or support tickets.

