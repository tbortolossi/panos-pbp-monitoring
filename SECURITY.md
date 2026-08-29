# Security policy

## Reporting a vulnerability

Do not open a public issue containing a vulnerability, API key, firewall
address, serial number, Syslog sample, JSONL capture, HTML report, or customer
identifier.

Use GitHub's private vulnerability reporting from the repository **Security**
tab. If you obtained the software through a support agreement, you may instead
use that agreement's private support channel. Include only the minimum
information required to reproduce the issue, and agree on a protected transfer
method before sending captures or credentials.

Immediately revoke and replace any API key that may have been disclosed. Never
send a PAN-OS password; the collector does not require one at runtime.

## Supported deployments

Security fixes apply to versions explicitly covered by the customer's current
support agreement. Deploy with TLS verification enabled, a dedicated
least-privilege API administrator, network ACLs around Syslog port 514, and
restricted access to the persistent evidence volume.

Also restrict the `pbp-monitoring-config` volume and its backups. `config.db`
contains encrypted API keys and `master.key` decrypts them; possession of both
is equivalent to possession of the configured API keys. The dashboard and
administration endpoint always uses HTTPS and is remotely published by default.
Restrict host TCP 80 and 8088 to a trusted management network with host-firewall
or upstream ACL rules. Port 80 only redirects to HTTPS and never serves
application content. Install and validate the generated self-signed certificate,
or configure a certificate issued by the organization's trusted CA, before
entering credentials on an untrusted network.

Plain TCP and UDP Syslog are not encrypted and carry no source authentication.
The collector's source-address and device-serial gates attribute a message to
a registered firewall; they do not authenticate the sender, because a serial
is printed in every PAN-OS log. Run the Syslog path over a trusted or tightly
filtered network segment. The collector additionally caps monitoring-run
starts per firewall per hour so a forged trigger stream cannot cycle
collection runs without limit. Use a TLS-capable gateway or a protected
management network when transport confidentiality is required.
