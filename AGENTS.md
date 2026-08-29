# Instructions for Codex

## Mission

Maintain an event-driven diagnostic collector for PAN-OS packet-buffer and
on-chip packet-descriptor incidents. The collector is observational only: it
must never clear sessions, block IP addresses, commit configuration, restart a
process, or otherwise change firewall state.

## Architecture

- `src/pbp_monitoring/orchestrator.py`: UDP syslog listener, incident state
  machine, PAN-OS XML API client, parsers, and JSONL persistence.
- `src/pbp_monitoring/reporting.py`: standalone HTML report generation.
- `pyproject.toml`: package metadata and the `pbp-orchestrator` and
  `pbp-report` console entry points.
- `tests/`: deterministic unit tests that require no firewall.
- `src/pbp_monitoring/config_store.py`: persistent SQLite settings and encrypted
  target credentials.
- `Dockerfile`, `compose.yaml`, and `docker/`: supported container deployment.
- `PRD.md`: authoritative product behavior and acceptance criteria.

## Development commands

```bash
python3 -m pip install --editable .
python3 -m unittest discover -s tests -t . -v
python3 -m compileall -q src/pbp_monitoring tools
pbp-orchestrator
```

The runtime uses `cryptography` for authenticated secret encryption. Keep other
dependencies out unless they have a clear operational benefit and the PRD is
updated.

## Change rules

1. Read `PRD.md` and `README.md` before modifying behavior.
2. Keep secrets out of source, logs, fixtures, and error messages.
3. Authenticate with `X-PAN-KEY`; never place the API key in query parameters.
4. Keep PAN-OS TLS verification configurable per firewall. New firewalls default
   to disabled verification for compatibility with appliance certificates, and
   the UI and logs must make that reduced assurance visible.
5. Preserve direct-firewall and Panorama `target` operation modes.
6. Preserve raw command outputs in JSONL for TAC evidence.
7. Treat parser failures as partial collection failures; one failed command
   must not discard successful results from the same cycle.
8. Deduplicate concurrent triggers. A new trigger during an active incident
   must extend/reinforce the current monitor, not create a polling storm.
9. Add or update tests for every parser, trigger, or state-machine change.
10. Update the README and PRD when configuration changes.
11. Keep changes focused and reviewable. Preserve backward-compatible persisted
    data whenever practical, provide explicit migrations for schema changes, and
    do not mix unrelated cleanup into a functional change.
12. Prefer the Python standard library and existing project patterns. Add a
    runtime dependency only when its operational or security benefit is clear,
    documented in the PRD, and covered by tests.
13. Validate untrusted input at the boundary, escape all rendered data, reject
    redirects and path traversal, use bounded reads/concurrency/retention, and
    fail closed for authentication and authorization decisions.
14. Keep tests deterministic, independent of external firewalls and public
    networks, and use only anonymized fixtures.

## Versioning

- Follow Semantic Versioning for the application version: PATCH for compatible
  fixes, MINOR for backward-compatible features or persisted-schema additions,
  and MAJOR for breaking CLI, configuration, data-format, or deployment changes.
- Documentation-only and test-only changes do not require a version bump unless
  they describe a release.
- Keep the version synchronized in `pyproject.toml`,
  `src/pbp_monitoring/__init__.py`, and the Docker OCI image label. Do not confuse
  editor/workspace schema versions with the application version.
- Before release, ensure the UI, captures, HTML reports, support archives, and
  recovery-key export all obtain the version from the package rather than a
  duplicated literal.
- Record user-visible behavior, configuration changes, migrations, and security
  implications in the README and PRD before tagging a release.

## PAN-OS validation

Operational XML varies occasionally by PAN-OS release. Confirm command XML on
the target release with `debug cli on`. Do not silently replace operational
commands with configuration calls.

Live testing must use a dedicated least-privilege API administrator and a lab
firewall whenever possible. Never generate a flood to test this collector.

## Definition of done

- `python3 -m unittest discover -s tests -t . -v` passes.
- Python compilation passes for `src/pbp_monitoring/` and `tools/`.
- No credentials or real management addresses are committed.
- Failure paths are logged and do not terminate the syslog listener.
- Documentation matches observable behavior.
- Application-version declarations are synchronized when a bump is required.
