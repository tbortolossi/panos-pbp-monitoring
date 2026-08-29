# CLAUDE.md

Instructions for Claude Code on this repository. This file replaces the former
`AGENTS.md` and is the single source of truth for agent behavior here.

## Mission

Maintain an event-driven diagnostic collector for PAN-OS packet-buffer and
on-chip packet-descriptor incidents. The collector is observational only: it
must never clear sessions, block IP addresses, commit configuration, restart a
process, or otherwise change firewall state.

## Working with the maintainer

The maintainer is a network security engineer, not a software developer. Adapt
accordingly:

- Reply in the language they wrote in. Keep code, comments, commit messages,
  documentation, issues, and pull requests in English.
- Explain a change by its operational effect on the collector and the firewall
  before any implementation detail, and use PAN-OS vocabulary.
- Propose the next step with its exact command instead of assuming git, GitHub,
  Docker, or Python knowledge. Run it yourself when it is local and reversible.
- Never report work as finished without having run the Definition of done
  checks, and quote their real output.
- Raise any risk to firewall safety, secrets, or persisted data immediately, in
  plain language.

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

The runtime uses `cryptography` for authenticated secret encryption. Keep other
dependencies out unless they have a clear operational benefit and the PRD is
updated.

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

- `PYTHONPATH=src python3 -m unittest discover -s tests -t . -v` passes.
- Python compilation passes for `src/pbp_monitoring/` and `tools/`.
- No credentials or real management addresses are committed.
- Failure paths are logged and do not terminate the syslog listener.
- Documentation matches observable behavior.
- Application-version declarations are synchronized when a bump is required.

## Development commands

```bash
# Tests and compilation
PYTHONPATH=src python3 -m unittest discover -s tests -t . -v
python3 -m compileall -q src/pbp_monitoring tools

# Stack
docker compose config --quiet
docker compose build
docker compose up -d
docker compose ps                       # all three services must be healthy
docker compose logs --tail 100 collector syslog-gateway webui
```

Run the tests with `PYTHONPATH=src`, not `pip install --editable .`: a system
Python older than the pinned `cryptography>=50.0.1,<51` would be downgraded or
overwritten by an editable install. The suite is standard-library only and runs
against the sources directly. The containers are where the pinned dependency
version actually applies.

## Delivery workflow

Drive this sequence to completion and say which step you are on as you go.
Steps 1 to 6 and 9 are local and reversible. Steps 7 and 8 are pre-authorized:
push the branch, open the pull request, wait for CI, and merge and tag without
stopping to ask. Report the issue, pull request, and tag URLs.

Stop and ask first, every time, for anything that destroys or rewrites
published work:

- force-pushing, or rewriting history already on the remote;
- deleting a remote branch other than the merged pull request's own branch;
- moving or deleting a tag that is already published;
- merging when CI is red, or when a check could not run.

The pre-authorization covers this repository's own delivery flow. It does not
extend to the firewall: the collector stays observational, and the Mission
section still forbids any change to PAN-OS state.

1. **Functional requirement.** A non-trivial behavior change starts as a GitHub
   issue from the feature-request template (`gh issue create`), labelled
   `requirement` when it belongs to the FR list referenced by `PRD.md`.
   Reference it as `Refs #<n>` in the commit and the pull request.
2. **Branch.** Never commit to `main`. Kebab-case with a type prefix: `feat/`,
   `fix/`, `docs/`, `refactor/`, `chore/`, as in
   `feat/single-firewall-ip-form`.
3. **Naming.** English throughout the repository. Python follows the
   surrounding style: `snake_case` functions, `PascalCase` classes, `_private`
   helpers. Tests are named for the behavior they prove
   (`test_unreachable_firewall_prevents_saving`), not for the function they
   call. Persisted keys, settings, and JSONL fields stay `snake_case` and
   backward compatible.
4. **Tests.** Every parser, trigger, state-machine, persistence, or admin-form
   change ships with a test. Run the full suite and the compile check before
   reporting anything as done.
5. **Version.** Run `git tag` first. If the version in `pyproject.toml` is not
   yet tagged, the change belongs to that unreleased version: do not bump
   again. If it is tagged, bump per the Versioning section and update in the
   same commit `pyproject.toml`, `src/pbp_monitoring/__init__.py`, the
   Dockerfile OCI label, the README version badge, and a new `CHANGELOG.md`
   entry.
6. **Commit.** Imperative English subject under 72 characters, no trailing
   period, and a body stating the operational impact.
7. **Pull request.** `gh pr create` against `main`, filling the repository
   template: summary, validation checklist, and safety confirmation. CI runs
   the unit tests and `compileall` on Python 3.10 and 3.13, plus
   `docker compose config`.
8. **Merge.** Only with green CI: `gh pr merge --squash --delete-branch`, then
   `git checkout main && git pull`. Tag only when publishing a version bump:
   `git tag -a v<x.y.z>` and push the tag. Both run without asking; a red or
   missing check turns this back into a question for the maintainer.
9. **Rebuild.** After any change to the image or its code:
   `docker compose build && docker compose up -d && docker compose ps`, and
   confirm the three services are healthy. The `config` and `captures` volumes
   persist, so verify a schema migration against the live database after a
   store change.

### Worktrees

Use a worktree when work is risky or long, or must not disturb the stack
running from the primary checkout:

```bash
git worktree add ../pbp-<topic> -b feat/<topic>
```

Run the suite from inside the worktree with `PYTHONPATH=src`. Do not run
`docker compose up` from two worktrees at once: the project name and published
host ports collide with the primary stack. Clean up as soon as the branch is
merged or abandoned:

```bash
git -C ../pbp-<topic> status        # check nothing is left uncommitted
git worktree remove ../pbp-<topic>  # --force only after that check
git worktree prune
git branch -d feat/<topic>
```

`git worktree list` must show only the primary checkout when no work is in
flight.

## Port model

Container ports are fixed and non-privileged by design: every service runs as
uid 10001 with `cap_drop: ALL`, so nothing can bind a port below 1024 inside the
container. Host exposure is what varies per deployment, through the published
side of `compose.yaml`:

| Service | Container port | Host variable | Default |
| --- | --- | --- | --- |
| `syslog-gateway` | `1514/udp`, `1514/tcp` | `SYSLOG_PORT` | `514` |
| `webui` | `8080/tcp` (HTTPS) | `WEB_PORT` | `8088` |
| `webui` | `8081/tcp` (HTTP redirect) | `WEB_HTTP_PORT` | `8090` |

The defaults are chosen to work on a host where `80`, `443`, `8080` and `8443`
are already taken. Override them on the command line for a different host rather
than editing `compose.yaml`:

```bash
WEB_PORT=443 WEB_HTTP_PORT=80 docker compose up -d
```

`WEB_HTTPS_PUBLIC_PORT` is derived from `WEB_PORT` so the HTTP redirect always
points at the port actually published. No `.env` file is required.

## Verifying the syslog path

End-to-end transport check through the real host port, without fabricating an
incident:

```bash
printf '<14>Jan  1 12:00:00 lab-fw-01 pbp-monitoring transport test\n' \
  | nc -u -w1 <docker-host-ip> 514
docker compose exec -T collector tail -n 5 /data/syslog-received.jsonl
```

The journal entry must show `metadata.syslog_source_ip` equal to the sending
address: the gateway prepends `PBP_SYSLOG_SOURCE=<ip>` so the collector can
attribute a message to a registered target. `target_names: []` means the sender
is not registered as a target in the admin UI yet.

A sender that is not a declared Syslog source of any firewall is journalled as
`suppressed: "source_not_registered"`, with no `message` field and no extracted
metadata other than that source address. The reception is still visible, so the
check above still proves the transport, but the text of the log is not stored.
Register the firewall in the admin UI to record its messages.

Never generate a real packet-buffer flood to test the collector.
