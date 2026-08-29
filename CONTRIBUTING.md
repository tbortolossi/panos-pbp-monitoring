# Contributing

This is a safety-sensitive diagnostic collector. Contributions must preserve
its read-only relationship with PAN-OS and the confidentiality of customer
evidence.

## Development setup

Python 3.10 or newer is required. `cryptography` is the only runtime dependency
outside the standard library and is used for authenticated secret encryption.

```bash
python3 -m pip install --editable .
python3 -m unittest discover -s tests -t . -v
python3 -m compileall -q src/pbp_monitoring tools
```

Application code belongs under `src/pbp_monitoring/`, command-line entry points
are declared in `pyproject.toml`, and tests belong under `tests/`.

## Change requirements

- Read `PRD.md`, `README.md`, and `CLAUDE.md` before changing behavior.
- Never add mitigation actions, configuration calls, commits, session clears,
  process restarts, or arbitrary operational commands.
- Keep API keys, management addresses, customer names, serial numbers, and raw
  production captures out of commits, fixtures, issues, and review comments.
- Use only anonymized deterministic fixtures. Never generate a traffic flood to
  validate the collector.
- Preserve raw successful and partial command responses in JSONL.
- Add or update tests for parser, trigger, configuration, persistence, or state
  machine changes.
- Update the README and PRD when observable behavior or configuration changes.

## Validation

Before submitting a change, run:

```bash
python3 -m unittest discover -s tests -t . -v
python3 -m compileall -q src/pbp_monitoring tools
docker compose config --quiet
```

When Docker is available, also build the images and run the read-only API check
against a lab firewall using a dedicated least-privilege API administrator.

## Contributions and licensing

The project is proprietary. Submit changes only if you are authorized to do so.
By submitting a contribution, you confirm that it may be incorporated and
distributed under the project's proprietary terms. Contact the maintainer
through the established private project channel if a separate contribution
agreement is required.
