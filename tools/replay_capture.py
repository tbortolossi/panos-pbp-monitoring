#!/usr/bin/env python3
"""Replay the raw PAN-OS XML of a capture through the current parsers.

A customer archive preserves the raw HTTP XML of every command it ran. That is
enough to reproduce a parsing problem here, on any PAN-OS release, without
touching the customer's firewall: this tool reads a capture, hands each stored
response to the parser that owns it, and reports what comes back.

Use it to answer three questions, in this order:

1. Does the shipped parser still fail on this XML? Run the tool as it is.
2. What exactly does it read wrongly? Compare `--format json` against the
   values the same record already holds.
3. Is the fix real? Re-run after the change, then promote the offending
   response into an anonymized fixture and a test.

Accepted inputs: a run ZIP as downloaded from the dashboard, a support bundle,
a capture directory, or a bare `incident.jsonl` / `api-check.jsonl`.

Nothing here contacts a firewall. It is a pure offline replay.
"""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path
from typing import Any, Callable, Iterator

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from pbp_monitoring.orchestrator import (  # noqa: E402
    extract_dataplane_pool_statistics,
    extract_dp_core_functions,
    extract_firewall_clock,
    extract_global_counters,
    extract_ingress_backlogs,
    extract_interface_counters,
    extract_large_sessions,
    extract_pbp_offenders,
    extract_pbp_status,
    extract_resource_cpu_cores,
    extract_session_filter_count,
    extract_session_filter_entries,
    extract_session_info,
    extract_system_info,
)

#: Which parser owns which stored command. A command absent from this table is
#: reported as unmapped rather than silently skipped: a new command that never
#: gets a replay entry is exactly the one nobody can diagnose remotely.
PARSERS: dict[str, Callable[[str], Any]] = {
    "system_info": extract_system_info,
    "clock": extract_firewall_clock,
    "packet_buffer_protection": extract_pbp_offenders,
    "ingress_backlogs": extract_ingress_backlogs,
    "dataplane_pool_statistics": extract_dataplane_pool_statistics,
    "global_counters_delta": extract_global_counters,
    "global_counters_baseline": extract_global_counters,
    "session_info": extract_session_info,
    "large_sessions": extract_large_sessions,
    "dp_core_functions": extract_dp_core_functions,
    "resource_monitor": extract_resource_cpu_cores,
    "interface_counters": extract_interface_counters,
    "session_filter_count": extract_session_filter_count,
    "session_filter_list": extract_session_filter_entries,
}

CAPTURE_NAMES = ("incident.jsonl", "api-check.jsonl")


def iter_capture_records(source: Path) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield every capture record found in a file, directory or archive."""
    if source.is_file() and source.suffix == ".zip":
        with zipfile.ZipFile(source) as archive:
            for name in sorted(archive.namelist()):
                if Path(name).name not in CAPTURE_NAMES:
                    continue
                for line in archive.read(name).splitlines():
                    record = _decode(line)
                    if record is not None:
                        yield name, record
        return
    if source.is_dir():
        for name in CAPTURE_NAMES:
            for path in sorted(source.rglob(name)):
                yield from _iter_file(path)
        return
    yield from _iter_file(source)


def _iter_file(path: Path) -> Iterator[tuple[str, dict[str, Any]]]:
    with path.open("rb") as handle:
        for line in handle:
            record = _decode(line)
            if record is not None:
                yield str(path), record


def _decode(line: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(line.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def replay_record(record: dict[str, Any], only: set[str] | None) -> list[dict[str, Any]]:
    """Re-parse every stored command of one record."""
    commands = record.get("commands")
    if not isinstance(commands, dict):
        return []
    outcomes: list[dict[str, Any]] = []
    for name, payload in sorted(commands.items()):
        if only and name not in only:
            continue
        if not isinstance(payload, dict):
            continue
        outcome: dict[str, Any] = {
            "run_id": record.get("run_id"),
            "timestamp": record.get("timestamp"),
            "command": name,
            "collected_ok": payload.get("ok"),
            "collection_error": payload.get("error"),
        }
        parser = PARSERS.get(name)
        result = payload.get("result")
        if parser is None:
            outcome["status"] = "unmapped"
        elif not isinstance(result, str) or not result.strip():
            outcome["status"] = "empty"
        else:
            try:
                outcome["parsed"] = parser(result)
                outcome["status"] = "parsed"
            except Exception as exc:
                outcome["status"] = "parser_raised"
                outcome["parser_error"] = f"{type(exc).__name__}: {exc}"
        outcomes.append(outcome)
    return outcomes


def _summary_line(outcome: dict[str, Any]) -> str:
    marks = {
        "parsed": "ok  ",
        "empty": "SKIP",
        "unmapped": "----",
        "parser_raised": "FAIL",
    }
    detail = outcome.get("parser_error") or outcome.get("collection_error") or ""
    if outcome["status"] == "parsed":
        parsed = outcome.get("parsed")
        if isinstance(parsed, (dict, list)):
            detail = f"{len(parsed)} entries"
        else:
            detail = str(parsed)
    return (
        f"{marks.get(outcome['status'], '????')} "
        f"{str(outcome.get('run_id') or '-'):<20} "
        f"{outcome['command']:<28} {detail}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "source",
        type=Path,
        help="run ZIP, support bundle, capture directory, or capture JSONL",
    )
    parser.add_argument(
        "--command",
        action="append",
        default=[],
        help="replay only this command; repeatable",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="text prints one line per command, json prints the parsed values",
    )
    parser.add_argument(
        "--failures-only",
        action="store_true",
        help="report only commands that failed to collect or to parse",
    )
    args = parser.parse_args(argv)
    if not args.source.exists():
        parser.error(f"{args.source} does not exist")

    only = set(args.command) or None
    outcomes: list[dict[str, Any]] = []
    for _origin, record in iter_capture_records(args.source):
        outcomes.extend(replay_record(record, only))
    if args.failures_only:
        outcomes = [
            outcome
            for outcome in outcomes
            if outcome["status"] == "parser_raised" or outcome["collected_ok"] is False
        ]

    if args.format == "json":
        json.dump(outcomes, sys.stdout, ensure_ascii=False, indent=2, default=str)
        sys.stdout.write("\n")
    else:
        for outcome in outcomes:
            print(_summary_line(outcome))
        failures = sum(1 for outcome in outcomes if outcome["status"] == "parser_raised")
        print(f"\n{len(outcomes)} commands replayed, {failures} parser failures")
    return 1 if any(o["status"] == "parser_raised" for o in outcomes) else 0


if __name__ == "__main__":
    raise SystemExit(main())
