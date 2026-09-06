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
from typing import Any, Callable, Iterator, NamedTuple

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from pbp_monitoring.orchestrator import (  # noqa: E402
    extract_buffer_latency,
    extract_congestion_log_entries,
    extract_dataplane_pool_statistics,
    extract_dp_core_functions,
    extract_firewall_clock,
    extract_global_counters,
    extract_global_counters_raw,
    extract_ha_state,
    extract_ingress_backlogs,
    extract_interface_counter_table,
    extract_interface_counters,
    extract_interface_status,
    extract_large_sessions,
    extract_pbp_offenders,
    extract_pbp_settings,
    extract_pbp_status,
    extract_pbp_threat_log_entries,
    extract_resource_cpu_cores,
    extract_resource_monitor_history,
    extract_session_filter_count,
    extract_session_filter_entries,
    extract_session_info,
    extract_system_info,
    extract_traffic_log_entries,
    extract_zone_protection,
)

#: Which parser owns which stored command. A command absent from this table is
#: reported as unmapped rather than silently skipped: a new command that never
#: gets a replay entry is exactly the one nobody can diagnose remotely.
PARSERS: dict[str, Callable[[str], Any]] = {
    "system_info": extract_system_info,
    "pbp_settings": extract_pbp_settings,
    "clock": extract_firewall_clock,
    "buffer_latency": extract_buffer_latency,
    "packet_buffer_protection": extract_pbp_offenders,
    "ingress_backlogs": extract_ingress_backlogs,
    "dataplane_pool_statistics": extract_dataplane_pool_statistics,
    "global_counters_delta": extract_global_counters,
    "global_counters_baseline": extract_global_counters,
    "session_info": extract_session_info,
    "large_sessions": extract_large_sessions,
    "dp_core_functions": extract_dp_core_functions,
    "resource_monitor": extract_resource_cpu_cores,
    "resource_monitor_history": extract_resource_monitor_history,
    "interface_counters": extract_interface_counters,
    "interface_counters_all": extract_interface_counter_table,
    "interface_status": extract_interface_status,
    "global_counters_raw": extract_global_counters_raw,
    "zone_protection": extract_zone_protection,
    "ha_state": extract_ha_state,
    "session_filter_count": extract_session_filter_count,
    "session_filter_list": extract_session_filter_entries,
}


class RawResponseEvent(NamedTuple):
    """How one journal event stores a raw PAN-OS response, and who parses it."""

    #: The parser that owns the stored XML.
    parser: Callable[[str], Any]
    #: The list field holding one response per entry, or None when the event
    #: carries a single `raw_response` at its root.
    container: str | None
    #: The field naming an entry of that list, for the replay line.
    label_field: str = "source_ip"


#: Events that keep a raw PAN-OS response outside the per-command table. The
#: log queries run at monitor stop are not `commands`: they store their XML on
#: the journal record itself, so replaying only `record["commands"]` would skip
#: exactly the evidence a customer archive was collected for.
RAW_RESPONSE_EVENTS: dict[str, RawResponseEvent] = {
    "pbp_threat_logs": RawResponseEvent(extract_pbp_threat_log_entries, None),
    "offender_traffic_logs": RawResponseEvent(extract_traffic_log_entries, "sources"),
    "offender_live_sessions": RawResponseEvent(
        extract_session_filter_entries, "sources"
    ),
    "congestion_system_logs": RawResponseEvent(
        extract_congestion_log_entries, None
    ),
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


def _replay_one(
    record: dict[str, Any],
    name: str,
    payload: dict[str, Any],
    parser: Callable[[str], Any] | None,
    stored_xml: Any,
) -> dict[str, Any]:
    """Hand one stored response to its parser and describe what came back."""
    outcome: dict[str, Any] = {
        "run_id": record.get("run_id"),
        "timestamp": record.get("timestamp"),
        "command": name,
        "collected_ok": payload.get("ok"),
        "collection_error": payload.get("error"),
    }
    if parser is None:
        outcome["status"] = "unmapped"
    elif not isinstance(stored_xml, str) or not stored_xml.strip():
        outcome["status"] = "empty"
    else:
        try:
            outcome["parsed"] = parser(stored_xml)
            outcome["status"] = "parsed"
        except Exception as exc:
            outcome["status"] = "parser_raised"
            outcome["parser_error"] = f"{type(exc).__name__}: {exc}"
    return outcome


def replay_event_raw_responses(
    record: dict[str, Any], only: set[str] | None
) -> list[dict[str, Any]]:
    """Re-parse the raw responses a journal event stores outside `commands`.

    The log queries run at monitor stop are the firewall's own designation of
    the incident. They never travel as commands, so without this they would be
    the one piece of a customer archive nobody could replay.
    """
    event = record.get("event")
    mapping = RAW_RESPONSE_EVENTS.get(event) if isinstance(event, str) else None
    if mapping is None or (only and event not in only):
        return []
    if mapping.container is None:
        entries: list[tuple[str, dict[str, Any]]] = [(str(event), record)]
    else:
        stored = record.get(mapping.container)
        entries = [
            (
                f"{event}[{entry.get(mapping.label_field) or index}]",
                entry,
            )
            for index, entry in enumerate(stored if isinstance(stored, list) else [])
            if isinstance(entry, dict)
        ]
    return [
        _replay_one(record, name, entry, mapping.parser, entry.get("raw_response"))
        for name, entry in entries
    ]


def replay_record(record: dict[str, Any], only: set[str] | None) -> list[dict[str, Any]]:
    """Re-parse every stored response of one record, command or event."""
    outcomes = replay_event_raw_responses(record, only)
    commands = record.get("commands")
    if not isinstance(commands, dict):
        return outcomes
    for name, payload in sorted(commands.items()):
        if only and name not in only:
            continue
        if not isinstance(payload, dict):
            continue
        outcomes.append(
            _replay_one(
                record, name, payload, PARSERS.get(name), payload.get("result")
            )
        )
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
        help="replay only this command or log-query event; repeatable",
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
