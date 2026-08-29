#!/usr/bin/env python3
"""Generate human-readable per-batch text exports from PBP JSONL evidence."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterable, Sequence


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    try:
        return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)


def _payload_sections(name: str, payload: Any) -> list[str]:
    lines = [f"=== {name} ==="]
    if not isinstance(payload, dict):
        lines.extend(("", _text(payload), ""))
        return lines

    lines.extend(
        (
            f"Status: {'OK' if payload.get('ok') is True else 'ERROR'}",
            f"Started: {_text(payload.get('started_at')) or '-'}",
            f"Finished: {_text(payload.get('finished_at')) or '-'}",
            f"Duration seconds: {_text(payload.get('duration_seconds')) or '-'}",
        )
    )
    error = payload.get("error")
    if error not in (None, ""):
        lines.extend(("", "--- ERROR ---", _text(error)))
    lines.extend(("", "--- RESULT ---", _text(payload.get("result"))))
    raw_response = payload.get("raw_response")
    if raw_response not in (None, ""):
        lines.extend(
            ("", "--- RAW HTTP XML RESPONSE ---", _text(raw_response))
        )
    lines.append("")
    return lines


def render_record_text(record: dict[str, Any]) -> str:
    """Render one startup or cycle record without dropping raw command data."""
    cycle = record.get("cycle")
    title = "PBP MONITORING STARTUP" if cycle is None else "PBP MONITORING BATCH"
    lines = [
        title,
        "=" * len(title),
        f"Run ID: {_text(record.get('run_id')) or '-'}",
        f"Target: {_text(record.get('target_name')) or '-'}",
        f"Batch: {_text(cycle) or '-'}",
        f"Collector time: {_text(record.get('timestamp')) or '-'}",
        f"Completed time: {_text(record.get('completed_at')) or '-'}",
        f"Firewall time: {_text(record.get('firewall_clock')) or '-'}",
        f"Elapsed seconds: {_text(record.get('elapsed_seconds')) or '-'}",
        f"Cycle duration seconds: {_text(record.get('cycle_duration_seconds')) or '-'}",
        "",
    ]

    commands = record.get("commands")
    if isinstance(commands, dict):
        for name, payload in commands.items():
            lines.extend(_payload_sections(f"COMMAND: {name}", payload))
    elif commands not in (None, ""):
        lines.extend(_payload_sections("COMMANDS", commands))

    details = record.get("session_details")
    if isinstance(details, dict):
        for session_id, payload in details.items():
            lines.extend(_payload_sections(f"SESSION: {session_id}", payload))
    elif details not in (None, "", {}):
        lines.extend(_payload_sections("SESSION DETAILS", details))

    return "\n".join(lines).rstrip() + "\n"


def _write_atomic_private(path: Path, content: str) -> Path:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix":
            os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
        temporary_path = None
        if os.name == "posix":
            os.chmod(path, 0o600)
        return path
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def write_record_text_export(
    incident_path: Path,
    record: dict[str, Any],
    *,
    sequence: int | None = None,
    output_dir: Path | None = None,
) -> Path | None:
    """Write the text file corresponding to one startup or cycle record."""
    if record.get("event") == "monitor_started":
        filename = "startup.txt"
    elif record.get("cycle") is not None:
        try:
            cycle = int(record["cycle"])
        except (TypeError, ValueError):
            cycle = sequence
        if cycle is None or cycle < 0:
            return None
        filename = f"batch-{cycle:04d}.txt"
    else:
        return None
    return _write_atomic_private(
        (Path(output_dir) if output_dir else Path(incident_path).parent / "raw")
        / filename,
        render_record_text(record),
    )


def _records(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8-sig") as handle:
        for line in handle:
            try:
                value = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(value, dict):
                yield value


def export_jsonl_text(jsonl_path: Path, output_dir: Path | None = None) -> list[Path]:
    """Rebuild startup and batch text files from an existing JSONL capture."""
    source = Path(jsonl_path)
    destination = Path(output_dir) if output_dir else source.parent / "raw"
    written: list[Path] = []
    cycle_sequence = 0
    for record in _records(source):
        if record.get("cycle") is not None:
            cycle_sequence += 1
        path = write_record_text_export(
            source,
            record,
            sequence=cycle_sequence or None,
            output_dir=destination,
        )
        if path is not None:
            written.append(path)
    return written


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export human-readable startup and batch TXT files from JSONL."
    )
    parser.add_argument("capture", type=Path, help="incident or API-check JSONL")
    parser.add_argument("-o", "--output-dir", type=Path, help="TXT output directory")
    args = parser.parse_args(argv)
    try:
        written = export_jsonl_text(args.capture, args.output_dir)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"error: {exc}\n")
    print(f"{len(written)} text files written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
