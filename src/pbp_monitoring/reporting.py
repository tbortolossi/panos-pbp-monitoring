#!/usr/bin/env python3
"""Generate a self-contained HTML report from a PBP incident JSONL capture."""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import math
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from . import __version__

_COMMAND_RESULT_KEYS = ("error", "result", "raw_response")
_COMMAND_METADATA_KEYS = ("ok", "started_at", "finished_at", "duration_seconds")
_METRICS = (
    ("packet_buffer_congestion", "PBP congestion"),
    ("dataplane_pool_packet_buffer_used", "Dataplane packet buffers used"),
    ("descriptor_atomic", "Descriptor ATOMIC"),
    ("descriptor_total", "Descriptor TOTAL"),
    ("resource_monitor_dp_cpu", "Dataplane CPU"),
    ("resource_monitor_session", "Session table"),
    ("resource_monitor_packet_buffer", "Resource monitor packet buffer"),
    ("resource_monitor_packet_descriptor", "Resource monitor descriptor"),
    (
        "resource_monitor_packet_descriptor_on_chip",
        "Resource monitor descriptor on-chip",
    ),
    ("resource_monitor_sw_tags_descriptor", "Resource monitor SW tags descriptor"),
)
_METRIC_CARD_GROUPS = (
    (
        "Packet buffers",
        (
            ("packet_buffer_congestion", "PBP congestion"),
            ("dataplane_pool_packet_buffer_used", "DP pool used"),
            ("resource_monitor_packet_buffer", "Resource monitor"),
        ),
    ),
    (
        "Packet descriptors",
        (
            ("descriptor_atomic", "Ingress ATOMIC"),
            ("descriptor_total", "Ingress TOTAL"),
            ("resource_monitor_packet_descriptor", "Resource monitor"),
            ("resource_monitor_packet_descriptor_on_chip", "On-chip"),
            ("resource_monitor_sw_tags_descriptor", "SW tags"),
        ),
    ),
    (
        "System load",
        (
            ("resource_monitor_dp_cpu", "Dataplane CPU"),
            ("resource_monitor_session", "Session table"),
        ),
    ),
)


def _display_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return "null"
    try:
        return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)


def _escape(value: Any) -> str:
    """Convert dynamic data to escaped text safe for HTML text and attributes."""
    return html.escape(_display_text(value), quote=True)


def _read_jsonl(path: Path) -> tuple[list[tuple[int, dict[str, Any]]], list[str], str]:
    records: list[tuple[int, dict[str, Any]]] = []
    warnings: list[str] = []
    digest = hashlib.sha256()
    first_content_line = True

    with path.open("rb") as handle:
        for line_number, raw_line in enumerate(handle, 1):
            digest.update(raw_line)
            if not raw_line.strip():
                warnings.append(f"Empty line {line_number} ignored.")
                continue

            try:
                encoding = "utf-8-sig" if first_content_line else "utf-8"
                line = raw_line.decode(encoding)
            except UnicodeDecodeError:
                line = raw_line.decode("utf-8", errors="replace")
                warnings.append(
                    f"Line {line_number}: invalid UTF-8 bytes replaced."
                )
            first_content_line = False

            try:
                value = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                warnings.append(
                    f"Line {line_number} ignored: invalid or truncated JSON."
                )
                continue

            if not isinstance(value, dict):
                warnings.append(
                    f"Line {line_number} ignored: record is not an object."
                )
                continue
            records.append((line_number, value))

    return records, warnings, digest.hexdigest()


def _is_cycle(record: dict[str, Any]) -> bool:
    event = str(record.get("event", "")).strip().lower()
    if event:
        return event in {"batch", "cycle", "monitor_cycle", "snapshot"}
    return any(
        key in record
        for key in (
            "commands",
            "elapsed_seconds",
            "percentages",
            "candidate_session_ids",
            "session_details",
        )
    )


def _command_items(commands: Any) -> list[tuple[str, Any]]:
    """Normalize legacy strings and structured command response mappings."""
    if isinstance(commands, dict):
        # A command response can itself be the value of ``commands``.
        if any(key in commands for key in _COMMAND_RESULT_KEYS):
            return [("command", commands)]
        return [(str(name), value) for name, value in commands.items()]
    if commands is None:
        return []
    return [("commands", commands)]


def _payload_parts(payload: Any) -> list[tuple[str | None, Any]]:
    if not isinstance(payload, dict):
        return [(None, payload)]

    ordered_keys = [
        key
        for key in _COMMAND_RESULT_KEYS
        if key in payload
        and not (
            key == "error"
            and payload[key] in (None, "", False, [], {})
        )
    ]
    ordered_keys.extend(key for key in payload if key not in _COMMAND_RESULT_KEYS)
    return [(str(key), payload[key]) for key in ordered_keys]


def _contains_error(payload: Any) -> bool:
    if isinstance(payload, str):
        return payload.lstrip().upper().startswith("ERROR:")
    if isinstance(payload, dict):
        error = payload.get("error")
        if error not in (None, "", False, [], {}):
            return True
        if payload.get("ok") is False:
            return True
        status = str(payload.get("status", "")).strip().lower()
        return status in {"error", "failed", "failure"}
    return False


def _numbers(value: Any) -> Iterable[float]:
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, (int, float)):
        try:
            number = float(value)
        except OverflowError:
            return
        if math.isfinite(number):
            yield number
        return
    if isinstance(value, str):
        try:
            number = float(value.strip())
        except (OverflowError, ValueError):
            return
        if math.isfinite(number):
            yield number
        return
    if isinstance(value, dict):
        for nested in value.values():
            yield from _numbers(nested)
        return
    if isinstance(value, (list, tuple)):
        for nested in value:
            yield from _numbers(nested)


def _metric_max(record: dict[str, Any], key: str) -> float | None:
    percentages = record.get("percentages")
    if not isinstance(percentages, dict) or key not in percentages:
        return None
    values = list(_numbers(percentages[key]))
    return max(values) if values else None


def _format_number(value: float | int | None) -> str:
    if value is None:
        return "—"
    if float(value).is_integer():
        return str(int(value))
    return f"{value:.2f}".rstrip("0").rstrip(".")


# PAN-OS packet buffer protection defaults: alert at 50 %, activate at 80 %.
_PBP_ALERT_PERCENT = 50.0
_PBP_ACTIVATE_PERCENT = 80.0

_STOP_REASON_LABELS = {
    "resources_recovered": "Resources recovered",
    "maximum_duration": "Maximum duration reached",
    "api_check_complete": "API check complete",
    "monitor_stopped": "Monitor stopped",
    "stopped": "Monitor stopped",
}


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None


def _human_timestamp(value: Any) -> str:
    """Render an ISO timestamp as ``YYYY-MM-DD HH:MM:SS UTC`` for reading."""
    parsed = _parse_timestamp(value)
    if parsed is None:
        return _display_text(value) if value not in (None, "") else "—"
    zone = parsed.strftime("%z")
    if parsed.tzinfo is None:
        suffix = ""
    elif zone in ("+0000", "-0000"):
        suffix = " UTC"
    else:
        suffix = f" UTC{zone[:3]}:{zone[3:]}"
    return parsed.strftime("%Y-%m-%d %H:%M:%S") + suffix


def _clock_time(value: Any) -> str:
    """Keep only the time of day; the full value stays available on hover."""
    parsed = _parse_timestamp(value)
    if parsed is None:
        return _display_text(value) if value not in (None, "") else "—"
    return parsed.strftime("%H:%M:%S")


def _time_cell(value: Any) -> str:
    """A clock-time ``<time>`` whose tooltip carries the full timestamp."""
    if value in (None, ""):
        return "—"
    return (
        f'<time datetime="{_escape(value)}" title="{_escape(value)}">'
        f"{_escape(_clock_time(value))}</time>"
    )


def _human_duration(seconds: float | int | None) -> str:
    if seconds is None:
        return "—"
    total = float(seconds)
    if total < 60:
        return f"{_format_number(round(total, 2))} s"
    minutes, remainder = divmod(int(round(total)), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours} h {minutes:02d} min"
    return f"{minutes} min {remainder:02d} s"


def _stop_reason_label(reason: Any) -> str:
    text = _display_text(reason)
    return _STOP_REASON_LABELS.get(text, text.replace("_", " ").capitalize())


def _level(value: float | int | None) -> str:
    """Classify a utilization percentage against the PBP thresholds."""
    if value is None:
        return "none"
    if float(value) >= _PBP_ACTIVATE_PERCENT:
        return "bad"
    if float(value) >= _PBP_ALERT_PERCENT:
        return "warn"
    return "ok"


def _severity(peak: float | None) -> tuple[str, str, str]:
    """Name the incident severity from the peak packet-buffer pressure."""
    if peak is None:
        return (
            "unknown",
            "Pressure unknown",
            "No packet-buffer percentage was collected, so the pressure level "
            "cannot be stated; read the batch details for the raw responses.",
        )
    if peak >= _PBP_ACTIVATE_PERCENT:
        return (
            "bad",
            "Critical pressure",
            f"Packet buffers peaked at {_format_number(peak)}%, at or above the "
            f"{_format_number(_PBP_ACTIVATE_PERCENT)}% PBP activate level: the "
            "firewall was discarding packets to protect itself.",
        )
    if peak >= _PBP_ALERT_PERCENT:
        return (
            "warn",
            "Elevated pressure",
            f"Packet buffers peaked at {_format_number(peak)}%, between the "
            f"{_format_number(_PBP_ALERT_PERCENT)}% alert and the "
            f"{_format_number(_PBP_ACTIVATE_PERCENT)}% activate levels: PAN-OS "
            "raised alerts without discarding packets by itself.",
        )
    return (
        "ok",
        "Low pressure",
        f"Packet buffers peaked at {_format_number(peak)}%, below the "
        f"{_format_number(_PBP_ALERT_PERCENT)}% PBP alert level. If PBP still "
        "engaged, its thresholds are set lower than the PAN-OS defaults.",
    )


def _resource_cpu_samples(record: dict[str, Any]) -> list[dict[str, Any]]:
    raw_samples = record.get("resource_monitor_cpu_cores")
    if not isinstance(raw_samples, list):
        return []
    samples: list[dict[str, Any]] = []
    for raw_sample in raw_samples:
        if not isinstance(raw_sample, dict):
            continue
        values = list(_numbers(raw_sample.get("utilization")))
        if not values or raw_sample.get("core_id") in (None, ""):
            continue
        samples.append(
            {
                "dataplane": str(raw_sample.get("dataplane") or "dp0"),
                "core_id": str(raw_sample["core_id"]),
                "utilization": values[0],
                "average": next(
                    iter(_numbers(raw_sample.get("average"))), values[0]
                ),
                "maximum": next(
                    iter(_numbers(raw_sample.get("maximum"))), values[0]
                ),
                "window_average": next(
                    iter(_numbers(raw_sample.get("window_average"))), values[0]
                ),
                "window_peak": next(
                    iter(_numbers(raw_sample.get("window_peak"))), values[0]
                ),
                "hot_points": int(
                    next(
                        iter(_numbers(raw_sample.get("seconds_at_or_above_90"))),
                        1 if values[0] >= 90 else 0,
                    )
                ),
                "sample_count": int(
                    next(iter(_numbers(raw_sample.get("sample_count"))), 1)
                ),
            }
        )
    return samples


def _core_sort_key(identity: tuple[str, str]) -> tuple[str, int, str]:
    dataplane, core_id = identity
    try:
        numeric_core = int(core_id)
    except ValueError:
        numeric_core = 10**9
    return dataplane, numeric_core, core_id


_HEAT_SCALE = (
    (10.0, "#eef2f7", "0-10"),
    (25.0, "#dbeafe", "10-25"),
    (50.0, "#bfdbfe", "25-50"),
    (70.0, "#fde68a", "50-70"),
    (85.0, "#fb923c", "70-85"),
    (95.0, "#ef4444", "85-95"),
    (float("inf"), "#991b1b", "95-100"),
)
_SERIES_COLORS = ("#b91c1c", "#c2410c", "#a16207", "#0f766e", "#1d4ed8")
_CHART_WIDTH = 920
_HIGHLIGHT_CORES = 5


def _core_roles(core_functions: Sequence[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    """Describe what distinguishes each core from its peers on the same dataplane.

    Every core of a dataplane shares a base set of function groups. Only the
    extra groups explain why one core behaves differently, so those are what the
    charts label.
    """
    by_dataplane: dict[str, list[dict[str, Any]]] = {}
    for entry in core_functions:
        if not isinstance(entry, dict):
            continue
        core_id = entry.get("core_id")
        functions = entry.get("functions")
        if core_id in (None, "") or not isinstance(functions, list):
            continue
        by_dataplane.setdefault(str(entry.get("dataplane") or "dp0"), []).append(
            {
                "core_id": str(core_id),
                "functions": [str(name) for name in functions],
                "forwards_traffic": bool(entry.get("forwards_traffic")),
            }
        )

    roles: dict[tuple[str, str], dict[str, Any]] = {}
    for dataplane, entries in by_dataplane.items():
        forwarding = [
            frozenset(entry["functions"])
            for entry in entries
            if entry["forwards_traffic"] and entry["functions"]
        ]
        sets = forwarding or [
            frozenset(entry["functions"]) for entry in entries if entry["functions"]
        ]
        common = frozenset.intersection(*sets) if sets else frozenset()
        for entry in entries:
            distinctive = sorted(set(entry["functions"]) - common)
            if distinctive:
                label = " + ".join(distinctive[:3])
            elif entry["forwards_traffic"]:
                label = "fastpath only"
            else:
                label = " + ".join(entry["functions"][:3]) or "—"
            roles[(dataplane, entry["core_id"])] = {
                "label": label,
                "functions": entry["functions"],
                "forwards_traffic": entry["forwards_traffic"],
            }
    return roles


def _cpu_series(
    cycles: Sequence[tuple[int, dict[str, Any]]],
) -> tuple[list[tuple[int, str]], dict[tuple[str, str], dict[int, float]]]:
    """Return the sampled batches and the window peak of every core per batch."""
    batches: list[tuple[int, str]] = []
    peaks: dict[tuple[str, str], dict[int, float]] = {}
    for batch_number, (_, record) in enumerate(cycles, 1):
        samples = _resource_cpu_samples(record)
        if not samples:
            continue
        batches.append((batch_number, str(record.get("timestamp") or "—")))
        for sample in samples:
            identity = (sample["dataplane"], sample["core_id"])
            peaks.setdefault(identity, {})[batch_number] = sample["window_peak"]
    return batches, peaks


def _heat_colour(value: float) -> str:
    for limit, colour, _ in _HEAT_SCALE:
        if value < limit:
            return colour
    return _HEAT_SCALE[-1][1]


def _median(values: Sequence[float]) -> float:
    ordered = sorted(values)
    count = len(ordered)
    middle = count // 2
    if count % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2


def _core_label(dataplane: str, core_id: str, roles: dict[tuple[str, str], dict[str, Any]]) -> str:
    role = roles.get((dataplane, core_id))
    if role:
        return f"core {core_id} · {role['label']}"
    return f"core {core_id}"


def _core_roles_recall(
    dataplane: str,
    cores: Sequence[str],
    roles: dict[tuple[str, str], dict[str, Any]],
) -> str:
    """State once what each core does, so the charts can label by number alone."""
    chips = [
        f'<span class="key">{_escape(_core_label(dataplane, core_id, roles))}</span>'
        for core_id in cores
        if roles.get((dataplane, core_id))
    ]
    if not chips:
        return ""
    return (
        '<p class="chart-legend core-roles">'
        '<span class="key core-roles-title">Core functions:</span>'
        f'{"".join(chips)}</p>'
    )


def _line_chart(
    dataplane: str,
    batches: Sequence[tuple[int, str]],
    cores: Sequence[str],
    peaks: dict[tuple[str, str], dict[int, float]],
    comparable: Sequence[str],
) -> str:
    """Plot every core, highlighting the hottest, against the median of its peers."""
    left, right, top, bottom = 46, 18, 16, 34
    height = 250
    count = len(batches)
    plot_width = _CHART_WIDTH - left - right
    step = plot_width / (count - 1) if count > 1 else 0.0

    def x_at(index: int) -> float:
        if count == 1:
            return left + plot_width / 2
        return left + index * step

    def y_at(value: float) -> float:
        bounded = max(0.0, min(100.0, value))
        return top + (100.0 - bounded) * (height - top - bottom) / 100.0

    def path_for(core_id: str) -> tuple[str, list[tuple[float, float]]]:
        series = peaks.get((dataplane, core_id), {})
        points = [
            (x_at(index), y_at(series[batch_number]))
            for index, (batch_number, _) in enumerate(batches)
            if batch_number in series
        ]
        return " ".join(f"{x:.1f},{y:.1f}" for x, y in points), points

    parts: list[str] = []
    for gridline in (0, 25, 50, 75, 100):
        y = y_at(gridline)
        parts.append(
            f'<line x1="{left}" y1="{y:.1f}" x2="{_CHART_WIDTH - right}" y2="{y:.1f}" '
            'stroke="#e2e8f0" stroke-width="1"/>'
            f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end" class="axis">{gridline}%</text>'
        )

    tick_stride = max(1, math.ceil(count / 12))
    for index, (batch_number, _) in enumerate(batches):
        if index % tick_stride and index != count - 1:
            continue
        parts.append(
            f'<text x="{x_at(index):.1f}" y="{height - 12}" text-anchor="middle" '
            f'class="axis">{_escape(batch_number)}</text>'
        )

    ranking = sorted(
        cores,
        key=lambda core_id: max(peaks.get((dataplane, core_id), {}).values(), default=0.0),
        reverse=True,
    )
    highlighted = ranking[:_HIGHLIGHT_CORES]
    for core_id in cores:
        if core_id in highlighted:
            continue
        points, _ = path_for(core_id)
        if points:
            parts.append(
                f'<polyline points="{points}" fill="none" stroke="#cbd5e1" stroke-width="1"/>'
            )

    if len(comparable) > 2:
        median_points = []
        for index, (batch_number, _) in enumerate(batches):
            values = [
                peaks[(dataplane, core_id)][batch_number]
                for core_id in comparable
                if batch_number in peaks.get((dataplane, core_id), {})
            ]
            if values:
                median_points.append((x_at(index), y_at(_median(values))))
        if median_points:
            joined = " ".join(f"{x:.1f},{y:.1f}" for x, y in median_points)
            parts.append(
                f'<polyline points="{joined}" fill="none" stroke="#0f172a" '
                'stroke-width="1.6" stroke-dasharray="6 4"/>'
            )

    legend: list[str] = []
    for position, core_id in enumerate(highlighted):
        colour = _SERIES_COLORS[position % len(_SERIES_COLORS)]
        points, coordinates = path_for(core_id)
        if not points:
            continue
        if len(coordinates) == 1:
            x, y = coordinates[0]
            parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="{colour}"/>')
        else:
            parts.append(
                f'<polyline points="{points}" fill="none" stroke="{colour}" stroke-width="2"/>'
            )
        legend.append(
            f'<span class="key"><i style="background:{colour}"></i>'
            f'core {_escape(core_id)}</span>'
        )
    if len(comparable) > 2:
        legend.append(
            '<span class="key"><i class="dashed"></i>median of comparable cores</span>'
        )
    legend.append('<span class="key"><i style="background:#cbd5e1"></i>other cores</span>')

    title = f"Window peak CPU per core on {dataplane}, batch by batch"
    return (
        f'<svg class="chart" viewBox="0 0 {_CHART_WIDTH} {height}" width="{_CHART_WIDTH}" '
        f'height="{height}" role="img" aria-label="{_escape(title)}">'
        f"<title>{_escape(title)}</title>{''.join(parts)}</svg>"
        f'<p class="chart-legend">{"".join(legend)}</p>'
        '<p class="muted chart-caption">Horizontal axis: batch number. Vertical axis: '
        "window peak CPU.</p>"
    )


def _heatmap(
    dataplane: str,
    batches: Sequence[tuple[int, str]],
    cores: Sequence[str],
    peaks: dict[tuple[str, str], dict[int, float]],
) -> str:
    """Draw core by batch as coloured cells, which stays readable at 64 cores."""
    label_width = 88
    value_width = 46
    cell_height = 15
    columns = len(batches)
    cell_width = max(5, min(24, (_CHART_WIDTH - label_width - value_width) // max(1, columns)))
    width = label_width + columns * cell_width + value_width
    height = 22 + len(cores) * cell_height

    parts: list[str] = []
    for row, core_id in enumerate(cores):
        y = 22 + row * cell_height
        series = peaks.get((dataplane, core_id), {})
        parts.append(
            f'<text x="0" y="{y + 11}" class="axis heat-label">'
            f'core {_escape(core_id)}</text>'
        )
        for column, (batch_number, timestamp) in enumerate(batches):
            x = label_width + column * cell_width
            if batch_number not in series:
                parts.append(
                    f'<rect x="{x}" y="{y}" width="{cell_width - 1}" '
                    f'height="{cell_height - 1}" fill="#f8fafc" stroke="#e2e8f0"/>'
                )
                continue
            value = series[batch_number]
            parts.append(
                f'<rect x="{x}" y="{y}" width="{cell_width - 1}" height="{cell_height - 1}" '
                f'fill="{_heat_colour(value)}">'
                f"<title>{_escape(f'batch {batch_number} · core {core_id} · ')}"
                f"{_escape(_format_number(value))}% · {_escape(timestamp)}</title></rect>"
            )
        peak = max(series.values(), default=None)
        parts.append(
            f'<text x="{width}" y="{y + 11}" text-anchor="end" class="axis">'
            f"{_escape(_format_number(peak))}%</text>"
        )

    for column, (batch_number, _) in enumerate(batches):
        if column % max(1, math.ceil(columns / 16)) and column != columns - 1:
            continue
        parts.append(
            f'<text x="{label_width + column * cell_width + cell_width / 2:.1f}" y="14" '
            f'text-anchor="middle" class="axis">{_escape(batch_number)}</text>'
        )

    scale = "".join(
        f'<span class="key"><i style="background:{colour}"></i>{label}%</span>'
        for _, colour, label in _HEAT_SCALE
    )
    title = f"Window peak CPU heatmap for {dataplane}"
    return (
        f'<svg class="chart" viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
        f'role="img" aria-label="{_escape(title)}">'
        f"<title>{_escape(title)}</title>{''.join(parts)}</svg>"
        f'<p class="chart-legend">{scale}</p>'
        '<p class="muted chart-caption">One row per core, one column per batch. The '
        "rightmost figure is the highest window peak the core reached during the run.</p>"
    )


def _dataplane_verdict(
    dataplane: str,
    batches: Sequence[tuple[int, str]],
    comparable: Sequence[str],
    peaks: dict[tuple[str, str], dict[int, float]],
    labelled: bool,
) -> str:
    """State whether the load rose on every comparable core or on a few of them."""
    if len(comparable) < 2:
        return (
            '<p class="muted">Only one comparable core was sampled on '
            f"{_escape(dataplane)}, so a hot core cannot be told apart from overall load.</p>"
        )

    hottest_batch = None
    hottest_value = -1.0
    hottest_core = ""
    for batch_number, _ in batches:
        for core_id in comparable:
            value = peaks.get((dataplane, core_id), {}).get(batch_number)
            if value is not None and value > hottest_value:
                hottest_value, hottest_batch, hottest_core = value, batch_number, core_id
    if hottest_batch is None:
        return ""

    values = [
        peaks[(dataplane, core_id)][hottest_batch]
        for core_id in comparable
        if hottest_batch in peaks.get((dataplane, core_id), {})
    ]
    median = _median(values)
    spread = hottest_value - median
    above_half = sum(1 for value in values if value >= hottest_value / 2)

    if hottest_value < 60:
        verdict = "No core came close to saturation during this capture."
        state = "calm"
    elif spread >= 40 and above_half <= max(1, len(values) // 4):
        verdict = (
            f"Core {_escape(hottest_core)} peaked at "
            f"{_escape(_format_number(hottest_value))}% while the median comparable core "
            f"stayed at {_escape(_format_number(median))}%. An isolated hot core is what "
            "flow-hash concentration looks like, so a single high-rate session is worth "
            "checking against the offender and session-rate evidence."
        )
        state = "isolated"
    elif spread < 20:
        verdict = (
            f"Every comparable core moved together, peaking at "
            f"{_escape(_format_number(hottest_value))}% against a median of "
            f"{_escape(_format_number(median))}%. That is aggregate load rather than one "
            "session pinned to a core."
        )
        state = "collective"
    else:
        verdict = (
            f"Core {_escape(hottest_core)} led at "
            f"{_escape(_format_number(hottest_value))}% with a median of "
            f"{_escape(_format_number(median))}%. Several cores are loaded and the pattern "
            "is not conclusive on its own."
        )
        state = "mixed"

    note = (
        ""
        if labelled
        else (
            " Core function groups were not collected, so every sampled core is compared, "
            "including any that never forward traffic."
        )
    )
    return (
        f'<p class="verdict verdict-{state}"><strong>{_escape(dataplane)} · batch '
        f"{_escape(hottest_batch)}</strong> — {verdict}{note}</p>"
    )


def _render_cpu_charts(
    cycles: Sequence[tuple[int, dict[str, Any]]],
    core_functions: Sequence[dict[str, Any]],
) -> str:
    batches, peaks = _cpu_series(cycles)
    if not batches or not peaks:
        return ""
    roles = _core_roles(core_functions)

    dataplanes: dict[str, list[str]] = {}
    for dataplane, core_id in peaks:
        dataplanes.setdefault(dataplane, []).append(core_id)

    sections: list[str] = []
    for dataplane in sorted(dataplanes):
        cores = sorted(
            dataplanes[dataplane],
            key=lambda core_id: _core_sort_key((dataplane, core_id)),
        )
        forwarding = [
            core_id
            for core_id in cores
            if roles.get((dataplane, core_id), {}).get("forwards_traffic")
        ]
        labelled = bool(forwarding)
        comparable = forwarding or cores
        sections.append(
            f'<h3>{_escape(dataplane)} <span class="muted">· {_escape(len(cores))} cores'
            + (
                f", {_escape(len(forwarding))} forwarding traffic"
                if labelled
                else ", function groups unavailable"
            )
            + "</span></h3>"
            + _core_roles_recall(dataplane, cores, roles)
            + _dataplane_verdict(dataplane, batches, comparable, peaks, labelled)
            + _line_chart(dataplane, batches, cores, peaks, comparable)
            + _heatmap(dataplane, batches, cores, peaks)
        )
    return "".join(sections)


def _render_cpu_tracking(
    cycles: Sequence[tuple[int, dict[str, Any]]],
    core_functions: Sequence[dict[str, Any]] = (),
) -> str:
    roles = _core_roles(core_functions)
    per_core: dict[
        tuple[str, str], list[tuple[int, str, float, float, int, int]]
    ] = {}
    timeline_rows: list[str] = []
    for batch_number, (_, record) in enumerate(cycles, 1):
        samples = _resource_cpu_samples(record)
        timestamp = str(record.get("timestamp") or "—")
        for sample in samples:
            identity = (sample["dataplane"], sample["core_id"])
            per_core.setdefault(identity, []).append(
                (
                    batch_number,
                    timestamp,
                    sample["window_average"],
                    sample["window_peak"],
                    sample["hot_points"],
                    sample["sample_count"],
                )
            )
        if not samples:
            continue
        peak = max(sample["window_peak"] for sample in samples)
        minimum = min(sample["window_peak"] for sample in samples)
        average = sum(sample["window_average"] for sample in samples) / len(samples)
        hottest = ", ".join(
            f'{sample["dataplane"]}/core {sample["core_id"]}'
            for sample in samples
            if sample["window_peak"] == peak
        )
        spread = peak - minimum
        signal = "High" if peak >= 90 and spread >= 50 else "—"
        signal_class = " signal-high" if signal == "High" else ""
        timeline_rows.append(
            "<tr>"
            f'<td class="number">{_escape(batch_number)}</td>'
            f'<td>{_time_cell(timestamp)}</td>'
            f'<td>{_escape(hottest)}</td>'
            f'<td class="number">{_escape(_format_number(peak))}</td>'
            f'<td class="number">{_escape(_format_number(average))}</td>'
            f'<td class="number">{_escape(_format_number(spread))}</td>'
            f'<td class="{signal_class.strip()}">{_escape(signal)}</td>'
            "</tr>"
        )

    if not per_core:
        return '<p class="muted">No per-core CPU samples were recorded.</p>'

    core_rows: list[str] = []
    for identity in sorted(per_core, key=_core_sort_key):
        dataplane, core_id = identity
        observations = per_core[identity]
        average_values = [observation[2] for observation in observations]
        maximum_values = [observation[3] for observation in observations]
        peak = max(maximum_values)
        peak_batch, peak_time, _, _, _, _ = next(
            observation for observation in observations if observation[3] == peak
        )
        role = roles.get((dataplane, core_id))
        functions = " ".join(role["functions"]) if role else "—"
        core_rows.append(
            "<tr>"
            f'<td>{_escape(dataplane)}</td>'
            f'<td class="number">{_escape(core_id)}</td>'
            f'<td class="wrap">{_escape(functions)}</td>'
            f'<td class="number">{_escape(len(maximum_values))}</td>'
            f'<td class="number">{_escape(sum(observation[5] for observation in observations))}</td>'
            f'<td class="number">{_escape(_format_number(sum(average_values) / len(average_values)))}</td>'
            f'<td class="number">{_escape(_format_number(peak))}</td>'
            f'<td class="number">{_escape(_format_number(maximum_values[-1]))}</td>'
            f'<td class="number">{_escape(sum(observation[4] for observation in observations))}</td>'
            f'<td>Batch {_escape(peak_batch)}<br><span class="muted">{_time_cell(peak_time)}</span></td>'
            "</tr>"
        )

    return (
        '<p class="muted">Each batch covers the poll interval plus a two-second '
        "safety margin, so adjacent windows overlap. A high max–min spread with "
        "one hot core is useful "
        "corroborating evidence for flow-hash concentration. It does not, by "
        "itself, prove that a single session is responsible.</p>"
        '<h3>Per-core summary</h3><div class="table-wrap"><table><thead><tr>'
        "<th>Dataplane</th><th>Core</th><th>Function groups</th><th>Windows</th>"
        "<th>Returned points</th>"
        "<th>Window average %</th><th>Peak %</th><th>Latest window peak %</th>"
        "<th>Hot points ≥ 90%</th><th>Peak batch</th>"
        f"</tr></thead><tbody>{''.join(core_rows)}</tbody></table></div>"
        '<h3>CPU imbalance timeline</h3><div class="table-wrap"><table><thead><tr>'
        "<th>Batch</th><th>Collector time</th><th>Hottest core</th><th>Max %</th>"
        "<th>Core average %</th><th>Max–min spread</th><th>Imbalance signal</th>"
        f"</tr></thead><tbody>{''.join(timeline_rows)}</tbody></table></div>"
    )


def _candidate_ids(record: dict[str, Any]) -> list[str]:
    values = record.get("candidate_session_ids", [])
    if isinstance(values, (list, tuple, set)):
        return [str(value) for value in values]
    if values in (None, ""):
        return []
    return [str(values)]


def _detail_items(details: Any) -> list[tuple[str, Any]]:
    if isinstance(details, dict):
        return [(str(name), value) for name, value in details.items()]
    if details is None:
        return []
    return [("session_details", details)]


def _record_error_count(record: dict[str, Any]) -> int:
    command_errors = sum(
        _contains_error(payload)
        for _, payload in _command_items(record.get("commands"))
    )
    detail_errors = sum(
        _contains_error(payload)
        for _, payload in _detail_items(record.get("session_details"))
    )
    return command_errors + detail_errors


def _primary_payload_text(payload: Any) -> str:
    if isinstance(payload, dict):
        for key in ("result", "raw_response", "error"):
            if key in payload and payload[key] not in (None, ""):
                return _display_text(payload[key])
    return _display_text(payload)


def _firewall_clock(record: dict[str, Any]) -> str:
    explicit = record.get("firewall_time") or record.get("firewall_clock")
    if explicit:
        return _display_text(explicit)
    for name, payload in _command_items(record.get("commands")):
        normalized = name.lower().replace("-", "_").replace(" ", "_")
        if normalized in {"clock", "show_clock", "system_clock"}:
            text = " ".join(_primary_payload_text(payload).split())
            if len(text) > 120:
                return text[:117] + "…"
            return text
    return ""


def _format_command_timestamp(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return _display_text(value)
    candidate = value.strip()
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        return candidate
    rendered = parsed.isoformat(sep=" ", timespec="milliseconds")
    if rendered.endswith("+00:00"):
        return rendered[:-6] + " UTC"
    return rendered


def _render_command_metadata(payload: dict[str, Any]) -> str:
    if not any(key in payload for key in _COMMAND_METADATA_KEYS):
        return ""

    items: list[tuple[str, str, str]] = []
    if "ok" in payload:
        ok = payload.get("ok")
        if ok is True:
            items.append(("Status", "Success", " good"))
        elif ok is False:
            items.append(("Status", "Failed", " bad"))
        else:
            items.append(("Status", _display_text(ok), ""))
    if "started_at" in payload:
        items.append(("Started", _format_command_timestamp(payload["started_at"]), ""))
    if "finished_at" in payload:
        items.append(("Finished", _format_command_timestamp(payload["finished_at"]), ""))
    if "duration_seconds" in payload:
        duration = next(iter(_numbers(payload["duration_seconds"])), None)
        rendered = (
            f"{_format_number(duration)} s"
            if duration is not None
            else _display_text(payload["duration_seconds"])
        )
        items.append(("Duration", rendered, ""))

    return '<dl class="command-metadata">' + "".join(
        "<div>"
        f"<dt>{_escape(label)}</dt>"
        f'<dd><span class="command-value{state_class}">{_escape(value)}</span></dd>'
        "</div>"
        for label, value, state_class in items
    ) + "</dl>"


def _render_payload(payload: Any) -> str:
    fragments: list[str] = []
    if isinstance(payload, dict):
        fragments.append(_render_command_metadata(payload))
    for label, value in _payload_parts(payload):
        if label in _COMMAND_METADATA_KEYS:
            continue
        if label == "raw_response":
            fragments.append(
                '<details class="exact-response">'
                '<summary>Exact raw API response</summary>'
                f'<pre class="raw">{_escape(value)}</pre></details>'
            )
            continue
        if label is not None:
            display_label = {
                "result": "Extracted result",
                "error": "Error",
            }.get(label, label.replace("_", " ").title())
            fragments.append(f'<h5 class="payload-label">{_escape(display_label)}</h5>')
        error_class = " raw-error" if label == "error" and value not in (None, "", False) else ""
        fragments.append(f'<pre class="raw{error_class}">{_escape(value)}</pre>')
    return "".join(fragments)


def _render_commands(commands: Any) -> str:
    items = _command_items(commands)
    if not items:
        return '<p class="muted">No command output recorded.</p>'

    fragments: list[str] = []
    for name, payload in items:
        state = "Error" if _contains_error(payload) else "Result"
        state_class = " bad" if _contains_error(payload) else ""
        fragments.append(
            '<details class="raw-block">'
            f'<summary><code>{_escape(name)}</code>'
            f'<span class="pill{state_class}">{_escape(state)}</span></summary>'
            f'{_render_payload(payload)}</details>'
        )
    return "".join(fragments)


def _render_session_details(details: Any) -> str:
    items = _detail_items(details)
    if not items:
        return '<p class="muted">No session details for this batch.</p>'

    fragments: list[str] = []
    for session_id, payload in items:
        state_class = " bad" if _contains_error(payload) else ""
        fragments.append(
            '<details class="raw-block">'
            f'<summary>Session <code>{_escape(session_id)}</code>'
            f'<span class="pill{state_class}">'
            f'{_escape("Error" if state_class else "Result")}</span></summary>'
            f'{_render_payload(payload)}</details>'
        )
    return "".join(fragments)


def _aggregate_attribution(
    cycles: list[tuple[int, dict[str, Any]]],
) -> list[dict[str, Any]]:
    aggregated: dict[tuple[str, str], dict[str, Any]] = {}
    insertion_order = 0

    def ensure(entity_type: str, identifier: str) -> dict[str, Any]:
        nonlocal insertion_order
        key = (entity_type, identifier)
        if key not in aggregated:
            insertion_order += 1
            aggregated[key] = {
                "entity_type": entity_type,
                "identifier": identifier,
                "drop_state": False,
                "pbp_percentage": None,
                "pbp_samples": None,
                "ingress_percentage": None,
                "ingress_count": None,
                "best_rank": None,
                "first_seen": None,
                "last_seen": None,
                "evidence_sources": set(),
                "zones": set(),
                "group_ids": set(),
                "session_summary": None,
                "peak_bits_per_second_total": None,
                "latest_bits_per_second_total": None,
                "rate_status": None,
                "ingress_detail": None,
                "_order": insertion_order,
            }
        return aggregated[key]

    def update_max(item: dict[str, Any], key: str, value: Any) -> None:
        numbers = list(_numbers(value))
        if not numbers:
            return
        numeric = max(numbers)
        current = item.get(key)
        item[key] = numeric if current is None else max(float(current), numeric)

    for _, record in cycles:
        timestamp = record.get("timestamp")
        current_entities = record.get("candidate_entities")
        if not isinstance(current_entities, list):
            current_entities = [
                {
                    "entity_type": "session",
                    "session_id": session_id,
                    "evidence_sources": ["raw_session_id"],
                }
                for session_id in _candidate_ids(record)
            ]
        for entity in current_entities:
            if not isinstance(entity, dict):
                continue
            entity_type = str(entity.get("entity_type") or "session")
            identifier_value = (
                entity.get("session_id")
                if entity_type == "session"
                else entity.get("source_ip")
            )
            if identifier_value in (None, ""):
                continue
            item = ensure(entity_type, str(identifier_value))
            item["drop_state"] = item["drop_state"] or bool(
                entity.get("drop_state")
            )
            update_max(item, "pbp_percentage", entity.get("pbp_percentage_total"))
            update_max(item, "pbp_samples", entity.get("pbp_samples"))
            update_max(
                item,
                "ingress_percentage",
                entity.get("ingress_percentage_max"),
            )
            update_max(item, "ingress_count", entity.get("ingress_count"))
            ranks = list(_numbers(entity.get("rank")))
            if ranks:
                rank = int(min(ranks))
                item["best_rank"] = (
                    rank
                    if item["best_rank"] is None
                    else min(int(item["best_rank"]), rank)
                )
            sources = entity.get("evidence_sources", [])
            if isinstance(sources, (list, tuple, set)):
                item["evidence_sources"].update(str(value) for value in sources)
            for field in ("zones", "group_ids"):
                values = entity.get(field, [])
                if isinstance(values, (list, tuple, set)):
                    item[field].update(str(value) for value in values if value)
            if item["first_seen"] is None:
                item["first_seen"] = timestamp
            item["last_seen"] = timestamp

        ingress = record.get("ingress_backlogs")
        ingress_candidates = ingress.get("candidates", []) if isinstance(ingress, dict) else []
        if isinstance(ingress_candidates, list):
            for candidate in ingress_candidates:
                if not isinstance(candidate, dict) or candidate.get("session_id") is None:
                    continue
                item = ensure("session", str(candidate["session_id"]))
                item["ingress_detail"] = candidate

        summaries = record.get("session_summaries")
        if isinstance(summaries, dict):
            for session_id, summary in summaries.items():
                if not isinstance(summary, dict):
                    continue
                item = ensure("session", str(session_id))
                current = item.get("session_summary")
                current_status = current.get("status") if isinstance(current, dict) else None
                new_status = summary.get("status")
                if current is None or new_status == "parsed" or current_status != "parsed":
                    item["session_summary"] = summary

        session_rates = record.get("session_rates")
        if isinstance(session_rates, dict):
            for session_id, rate in session_rates.items():
                if not isinstance(rate, dict):
                    continue
                item = ensure("session", str(session_id))
                item["rate_status"] = rate.get("status")
                bits_per_second = next(
                    iter(_numbers(rate.get("bits_per_second_total"))),
                    None,
                )
                if bits_per_second is not None:
                    item["latest_bits_per_second_total"] = bits_per_second
                    update_max(
                        item,
                        "peak_bits_per_second_total",
                        bits_per_second,
                    )

    def sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
        strongest = max(
            (
                float(value)
                for value in (
                    item.get("pbp_percentage"),
                    item.get("ingress_percentage"),
                )
                if isinstance(value, (int, float))
            ),
            default=0.0,
        )
        return (
            0 if item.get("drop_state") else 1,
            -strongest,
            int(item.get("best_rank") or 10**9),
            int(item["_order"]),
        )

    ranked = sorted(aggregated.values(), key=sort_key)
    for rank, item in enumerate(ranked, 1):
        item["rank"] = rank
        item["evidence_sources"] = sorted(item["evidence_sources"])
        item["zones"] = sorted(item["zones"])
        item["group_ids"] = sorted(item["group_ids"])
        item.pop("_order", None)
    return ranked


def _flow_description(item: dict[str, Any]) -> tuple[str, str]:
    summary = item.get("session_summary")
    ingress = item.get("ingress_detail")
    flow: dict[str, Any] = {}
    application = None
    rule = None
    if isinstance(summary, dict):
        candidate_flow = summary.get("c2s")
        if isinstance(candidate_flow, dict):
            flow = candidate_flow
        application = summary.get("application")
        rule = summary.get("rule")
    if not flow and isinstance(ingress, dict):
        flow = ingress
        application = ingress.get("application")

    source = flow.get("source_ip")
    destination = flow.get("destination_ip")
    source_port = flow.get("source_port")
    destination_port = flow.get("destination_port")
    protocol = flow.get("protocol")
    if source or destination:
        source_text = f"{source or '?'}:{source_port}" if source_port is not None else str(source or "?")
        destination_text = (
            f"{destination or '?'}:{destination_port}"
            if destination_port is not None
            else str(destination or "?")
        )
        tuple_text = f"{source_text} -> {destination_text}"
        if protocol is not None:
            tuple_text += f" / proto {protocol}"
    else:
        tuple_text = "—"
    context = " · ".join(
        value
        for value in (
            f"app {application}" if application else None,
            f"rule {rule}" if rule else None,
        )
        if value
    ) or "—"
    return tuple_text, context


_MAX_RENDERED_ATTRIBUTION_ROWS = 50
_MAX_RENDERED_TOP_SOURCES = 50


def _hidden_rows_note(hidden: int, noun: str) -> str:
    """State how many table rows were left out and where they remain."""
    if hidden <= 0:
        return ""
    return (
        f'<p class="muted">{_escape(_format_number(hidden))} lower-ranked {noun} '
        "not listed; the JSONL capture keeps every ranked entity.</p>"
    )


def _render_attribution_table(attribution: list[dict[str, Any]]) -> str:
    if not attribution:
        return (
            '<p class="muted">No offender session or IP is visible in this capture. '
            "This is normal for an out-of-incident API check; during an early alert, "
            "subsequent batches are still required.</p>"
        )
    source_labels = {
        "packet_buffer_protection": "Primary PBP",
        "ingress_backlogs": "Ingress",
        "syslog_trigger": "Trigger Syslog",
        "raw_session_id": "Raw ID",
    }
    rows = []
    for item in attribution[:_MAX_RENDERED_ATTRIBUTION_ROWS]:
        entity_type = "Session" if item.get("entity_type") == "session" else "Source IP"
        sources = ", ".join(
            source_labels.get(str(source), str(source))
            for source in item.get("evidence_sources", [])
        ) or "—"
        tuple_text, context = _flow_description(item)
        summary = item.get("session_summary")
        status = summary.get("status") if isinstance(summary, dict) else None
        status_labels = {
            "parsed": "enriched",
            "bad_key": "missing session / Bad Key",
            "lookup_failed": "enrichment failed",
            "unparsed": "unrecognized format",
        }
        evidence_context = ", ".join(
            [*item.get("zones", []), *item.get("group_ids", [])]
        ) or "—"
        peak_rate = item.get("peak_bits_per_second_total")
        peak_mbps = (
            _format_number(float(peak_rate) / 1_000_000.0)
            if isinstance(peak_rate, (int, float))
            else "—"
        )
        rows.append(
            "<tr>"
            f'<td class="number">{_escape(item.get("rank"))}</td>'
            f'<td><strong>{_escape(entity_type)}</strong><br><code>{_escape(item.get("identifier"))}</code></td>'
            f'<td class="wrap">{_escape(sources)}<br><span class="muted">{_escape(evidence_context)}</span></td>'
            f'<td>{_escape("Yes" if item.get("drop_state") else "No")}</td>'
            f'<td class="number">{_escape(_format_number(item.get("pbp_percentage")))}</td>'
            f'<td class="number">{_escape(_format_number(item.get("pbp_samples")))}</td>'
            f'<td class="number">{_escape(_format_number(item.get("ingress_percentage")))}</td>'
            f'<td class="number">{_escape(peak_mbps)}</td>'
            f'<td class="wrap"><code>{_escape(tuple_text)}</code><br><span class="muted">{_escape(context)}</span></td>'
            f'<td>{_escape(status_labels.get(status, "not enriched"))}</td>'
            f'<td>{_escape(item.get("first_seen") or "—")}<br>{_escape(item.get("last_seen") or "—")}</td>'
            "</tr>"
        )
    return (
        '<p class="muted">Indicative ranking based on PAN-OS evidence: RED Drop State, '
        "PBP contribution, then ingress corroboration. A slowpath IP may be responsible "
        "without an active session.</p>"
        '<div class="table-wrap"><table><thead><tr>'
        "<th>Rank</th><th>Entity</th><th>Evidence / context</th><th>RED drop</th>"
        "<th>PBP %</th><th>Samples</th><th>Ingress %</th><th>Peak Mbit/s</th><th>5-tuple / application</th>"
        "<th>Session</th><th>First / last seen</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
        + _hidden_rows_note(
            len(attribution) - _MAX_RENDERED_ATTRIBUTION_ROWS, "entries"
        )
    )


_MAX_RENDERED_DROP_COUNTERS = 30


def _drop_counter_family(counter: dict[str, Any]) -> tuple[str, str]:
    """Group a PAN-OS drop counter by its aspect and name prefix.

    Classifying on the aspect and the name prefix rather than on a fixed list
    of counter names keeps a counter that a future PAN-OS release renames or
    adds inside the report instead of silently discarding it.
    """
    name = str(counter.get("name") or "")
    aspect = str(counter.get("aspect") or "")
    if name.startswith("flow_policy_"):
        return "policy", "Policy deny"
    if name.startswith("flow_dos_pbp_"):
        # Packet buffer protection's own RED drops: what PBP discarded during
        # the incident, not traffic refused before session setup.
        return "pbp", "PBP RED drops"
    if aspect == "dos" or name.startswith("flow_dos_"):
        return "dos", "DoS / zone protection"
    if aspect == "forward" or name.startswith("flow_fwd_"):
        return "forward", "Forwarding"
    if aspect == "parse":
        return "parse", "Parse"
    if aspect == "resource":
        return "resource", "Resource exhaustion"
    return "other", "Other drops"


def _aggregate_drop_counters(
    cycles: list[tuple[int, dict[str, Any]]],
) -> dict[str, Any]:
    """Sum the `drop` severity global counters observed across the capture.

    A batch whose delta baseline is untrusted is excluded from the totals: its
    sampling window is unknown, so its values would inflate the packet counts
    presented as evidence.
    """
    aggregated: dict[str, dict[str, Any]] = {}
    counted_batches = 0
    untrusted_batches = 0
    for _, record in cycles:
        parsed = record.get("global_counters_delta")
        if not isinstance(parsed, dict):
            continue
        counters = parsed.get("counters")
        if not isinstance(counters, list):
            continue
        if str(record.get("global_counters_delta_status") or "") == "baseline_untrusted":
            untrusted_batches += 1
            continue
        counted_batches += 1
        for counter in counters:
            if not isinstance(counter, dict):
                continue
            if str(counter.get("severity") or "").lower() != "drop":
                continue
            name = str(counter.get("name") or "").strip()
            if not name:
                continue
            value = next(iter(_numbers(counter.get("value"))), None)
            rate = next(iter(_numbers(counter.get("rate"))), None)
            family_key, family_label = _drop_counter_family(counter)
            item = aggregated.get(name)
            if item is None:
                item = aggregated[name] = {
                    "name": name,
                    "family_key": family_key,
                    "family_label": family_label,
                    "description": counter.get("description"),
                    "total": 0.0,
                    "peak_rate": None,
                    "batches": 0,
                }
            if item["description"] in (None, "") and counter.get("description"):
                item["description"] = counter.get("description")
            item["batches"] += 1
            if value is not None:
                item["total"] += value
            if rate is not None:
                current_peak = item["peak_rate"]
                item["peak_rate"] = (
                    rate if current_peak is None else max(float(current_peak), rate)
                )

    items = sorted(
        aggregated.values(),
        key=lambda item: (-float(item["total"]), item["name"]),
    )
    family_totals: dict[str, float] = {}
    for item in items:
        family_totals[item["family_key"]] = (
            family_totals.get(item["family_key"], 0.0) + float(item["total"])
        )
    return {
        "items": items[:_MAX_RENDERED_DROP_COUNTERS],
        "hidden_counters": max(0, len(items) - _MAX_RENDERED_DROP_COUNTERS),
        "family_totals": family_totals,
        "denied_total": family_totals.get("policy", 0.0) + family_totals.get("dos", 0.0),
        "counted_batches": counted_batches,
        "untrusted_batches": untrusted_batches,
    }


def _unenriched_source_ips(attribution: list[dict[str, Any]]) -> list[str]:
    """List ranked source IPs that no session command could enrich."""
    identifiers = []
    for item in attribution:
        if item.get("entity_type") == "session":
            continue
        summary = item.get("session_summary")
        if isinstance(summary, dict) and summary.get("status") == "parsed":
            continue
        identifier = item.get("identifier")
        if identifier not in (None, ""):
            identifiers.append(str(identifier))
    return identifiers


def _drop_counter_verdict(
    summary: dict[str, Any],
    attribution: list[dict[str, Any]],
) -> tuple[str, str]:
    """Classify the denied-traffic evidence and word its verdict."""
    policy_total = summary["family_totals"].get("policy", 0.0)
    dos_total = summary["family_totals"].get("dos", 0.0)
    pbp_total = summary["family_totals"].get("pbp", 0.0)
    pbp_text = (
        f" PBP itself discarded {_format_number(pbp_total)} packets by RED "
        "(<code>flow_dos_pbp_*</code> counters); those are the mitigation, not "
        "denied traffic, and are not counted above."
        if pbp_total > 0
        else ""
    )
    source_ips = _unenriched_source_ips(attribution)
    if summary["denied_total"] > 0 and source_ips:
        return (
            "isolated",
            f"{_format_number(summary['denied_total'])} packets were dropped before "
            f"session setup (policy deny {_format_number(policy_total)}, DoS or zone "
            f"protection {_format_number(dos_total)}) while "
            f"{len(source_ips)} source IP(s) were ranked without an enriched session. "
            "That combination is consistent with a UDP or GRE flood denied by a "
            "Security policy rule: denied traffic never creates a session, so PAN-OS "
            "can attribute the buffer pressure to a source IP only and no "
            f"<code>show session id</code> can enrich it.{pbp_text}",
        )
    if summary["denied_total"] > 0:
        return (
            "mixed",
            f"{_format_number(summary['denied_total'])} packets were dropped before "
            f"session setup (policy deny {_format_number(policy_total)}, DoS or zone "
            f"protection {_format_number(dos_total)}), and sessions were also ranked. "
            "Both denied and permitted traffic contributed to the observed "
            f"pressure.{pbp_text}",
        )
    return (
        "collective",
        "No packet was denied by a Security policy rule, by DoS protection, or by "
        "zone protection during the counted batches. The drops below happened "
        "after session setup or outside policy evaluation, so the offender "
        f"attribution table stays the primary evidence.{pbp_text}",
    )


def _aggregate_top_sources(attribution: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Roll ranked entities up by source IP.

    A scan or a flood produces many short sessions that are each ranked
    separately; this view states which source owns them. Session entities are
    grouped by their enriched c2s source address, source-IP entities by their
    identifier.
    """
    groups: dict[str, dict[str, Any]] = {}

    def ensure(source: str) -> dict[str, Any]:
        return groups.setdefault(
            source,
            {
                "source_ip": source,
                "sessions": 0,
                "unenriched": False,
                "drop_state": False,
                "pbp_percentage": None,
                "peak_bits_per_second_total": 0.0,
                "applications": set(),
                "zones": set(),
                "destinations": set(),
                "first_seen": None,
                "last_seen": None,
            },
        )

    for item in attribution:
        if item.get("entity_type") == "session":
            summary = item.get("session_summary")
            flow = summary.get("c2s") if isinstance(summary, dict) else None
            source = flow.get("source_ip") if isinstance(flow, dict) else None
            if not source:
                continue
            group = ensure(str(source))
            group["sessions"] += 1
            application = summary.get("application")
            if application:
                group["applications"].add(str(application))
            destination = flow.get("destination_ip")
            if destination:
                group["destinations"].add(str(destination))
        else:
            identifier = item.get("identifier")
            if not identifier:
                continue
            group = ensure(str(identifier))
            group["unenriched"] = True
        group["drop_state"] = group["drop_state"] or bool(item.get("drop_state"))
        pbp = item.get("pbp_percentage")
        if isinstance(pbp, (int, float)):
            current = group["pbp_percentage"]
            group["pbp_percentage"] = (
                float(pbp) if current is None else max(float(current), float(pbp))
            )
        peak = item.get("peak_bits_per_second_total")
        if isinstance(peak, (int, float)):
            group["peak_bits_per_second_total"] += float(peak)
        zones = item.get("zones")
        if isinstance(zones, (list, tuple, set)):
            group["zones"].update(str(zone) for zone in zones if zone)
        for boundary, pick in (("first_seen", min), ("last_seen", max)):
            value = item.get(boundary)
            if value in (None, ""):
                continue
            current = group[boundary]
            group[boundary] = (
                str(value) if current is None else pick(str(current), str(value))
            )

    rollup = sorted(
        groups.values(),
        key=lambda group: (
            0 if group["drop_state"] else 1,
            -(group["pbp_percentage"] or 0.0),
            -group["sessions"],
        ),
    )
    # The rollup only earns its place when it actually aggregates: several
    # sources, or one source owning several sessions.
    if len(rollup) <= 1 and all(group["sessions"] <= 1 for group in rollup):
        return []
    return rollup


def _render_top_sources(rollup: list[dict[str, Any]]) -> str:
    if not rollup:
        return ""
    rows = []
    for group in rollup[:_MAX_RENDERED_TOP_SOURCES]:
        rate = group["peak_bits_per_second_total"]
        rate_text = (
            _format_number(rate / 1_000_000.0) if rate else "—"
        )
        flows = group["sessions"]
        if group["unenriched"]:
            flows_text = f"{flows} + denied traffic" if flows else "denied traffic only"
        else:
            flows_text = str(flows)
        rows.append(
            "<tr>"
            f'<td><code>{_escape(group["source_ip"])}</code></td>'
            f'<td>{_escape(flows_text)}</td>'
            f'<td>{_escape("Yes" if group["drop_state"] else "No")}</td>'
            f'<td class="number">{_escape(_format_number(group["pbp_percentage"]))}</td>'
            f'<td class="number">{_escape(rate_text)}</td>'
            f'<td class="wrap">{_escape(", ".join(sorted(group["applications"])) or "—")}</td>'
            f'<td class="wrap">{_escape(", ".join(sorted(group["zones"])) or "—")}</td>'
            f'<td class="number">{_escape(len(group["destinations"]) or "—")}</td>'
            f'<td>{_escape(group["first_seen"] or "—")}<br>{_escape(group["last_seen"] or "—")}</td>'
            "</tr>"
        )
    return (
        "<h3>Top sources</h3>"
        '<p class="muted">Ranked entities rolled up by source address: a scan or a '
        "flood spreads over many short sessions, and this view states which source "
        "owns them.</p>"
        '<div class="table-wrap"><table><thead><tr>'
        "<th>Source</th><th>Sessions</th><th>RED drop</th><th>Max PBP %</th>"
        "<th>Aggregate peak Mbit/s</th><th>Applications</th><th>Zones</th>"
        "<th>Distinct destinations</th><th>First / last seen</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
        + _hidden_rows_note(len(rollup) - _MAX_RENDERED_TOP_SOURCES, "sources")
    )


_PRESSURE_SERIES = (
    (
        "Packet buffer",
        ("packet_buffer_congestion", "resource_monitor_packet_buffer"),
        "#155e75",
    ),
    (
        "Packet descriptor",
        (
            "descriptor_atomic",
            "descriptor_total",
            "resource_monitor_packet_descriptor",
            "resource_monitor_packet_descriptor_on_chip",
        ),
        "#b42318",
    ),
    ("Session table", ("resource_monitor_session",), "#0f766e"),
)


def _trigger_positions(
    cycles: Sequence[tuple[int, dict[str, Any]]],
    events: Sequence[tuple[int, dict[str, Any]]] | None,
) -> list[float]:
    """Place each received trigger on the batch axis, between its neighbours."""
    batch_times = [_parse_timestamp(record.get("timestamp")) for _, record in cycles]
    positions: list[float] = []
    for _, record in events or ():
        if str(record.get("event", "")).lower() != "trigger_received":
            continue
        moment = _parse_timestamp(record.get("timestamp"))
        if moment is None:
            continue
        position: float | None = None
        for index, batch_time in enumerate(batch_times):
            if batch_time is None:
                continue
            if moment <= batch_time:
                if index == 0:
                    position = 0.0
                else:
                    previous = batch_times[index - 1]
                    if previous is None or batch_time <= previous:
                        position = float(index)
                    else:
                        fraction = (moment - previous) / (batch_time - previous)
                        position = index - 1 + max(0.0, min(1.0, fraction))
                break
        if position is None:
            position = float(len(batch_times) - 1)
        positions.append(position)
    return positions


def _render_pressure_chart(
    cycles: list[tuple[int, dict[str, Any]]],
    events: list[tuple[int, dict[str, Any]]] | None = None,
) -> str:
    """Chart the primary incident metrics per batch.

    The peak cards say how bad it got; this curve says when, so the operator
    can align an offender's first appearance with the pressure itself. The
    vertical axis fits the data so a lightly loaded firewall is not a flat
    line, and the PBP alert and activate levels are drawn when they fit.
    """
    if len(cycles) < 2:
        return ""
    series_points: dict[str, list[tuple[int, float]]] = {}
    for index, (_, record) in enumerate(cycles):
        for label, keys, _ in _PRESSURE_SERIES:
            values = [
                value
                for key in keys
                if (value := _metric_max(record, key)) is not None
            ]
            if values:
                series_points.setdefault(label, []).append((index, max(values)))
    if not series_points:
        return ""
    highest = max(value for points in series_points.values() for _, value in points)
    ceiling = next(
        (candidate for candidate in (10, 25, 50, 100) if highest * 1.15 <= candidate),
        100,
    )
    left, right, top, bottom = 46, 18, 16, 34
    height = 250
    count = len(cycles)
    plot_width = _CHART_WIDTH - left - right
    step = plot_width / (count - 1)

    def x_at(index: float) -> float:
        return left + index * step

    def y_at(value: float) -> float:
        bounded = max(0.0, min(float(ceiling), value))
        return top + (ceiling - bounded) * (height - top - bottom) / ceiling

    parts: list[str] = []
    gridstep = ceiling / 4
    for level in range(5):
        gridline = level * gridstep
        y = y_at(gridline)
        parts.append(
            f'<line x1="{left}" y1="{y:.1f}" x2="{_CHART_WIDTH - right}" y2="{y:.1f}" '
            'stroke="#e2e8f0" stroke-width="1"/>'
            f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end" class="axis">'
            f"{_format_number(gridline)}%</text>"
        )
    thresholds = [
        (_PBP_ALERT_PERCENT, "alert", "#b45309"),
        (_PBP_ACTIVATE_PERCENT, "activate", "#b42318"),
    ]
    threshold_legend: list[str] = []
    for value, name, colour in thresholds:
        if value > ceiling:
            continue
        y = y_at(value)
        parts.append(
            f'<line x1="{left}" y1="{y:.1f}" x2="{_CHART_WIDTH - right}" y2="{y:.1f}" '
            f'stroke="{colour}" stroke-width="1" stroke-dasharray="6 4"/>'
            f'<text x="{_CHART_WIDTH - right - 4}" y="{y - 4:.1f}" text-anchor="end" '
            f'class="axis" fill="{colour}">PBP {name} {_format_number(value)}%</text>'
        )
        threshold_legend.append(
            f'<span class="key"><i class="dashed" style="border-color:{colour}"></i>'
            f"PBP {name} level</span>"
        )
    tick_stride = max(1, math.ceil(count / 12))
    for index in range(count):
        if index % tick_stride and index != count - 1:
            continue
        parts.append(
            f'<text x="{x_at(index):.1f}" y="{height - 12}" text-anchor="middle" '
            f'class="axis">{index + 1}</text>'
        )
    trigger_positions = _trigger_positions(cycles, events)
    for position in trigger_positions:
        x = x_at(position)
        parts.append(
            f'<line x1="{x:.1f}" y1="{top}" x2="{x:.1f}" y2="{y_at(0):.1f}" '
            'stroke="#d97706" stroke-width="1" stroke-opacity="0.7"/>'
            f'<polygon points="{x - 4:.1f},{top} {x + 4:.1f},{top} {x:.1f},{top + 7}" '
            'fill="#d97706"/>'
        )
    legend: list[str] = []
    for label, _, colour in _PRESSURE_SERIES:
        points = series_points.get(label)
        if not points:
            continue
        joined = " ".join(f"{x_at(i):.1f},{y_at(v):.1f}" for i, v in points)
        if len(points) == 1:
            index, value = points[0]
            parts.append(
                f'<circle cx="{x_at(index):.1f}" cy="{y_at(value):.1f}" r="3" fill="{colour}"/>'
            )
        else:
            parts.append(
                f'<polyline points="{joined}" fill="none" stroke="{colour}" stroke-width="2"/>'
            )
        legend.append(
            f'<span class="key"><i style="background:{colour}"></i>{_escape(label)}</span>'
        )
    if trigger_positions:
        legend.append(
            '<span class="key"><i class="marker"></i>'
            f"Trigger received ({len(trigger_positions)})</span>"
        )
    legend.extend(threshold_legend)
    buffer_points = series_points.get(_PRESSURE_SERIES[0][0])
    if buffer_points:
        peak_index, peak_value = max(buffer_points, key=lambda point: point[1])
        px, py = x_at(peak_index), y_at(peak_value)
        anchor = "end" if peak_index > count / 2 else "start"
        offset = -8 if anchor == "end" else 8
        parts.append(
            f'<circle cx="{px:.1f}" cy="{py:.1f}" r="4" fill="#fff" '
            f'stroke="{_PRESSURE_SERIES[0][2]}" stroke-width="2"/>'
            f'<text x="{px + offset:.1f}" y="{max(py - 8, top + 10):.1f}" '
            f'text-anchor="{anchor}" class="axis peak-label">peak '
            f"{_format_number(peak_value)}% · batch {peak_index + 1}</text>"
        )
    title = "Buffer, descriptor, and session-table utilization per batch"
    return (
        f'<svg class="chart pressure-chart" viewBox="0 0 {_CHART_WIDTH} {height}" width="{_CHART_WIDTH}" '
        f'height="{height}" role="img" aria-label="{_escape(title)}">'
        f"<title>{_escape(title)}</title>{''.join(parts)}</svg>"
        f'<p class="chart-legend">{"".join(legend)}</p>'
        '<p class="muted chart-caption">Horizontal axis: batch number. Vertical axis: '
        f"window peak utilization, scaled to {_format_number(ceiling)}% to fit the data. "
        "Each triangle marks a syslog trigger received during the capture.</p>"
    )


def _render_probable_cause(
    attribution: list[dict[str, Any]],
    drop_counter_summary: dict[str, Any],
    session_series: list[dict[str, Any]],
    cycles: list[tuple[int, dict[str, Any]]],
    events: list[tuple[int, dict[str, Any]]] | None = None,
) -> str:
    """Compose the scattered verdicts into a few sentences an engineer can paste."""
    if not cycles:
        return ""
    sentences: list[str] = []
    buffer_values = [
        value
        for _, record in cycles
        for key in ("packet_buffer_congestion", "resource_monitor_packet_buffer")
        if (value := _metric_max(record, key)) is not None
    ]
    if buffer_values:
        sentences.append(
            f"Packet buffer usage peaked at {_format_number(max(buffer_values))}% "
            f"over {len(cycles)} collected batches."
        )
    top = attribution[0] if attribution else None
    if top is not None:
        tuple_text, context = _flow_description(top)
        entity_label = (
            f"session <code>{_escape(top.get('identifier'))}</code>"
            if top.get("entity_type") == "session"
            else f"source IP <code>{_escape(top.get('identifier'))}</code>"
        )
        detail = ""
        if tuple_text != "—":
            detail = f" ({_escape(tuple_text)}"
            if context != "—":
                detail += f", {_escape(context)}"
            detail += ")"
        drop_text = (
            ", which reached the RED drop state" if top.get("drop_state") else ""
        )
        peak_rate = top.get("peak_bits_per_second_total")
        rate_text = (
            f" and peaked at {_format_number(float(peak_rate) / 1_000_000.0)} Mbit/s"
            if isinstance(peak_rate, (int, float))
            else ""
        )
        sentences.append(
            f"The strongest evidence points to {entity_label}{detail}"
            f"{drop_text}{rate_text}."
        )
    corroborations = [
        record
        for _, record in (events or [])
        if str(record.get("event", "")).lower() == "flood_corroboration"
    ]
    if corroborations:
        destinations = sorted(
            {
                str(metadata["destination_ip"])
                for record in corroborations
                if isinstance(metadata := record.get("metadata"), dict)
                and metadata.get("destination_ip")
            }
        )
        destination_text = (
            f" targeting {_escape(', '.join(destinations))}" if destinations else ""
        )
        sentences.append(
            f"{len(corroborations)} zone-protection or DoS flood log(s) "
            f"corroborated the incident{destination_text}."
        )
    if drop_counter_summary.get("items"):
        sentences.append(_drop_counter_verdict(drop_counter_summary, attribution)[1])
    if session_series:
        sentences.append(_session_verdict(session_series)[1])
    if not sentences:
        return ""
    return (
        '<div class="probable-cause">'
        '<h3 id="probable-cause-title">Probable cause</h3>'
        + "".join(f"<p>{sentence}</p>" for sentence in sentences)
        + "</div>"
    )


#: The only script the report carries. It builds the Collapse all control
#: itself, so a report whose script is stripped by a mail gateway, or blocked
#: by a policy, shows the page exactly as it did before rather than a dead
#: button. It reads and writes nothing but the open state of the report's own
#: sections: no network, no storage, no cookie. The Web UI pins it by hash, so
#: this text must stay byte-for-byte what REPORT_SCRIPT_CSP_HASH covers.
REPORT_SCRIPT = """(function(){
var sections=document.querySelectorAll("section:not(.glance)>details.section-fold");
var nav=document.querySelector("nav.toc");
if(!sections.length||!nav){return;}
var button=document.createElement("button");
button.type="button";
button.className="fold-all";
button.textContent="Collapse all";
button.addEventListener("click",function(){
var collapse=false,i;
for(i=0;i<sections.length;i++){if(sections[i].open){collapse=true;break;}}
for(i=0;i<sections.length;i++){sections[i].open=!collapse;}
button.textContent=collapse?"Expand all":"Collapse all";
});
nav.appendChild(button);
})();"""

#: The Content-Security-Policy source expression the Web UI must allow for a
#: report page, and nothing else: any other script stays refused.
REPORT_SCRIPT_CSP_HASH = "sha256-" + base64.b64encode(
    hashlib.sha256(REPORT_SCRIPT.encode("utf-8")).digest()
).decode("ascii")


def _render_section(
    anchor: str,
    title: str,
    body: str,
    *,
    intro: str = "",
    pill: str = "",
    open: bool = True,
    section_class: str = "",
    data_level: str = "",
) -> str:
    """Wrap a report section in a native disclosure so it can be folded away.

    Sections open by default so the report reads top to bottom as before; the
    disclosure is plain HTML, so the report stays a single file without script,
    and the heading keeps its anchor for the navigation bar.
    """
    state = " open" if open else ""
    class_html = f' class="{section_class}"' if section_class else ""
    level_html = f' data-level="{data_level}"' if data_level else ""
    pill_html = f'<span class="pill">{pill}</span>' if pill else ""
    intro_html = f'<p class="section-intro">{intro}</p>' if intro else ""
    return (
        f'<section{class_html}{level_html} aria-labelledby="{anchor}">'
        f'<details class="section-disclosure section-fold"{state}>'
        f'<summary><h2 id="{anchor}">{title}</h2>{pill_html}</summary>'
        f'<div class="section-body">{intro_html}{body}</div>'
        "</details></section>"
    )


def _render_offender_live_sessions(events: list[tuple[int, dict[str, Any]]]) -> str:
    """Render the live sessions enumerated for top offender sources at stop."""
    record = next(
        (
            item
            for _, item in reversed(events)
            if str(item.get("event", "")).lower() == "offender_live_sessions"
        ),
        None,
    )
    if record is None or not isinstance(record.get("sources"), list):
        return ""
    blocks: list[str] = []
    for source in record["sources"]:
        if not isinstance(source, dict):
            continue
        identifier = _escape(source.get("source_ip"))
        if source.get("ok") is not True:
            blocks.append(
                f'<p class="muted">Session listing for <code>{identifier}</code> '
                f"failed: {_escape(source.get('error') or 'unknown error')}.</p>"
            )
            continue
        count = source.get("session_count")
        entries = source.get("entries")
        if not isinstance(entries, list) or not entries:
            blocks.append(
                f'<p class="muted"><code>{identifier}</code> had '
                f"{_escape(count if count is not None else '—')} live session(s) "
                "at monitor stop; none could be listed.</p>"
                if count
                else f'<p class="muted"><code>{identifier}</code> had no live '
                "session at monitor stop.</p>"
            )
            continue
        rows = "".join(
            "<tr>"
            f'<td><code>{_escape(entry.get("destination_ip") or "—")}</code></td>'
            f'<td class="number">{_escape(entry.get("destination_port") or "—")}</td>'
            f'<td>{_escape(entry.get("protocol") or "—")}</td>'
            f'<td>{_escape(entry.get("application") or "—")}</td>'
            f'<td>{_escape(entry.get("from_zone") or "—")} &rarr; '
            f'{_escape(entry.get("to_zone") or "—")}</td>'
            f'<td>{_escape(entry.get("start_time") or "—")}</td>'
            "</tr>"
            for entry in entries
            if isinstance(entry, dict)
        )
        shown = len([entry for entry in entries if isinstance(entry, dict)])
        blocks.append(
            f"<h3>Source <code>{identifier}</code> — "
            f"{_escape(count if count is not None else shown)} live session(s), "
            f"{shown} listed</h3>"
            '<div class="table-wrap"><table>'
            "<thead><tr><th>Destination</th><th>Port</th><th>Protocol</th>"
            "<th>Application</th><th>Zones</th><th>Started</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></div>"
        )
    if not blocks:
        return ""
    return _render_section(
        "offender-sessions-title",
        "Live sessions of top sources",
        "".join(blocks),
        intro="Sessions still open for the top ranked sources when the monitor "
        "stopped, from one bounded filtered query per source.",
    )


def _render_offender_traffic_logs(events: list[tuple[int, dict[str, Any]]]) -> str:
    """Render the traffic-log flows recovered for unenriched offender sources."""
    record = next(
        (
            item
            for _, item in reversed(events)
            if str(item.get("event", "")).lower() == "offender_traffic_logs"
        ),
        None,
    )
    if record is None or not isinstance(record.get("sources"), list):
        return ""
    blocks: list[str] = []
    for source in record["sources"]:
        if not isinstance(source, dict):
            continue
        identifier = _escape(source.get("source_ip"))
        if source.get("ok") is not True:
            blocks.append(
                f'<p class="muted">Traffic log lookup for <code>{identifier}</code> '
                f"failed: {_escape(source.get('error') or 'unknown error')}.</p>"
            )
            continue
        entries = source.get("entries")
        if not isinstance(entries, list) or not entries:
            blocks.append(
                f'<p class="muted">The traffic log returned no entry for '
                f"<code>{identifier}</code> in the queried window.</p>"
            )
            continue
        rows = "".join(
            "<tr>"
            f'<td>{_escape(entry.get("receive_time") or "—")}</td>'
            f'<td><code>{_escape(entry.get("destination_ip") or "—")}</code></td>'
            f'<td class="number">{_escape(entry.get("destination_port") or "—")}</td>'
            f'<td>{_escape(entry.get("protocol") or "—")}</td>'
            f'<td>{_escape(entry.get("application") or "—")}</td>'
            f'<td>{_escape(entry.get("rule") or "—")}</td>'
            f'<td>{_escape(entry.get("action") or "—")}</td>'
            f'<td>{_escape(entry.get("from_zone") or "—")} &rarr; '
            f'{_escape(entry.get("to_zone") or "—")}</td>'
            "</tr>"
            for entry in entries
            if isinstance(entry, dict)
        )
        blocks.append(
            f"<h3>Source <code>{identifier}</code> — {len(entries)} recent "
            'traffic log entries</h3><div class="table-wrap"><table>'
            "<thead><tr><th>Receive time</th><th>Destination</th><th>Port</th>"
            "<th>Protocol</th><th>Application</th><th>Rule</th><th>Action</th>"
            "<th>Zones</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></div>"
        )
    if not blocks:
        return ""
    return _render_section(
        "offender-logs-title",
        "Traffic log evidence for unenriched sources",
        "".join(blocks),
        intro="These sources were ranked from PBP evidence but had no session to "
        "inspect (traffic denied before session setup, or a RED-blocked source). "
        "The flows below come from the firewall's own traffic log, queried "
        "read-only once at monitor stop.",
    )


def _render_drop_counters(
    summary: dict[str, Any],
    attribution: list[dict[str, Any]],
) -> str:
    items = summary["items"]
    if not items:
        return (
            '<p class="muted">No drop counter was recorded in this capture. '
            "Either the firewall dropped nothing during the observed batches, or "
            "<code>show counter global filter delta yes</code> could not be "
            "collected; the batch details below carry the exact response.</p>"
        )

    state, verdict = _drop_counter_verdict(summary, attribution)

    notes = [
        f"Counted batches: {_format_number(summary['counted_batches'])}.",
    ]
    if summary["untrusted_batches"]:
        notes.append(
            f"{_format_number(summary['untrusted_batches'])} batch(es) excluded: "
            "their delta baseline was untrusted, so the sampling window is unknown."
        )
    if summary["hidden_counters"]:
        notes.append(
            f"{_format_number(summary['hidden_counters'])} lower counter(s) not "
            "listed; the batch details and the JSONL keep every counter."
        )

    largest = max((float(item["total"]) for item in items), default=0.0) or 1.0
    rows = "".join(
        "<tr>"
        f'<td><code>{_escape(item["name"])}</code></td>'
        f'<td>{_escape(item["family_label"])}</td>'
        f'<td class="number bar-cell"><span class="bar" style="width:'
        f'{max(2.0, min(100.0, float(item["total"]) / largest * 100.0)):.0f}%"></span>'
        f'{_escape(_format_number(item["total"]))}</td>'
        f'<td class="number">{_escape(_format_number(item["peak_rate"]))}</td>'
        f'<td class="number">{_escape(item["batches"])}</td>'
        f'<td class="wrap">{_escape(item.get("description") or "—")}</td>'
        "</tr>"
        for item in items
    )
    return (
        f'<p class="verdict verdict-{state}">{verdict}</p>'
        f'<p class="muted">{_escape(" ".join(notes))}</p>'
        '<div class="table-wrap"><table><thead><tr>'
        "<th>Counter</th><th>Family</th><th>Packets</th><th>Peak /s</th>"
        "<th>Batches</th><th>PAN-OS description</th>"
        f"</tr></thead><tbody>{rows}</tbody></table></div>"
    )


_SESSION_PROTOCOLS = (
    ("tcp", "TCP"),
    ("udp", "UDP"),
    ("icmp", "ICMP"),
    ("sctp_sessions", "SCTP"),
    ("gtpc", "GTPc"),
    ("gtpu_active", "GTPu"),
    ("http2_5gc", "HTTP2-5gc"),
    ("pfcp", "PFCP"),
    ("imsi", "IMSI"),
    ("bcast", "BCAST"),
    ("mcast", "MCAST"),
    ("predict", "Predict"),
)


def _session_info_totals(record: dict[str, Any]) -> dict[str, Any]:
    """Return the device-wide session counters persisted for one batch."""
    session_info = record.get("session_info")
    if not isinstance(session_info, dict):
        return {}
    totals = session_info.get("totals")
    if isinstance(totals, dict) and any(
        isinstance(value, (int, float)) for value in totals.values()
    ):
        return totals
    dataplanes = session_info.get("dataplanes")
    if isinstance(dataplanes, list) and dataplanes:
        first = dataplanes[0]
        if isinstance(first, dict):
            return first
    return {}


def _session_number(totals: dict[str, Any], key: str) -> float | None:
    value = totals.get(key)
    return float(value) if isinstance(value, (int, float)) else None


def _session_series(
    cycles: Sequence[tuple[int, dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Collect the per-batch session table view in capture order."""
    series: list[dict[str, Any]] = []
    for batch_number, (_, record) in enumerate(cycles, 1):
        totals = _session_info_totals(record)
        if not totals:
            continue
        allocated = _session_number(totals, "allocated")
        known = [
            value
            for key, _ in _SESSION_PROTOCOLS
            if (value := _session_number(totals, key)) is not None
        ]
        other = (
            max(0.0, allocated - sum(known))
            if allocated is not None and known
            else None
        )
        series.append(
            {
                "batch": batch_number,
                "clock": _firewall_clock(record) or "—",
                "allocated": allocated,
                "supported": _session_number(totals, "supported"),
                "utilization": _session_number(totals, "utilization_percentage"),
                "protocols": {
                    key: _session_number(totals, key) for key, _ in _SESSION_PROTOCOLS
                },
                "other": other,
                "cps": _session_number(totals, "connection_rate_cps"),
                "pps": _session_number(totals, "packet_rate_pps"),
                "kbps": _session_number(totals, "throughput_kbps"),
                "created": _session_number(totals, "created_since_bootup"),
            }
        )
    return series


def _session_peak(series: Sequence[dict[str, Any]], key: str) -> float | None:
    values = [item[key] for item in series if isinstance(item.get(key), float)]
    return max(values) if values else None


def _session_verdict(series: Sequence[dict[str, Any]]) -> tuple[str, str]:
    """State what the session table did while the buffers were under pressure."""
    allocated = [item["allocated"] for item in series if item["allocated"] is not None]
    packet_rates = [item["pps"] for item in series if item["pps"] is not None]
    utilization = _session_peak(series, "utilization")

    if utilization is not None and utilization >= 80:
        return (
            "isolated",
            f"The session table peaked at {_format_number(utilization)}% of its "
            "capacity. At that level PAN-OS accelerates session aging and can "
            "refuse new sessions, so the session table is itself a constraint "
            "and not only a symptom.",
        )
    if allocated and packet_rates and min(allocated) > 0 and min(packet_rates) > 0:
        session_growth = max(allocated) / min(allocated)
        packet_growth = max(packet_rates) / min(packet_rates)
        if packet_growth >= 2 and session_growth < 1.2:
            return (
                "isolated",
                f"The packet rate varied by a factor of "
                f"{_format_number(round(packet_growth, 2))} while the number of "
                f"allocated sessions stayed within "
                f"{_format_number(round((session_growth - 1) * 100, 1))}%. Packets "
                "arrived without sessions being created, which is the signature of "
                "traffic denied before session setup or of a few sessions carrying "
                "the flood; read it with the denied and dropped traffic section.",
            )
        if session_growth >= 1.2:
            return (
                "mixed",
                f"Allocated sessions grew by "
                f"{_format_number(round((session_growth - 1) * 100, 1))}% during the "
                "capture, so session setup followed the load. The offender "
                "attribution table is the primary evidence for which sessions did it.",
            )
    return (
        "collective",
        "The session table stayed stable during the capture: neither its "
        "utilization nor the session count identifies a single contributor, so "
        "the buffer pressure has to be attributed from the offender and drop "
        "evidence.",
    )


def _render_session_table(series: Sequence[dict[str, Any]]) -> str:
    if not series:
        return (
            '<p class="muted">No session table snapshot was recorded in this '
            "capture. Either <code>show session info</code> could not be collected, "
            "or the capture predates its collection; the batch details below carry "
            "the exact response.</p>"
        )

    state, verdict = _session_verdict(series)
    supported = next(
        (item["supported"] for item in series if item["supported"] is not None),
        None,
    )
    created = [item["created"] for item in series if item["created"] is not None]
    created_delta = created[-1] - created[0] if len(created) > 1 else None
    cards = "".join(
        (
            '<article class="card"><span class="card-label">Peak allocated sessions'
            f'</span><strong>{_escape(_format_number(_session_peak(series, "allocated")))}'
            + (f' / {_escape(_format_number(supported))}' if supported else "")
            + "</strong></article>",
            '<article class="card"><span class="card-label">Peak session table'
            f'</span><strong>{_escape(_format_number(_session_peak(series, "utilization")))}'
            "%</strong></article>",
            '<article class="card"><span class="card-label">Peak new connections'
            f'</span><strong>{_escape(_format_number(_session_peak(series, "cps")))}'
            " cps</strong></article>",
            '<article class="card"><span class="card-label">Peak packet rate</span>'
            f'<strong>{_escape(_format_number(_session_peak(series, "pps")))}'
            " /s</strong></article>",
            '<article class="card"><span class="card-label">Peak throughput</span>'
            f'<strong>{_escape(_format_number(_session_peak(series, "kbps")))}'
            " kbps</strong></article>",
            '<article class="card"><span class="card-label">Sessions created</span>'
            f'<strong>{_escape(_format_number(created_delta))}</strong></article>',
        )
    )

    protocol_headers = "".join(
        f"<th>{_escape(label)}</th>" for _, label in _SESSION_PROTOCOLS
    )
    rows = []
    previous_created: float | None = None
    for item in series:
        new_sessions = (
            item["created"] - previous_created
            if item["created"] is not None and previous_created is not None
            else None
        )
        if item["created"] is not None:
            previous_created = item["created"]
        protocol_cells = "".join(
            f'<td class="number">'
            f'{_escape(_format_number(item["protocols"].get(key)))}</td>'
            for key, _ in _SESSION_PROTOCOLS
        )
        rows.append(
            "<tr>"
            f'<td class="number">{_escape(item["batch"])}</td>'
            f'<td>{_escape(item["clock"])}</td>'
            f'<td class="number">{_escape(_format_number(item["allocated"]))}</td>'
            f'<td class="number">{_escape(_format_number(item["utilization"]))}</td>'
            + protocol_cells
            + f'<td class="number">{_escape(_format_number(item["other"]))}</td>'
            f'<td class="number">{_escape(_format_number(item["cps"]))}</td>'
            f'<td class="number">{_escape(_format_number(item["pps"]))}</td>'
            f'<td class="number">{_escape(_format_number(item["kbps"]))}</td>'
            f'<td class="number">{_escape(_format_number(new_sessions))}</td>'
            "</tr>"
        )

    return (
        f'<p class="verdict verdict-{state}">{verdict}</p>'
        f'<div class="cards">{cards}</div>'
        '<div class="table-wrap"><table><thead><tr>'
        "<th>Batch</th><th>Firewall time</th><th>Allocated</th><th>Table %</th>"
        f"{protocol_headers}<th>Other</th><th>New /s</th><th>Packets /s</th>"
        "<th>kbps</th><th>New sessions</th>"
        f'</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'
    )


def _format_volume(total_bytes: Any) -> str:
    """Render a cumulative byte counter in the unit an operator reads fastest."""
    values = list(_numbers(total_bytes))
    if not values:
        return "—"
    value = values[0]
    for unit, scale in (("GB", 1_000_000_000.0), ("MB", 1_000_000.0), ("kB", 1_000.0)):
        if value >= scale:
            return f"{_format_number(round(value / scale, 2))} {unit}"
    return f"{_format_number(round(value))} B"


def _format_rate(bits_per_second: Any) -> str:
    values = list(_numbers(bits_per_second))
    if not values:
        return "—"
    return _format_number(round(values[0] / 1_000_000.0, 2))


def _aggregate_large_sessions(
    cycles: list[tuple[int, dict[str, Any]]],
) -> dict[str, Any]:
    """Follow each large session across the batches that listed it.

    A session index is only stable while the session lives, so the start time
    is part of the identity: a recycled index becomes a separate row instead of
    inheriting the volume of the session that used to hold it.
    """
    tracked: dict[str, dict[str, Any]] = {}
    summary: dict[str, Any] = {
        "status": None,
        "min_kb": None,
        "min_age_seconds": None,
        "truncated": False,
        "sessions": [],
    }
    for _, record in cycles:
        batch = record.get("large_sessions")
        if not isinstance(batch, dict):
            continue
        summary["status"] = batch.get("status") or summary["status"]
        if batch.get("min_kb") is not None:
            summary["min_kb"] = batch["min_kb"]
        if batch.get("min_age_seconds") is not None:
            summary["min_age_seconds"] = batch["min_age_seconds"]
        if batch.get("truncated"):
            summary["truncated"] = True
        for session in batch.get("sessions") or []:
            if not isinstance(session, dict):
                continue
            key = f"{session.get('session_id')}@{session.get('start_time')}"
            item = tracked.setdefault(
                key,
                {
                    "session_id": session.get("session_id"),
                    "start_time": session.get("start_time"),
                    "batches": 0,
                    "peak_bits_per_second": None,
                },
            )
            item["batches"] += 1
            for field in (
                "source_ip", "destination_ip", "source_port", "destination_port",
                "protocol", "application", "from_zone", "to_zone",
                "ingress_interface", "egress_interface", "state",
                "total_bytes", "duration_seconds", "average_bits_per_second",
            ):
                if session.get(field) is not None:
                    item[field] = session[field]
            rate = next(iter(_numbers(session.get("bits_per_second"))), None)
            if rate is not None:
                peak = item["peak_bits_per_second"]
                item["peak_bits_per_second"] = (
                    rate if peak is None else max(float(peak), rate)
                )
    summary["sessions"] = sorted(
        tracked.values(),
        key=lambda item: next(iter(_numbers(item.get("total_bytes"))), 0.0),
        reverse=True,
    )
    return summary


def _render_large_sessions(summary: dict[str, Any]) -> str:
    """Render the elephant sessions with their age and their throughput."""
    status = summary.get("status")
    if status is None:
        return (
            '<p class="muted">This capture predates largest-session tracking, so '
            "no session-table query was made.</p>"
        )
    if status == "disabled":
        return (
            '<p class="muted">Largest-session tracking is disabled for this '
            "firewall, so no session-table query was made.</p>"
        )
    min_kb = next(iter(_numbers(summary.get("min_kb"))), None)
    threshold = _format_volume(min_kb * 1000.0 if min_kb else None)
    age = next(iter(_numbers(summary.get("min_age_seconds"))), None)
    criteria = f"more than {threshold} of cumulative traffic"
    if age:
        criteria += f" and open for more than {_human_duration(age)}"
    if status == "lookup_failed":
        return (
            '<p class="muted">The largest-session query failed on at least one '
            "batch; the raw command output carries the error.</p>"
        )
    sessions = summary.get("sessions") or []
    if not sessions:
        return (
            f'<p class="muted">No session carried {_escape(criteria)} during the '
            "incident, so no single transfer explains the buffer pressure.</p>"
        )
    rows = "".join(
        "<tr>"
        f'<td class="number">{_escape(item.get("session_id"))}</td>'
        f'<td><code>{_escape(item.get("source_ip") or "—")}</code>:'
        f'{_escape(item.get("source_port") or "—")} &rarr; '
        f'<code>{_escape(item.get("destination_ip") or "—")}</code>:'
        f'{_escape(item.get("destination_port") or "—")}</td>'
        f'<td>{_escape(item.get("application") or "—")}</td>'
        f'<td>{_escape(item.get("from_zone") or "—")} &rarr; '
        f'{_escape(item.get("to_zone") or "—")}</td>'
        f'<td>{_escape(item.get("ingress_interface") or "—")} &rarr; '
        f'{_escape(item.get("egress_interface") or "—")}</td>'
        f'<td>{_escape(_human_duration(next(iter(_numbers(item.get("duration_seconds"))), None)))}</td>'
        f'<td class="number">{_escape(_format_volume(item.get("total_bytes")))}</td>'
        f'<td class="number">{_escape(_format_rate(item.get("average_bits_per_second")))}</td>'
        f'<td class="number">{_escape(_format_rate(item.get("peak_bits_per_second")))}</td>'
        f'<td class="number">{_escape(item.get("batches"))}</td>'
        "</tr>"
        for item in sessions
    )
    note = (
        '<p class="muted">More sessions matched than the collector kept per '
        "batch; only the largest ones are listed.</p>"
        if summary.get("truncated")
        else ""
    )
    return (
        f'<p class="muted">Sessions carrying {_escape(criteria)}. '
        "The average is the whole life of the session, the peak is the fastest "
        "interval measured between two batches, so a long idle session shows a "
        "low average and a low peak.</p>"
        '<div class="table-wrap"><table>'
        "<thead><tr><th>Session</th><th>Flow</th><th>Application</th>"
        "<th>Zones</th><th>Interfaces</th><th>Open for</th><th>Volume</th>"
        "<th>Avg Mbit/s</th><th>Peak Mbit/s</th><th>Batches</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></div>{note}"
    )


def _render_html(
    source: Path,
    records: list[tuple[int, dict[str, Any]]],
    warnings: list[str],
    source_hash: str,
) -> str:
    cycles = [(line, record) for line, record in records if _is_cycle(record)]
    events = [(line, record) for line, record in records if not _is_cycle(record)]
    trigger_events = [
        record
        for _, record in events
        if str(record.get("event", "")).lower() == "trigger_received"
    ]
    attribution = _aggregate_attribution(cycles)
    attribution_html = _render_top_sources(
        _aggregate_top_sources(attribution)
    ) + _render_attribution_table(attribution)
    drop_counter_summary = _aggregate_drop_counters(cycles)
    drop_counters_html = _render_drop_counters(drop_counter_summary, attribution)
    offender_logs_html = _render_offender_live_sessions(
        events
    ) + _render_offender_traffic_logs(events)
    session_series = _session_series(cycles)
    probable_cause_html = _render_probable_cause(
        attribution, drop_counter_summary, session_series, cycles, events
    )
    pressure_chart_html = _render_pressure_chart(cycles, events)
    session_table_html = _render_session_table(session_series)
    large_sessions_html = _render_large_sessions(_aggregate_large_sessions(cycles))
    core_functions = next(
        (
            record["dp_core_functions"]
            for _, record in events
            if isinstance(record.get("dp_core_functions"), list)
            and record["dp_core_functions"]
        ),
        [],
    )
    cpu_charts_html = _render_cpu_charts(cycles, core_functions)
    cpu_tracking_html = _render_cpu_tracking(cycles, core_functions)
    cpu_needs_attention = any(
        marker in cpu_charts_html for marker in ("verdict-isolated", "verdict-mixed")
    )
    if cpu_charts_html and not cpu_needs_attention:
        cpu_tracking_html = (
            '<details class="section-disclosure cpu-tables">'
            "<summary><h3>Per-core tables</h3>"
            '<span class="pill">no hot core · open for the detail</span></summary>'
            f'<div class="section-body">{cpu_tracking_html}</div></details>'
        )
    pbp_statuses = [
        record.get("pbp_status")
        for _, record in cycles
        if isinstance(record.get("pbp_status"), dict)
    ]
    pbp_modes = sorted(
        {
            str(status.get("mode"))
            for status in pbp_statuses
            if status.get("mode") not in (None, "", "unknown")
        }
    )
    pbp_active = (
        "Yes"
        if any(status.get("active") is True for status in pbp_statuses)
        else "No"
        if pbp_statuses and all(status.get("active") is False for status in pbp_statuses)
        else "Unknown"
    )
    packet_buffer_pool_samples = [
        pools.get("packet_buffers")
        for _, record in cycles
        if isinstance((pools := record.get("dataplane_pools")), dict)
        and isinstance(pools.get("packet_buffers"), dict)
    ]
    low_free_limit_state = (
        "Yes"
        if any(
            sample.get("below_low_free_buffer_limit") is True
            for sample in packet_buffer_pool_samples
        )
        else "No"
        if packet_buffer_pool_samples
        and all(
            sample.get("below_low_free_buffer_limit") is False
            for sample in packet_buffer_pool_samples
        )
        else "Unknown"
    )

    run_id = next(
        (str(record["run_id"]) for _, record in records if record.get("run_id")),
        source.stem,
    )
    timestamps = [
        str(record["timestamp"])
        for _, record in records
        if record.get("timestamp") not in (None, "")
    ]
    started_at = timestamps[0] if timestamps else None
    ended_at = timestamps[-1] if timestamps else None

    elapsed_values = [
        value
        for _, record in records
        for value in _numbers(record.get("elapsed_seconds"))
    ]
    duration = max(elapsed_values) if elapsed_values else None
    if duration is None:
        first_moment = _parse_timestamp(started_at)
        last_moment = _parse_timestamp(ended_at)
        if first_moment is not None and last_moment is not None:
            duration = max(0.0, (last_moment - first_moment).total_seconds())
    unique_sessions = sorted(
        {session_id for _, record in cycles for session_id in _candidate_ids(record)}
    )
    error_count = sum(_record_error_count(record) for _, record in records)
    metric_maxima: dict[str, float | None] = {}
    for key, _ in _METRICS:
        values = []
        for _, record in cycles:
            value = _metric_max(record, key)
            if value is not None:
                values.append(value)
        metric_maxima[key] = max(values) if values else None

    stop_event = next(
        (
            record
            for _, record in reversed(events)
            if str(record.get("event", "")).lower() in {"monitor_stopped", "stopped"}
        ),
        None,
    )
    stop_reason = (
        stop_event.get("reason") or stop_event.get("event")
        if stop_event is not None
        else None
    )
    stop_reason_html = (
        f"{_escape(_stop_reason_label(stop_reason))}"
        f'<br><span class="fact-detail">{_escape(stop_reason)}</span>'
        if stop_reason
        else "Capture has no stop marker"
    )
    start_event = next(
        (
            record
            for _, record in events
            if str(record.get("event", "")).lower() in {"monitor_started", "started"}
        ),
        {},
    )
    device = start_event.get("device", {})
    if not isinstance(device, dict):
        device = {}
    device_name = device.get("device_name") or device.get("hostname") or "Unidentified"
    device_model = device.get("model") or "—"
    software_version = device.get("software_version") or "—"
    collector_version = next(
        (
            str(record["collector_version"])
            for _, record in records
            if record.get("collector_version") not in (None, "")
        ),
        "Not recorded",
    )
    target_name = next(
        (
            str(record["target_name"])
            for _, record in records
            if record.get("target_name") not in (None, "")
        ),
        "Single target",
    )

    generated_at = datetime.now(timezone.utc).isoformat()
    title = f"PBP Report — {run_id}"

    warning_html = ""
    if warnings:
        warning_items = "".join(f"<li>{_escape(item)}</li>" for item in warnings)
        warning_html = (
            '<section class="warning" aria-labelledby="warnings-title">'
            '<h2 id="warnings-title">Read warnings</h2>'
            f"<ul>{warning_items}</ul></section>"
        )

    metric_cards: dict[str, str] = {}
    card_labels = {
        key: label
        for _, group in _METRIC_CARD_GROUPS
        for key, label in group
    }
    for key, _ in _METRICS:
        value = metric_maxima[key]
        meter = ""
        if value is not None:
            bounded = max(0.0, min(100.0, value))
            meter = (
                f'<meter min="0" max="100" low="{_format_number(_PBP_ALERT_PERCENT)}" '
                f'high="{_format_number(_PBP_ACTIVATE_PERCENT)}" optimum="0" '
                f'value="{_escape(_format_number(bounded))}">'
                f'{_escape(_format_number(value))}%</meter>'
            )
            value_html = f"<strong>{_escape(_format_number(value))}%</strong>"
        else:
            value_html = '<strong class="not-collected">Not collected</strong>'
        metric_cards[key] = (
            f'<article class="card metric-card" data-level="{_level(value)}">'
            f'<span class="card-label">{_escape(card_labels[key])}</span>'
            f"{value_html}{meter}</article>"
        )
    metric_groups_html = "".join(
        '<div class="metric-family">'
        f'<h4>{_escape(group_name)}</h4>'
        '<div class="cards metric-cards">'
        + "".join(metric_cards[key] for key, _ in group)
        + "</div></div>"
        for group_name, group in _METRIC_CARD_GROUPS
    )

    capture_cards = "".join(
        (
            '<article class="card"><span class="card-label">Batches</span>'
            f'<strong>{_escape(len(cycles))}</strong></article>',
            '<article class="card"><span class="card-label">Observed duration</span>'
            f'<strong>{_escape(_human_duration(duration))}</strong></article>',
            '<article class="card"><span class="card-label">Unique sessions</span>'
            f'<strong>{_escape(len(unique_sessions))}</strong></article>',
            '<article class="card"><span class="card-label">Ranked offenders</span>'
            f'<strong>{_escape(len(attribution))}</strong></article>',
            '<article class="card"><span class="card-label">Correlated triggers</span>'
            f'<strong>{_escape(len(trigger_events))}</strong></article>',
            '<article class="card"><span class="card-label">Partial errors</span>'
            f'<strong>{_escape(error_count)}</strong></article>',
        )
    )
    state_cards = "".join(
        (
            '<article class="card"><span class="card-label">Active PBP observed</span>'
            f'<strong>{_escape(pbp_active)}</strong></article>',
            '<article class="card"><span class="card-label">Low-free limit crossed</span>'
            f'<strong>{_escape(low_free_limit_state)}</strong></article>',
            '<article class="card"><span class="card-label">PBP mode</span>'
            f'<strong>{_escape(", ".join(pbp_modes) or "—")}</strong></article>',
            '<article class="card"><span class="card-label">Denied packets</span>'
            f'<strong>{_escape(_format_number(drop_counter_summary["denied_total"]))}'
            "</strong></article>",
        )
    )
    summary_groups = (
        '<div class="summary-group"><h3>Capture overview</h3>'
        f'<div class="cards">{capture_cards}</div></div>'
        '<div class="summary-group"><h3>Incident state</h3>'
        f'<div class="cards state-cards">{state_cards}</div></div>'
        '<div class="summary-group"><h3>Peak resource utilization</h3>'
        f'<div class="metric-families">{metric_groups_html}</div></div>'
    )

    # Only chart the metrics the firewall actually returned: a column of dashes
    # says nothing, and it pushes the useful ones off the screen.
    timeline_metrics = [
        (key, label) for key, label in _METRICS if metric_maxima[key] is not None
    ] or list(_METRICS)
    hidden_metrics = [
        label for key, label in _METRICS if (key, label) not in timeline_metrics
    ]
    timeline_rows: list[str] = []
    for batch_number, (_, record) in enumerate(cycles, 1):
        metrics = [_metric_max(record, key) for key, _ in timeline_metrics]
        ids = _candidate_ids(record)
        id_text = ", ".join(ids) if ids else "—"
        clock = _firewall_clock(record) or "—"
        elapsed = next(iter(_numbers(record.get("elapsed_seconds"))), None)
        timeline_rows.append(
            "<tr>"
            f'<td class="number">{_escape(batch_number)}</td>'
            f'<td>{_time_cell(record.get("timestamp"))}</td>'
            f'<td>{_escape(clock)}</td>'
            f'<td class="number">{_escape(_format_number(elapsed))}</td>'
            + "".join(
                f'<td class="number" data-level="{_level(value)}">'
                f"{_escape(_format_number(value))}</td>"
                for value in metrics
            )
            + f'<td class="sessions">{_escape(id_text)}</td>'
            f'<td class="number">{_escape(_record_error_count(record))}</td>'
            "</tr>"
        )

    if timeline_rows:
        timeline_body = "".join(timeline_rows)
    else:
        column_count = len(timeline_metrics) + 6
        timeline_body = (
            f'<tr><td colspan="{column_count}" class="empty">No valid batch.</td></tr>'
        )
    timeline_notes: list[str] = []
    if hidden_metrics and cycles:
        timeline_notes.append(
            "Columns never returned by the firewall are hidden: "
            f"{_escape(', '.join(hidden_metrics))}."
        )
    if cycles:
        # The header used to read "Sessions", which the same report already uses
        # for a per-source count. State that this one is a list of IDs.
        timeline_notes.append(
            "<strong>Candidate sessions</strong> lists the session IDs the firewall "
            "ranked for that batch, not a session total; the device-wide count is in "
            "the session-table section."
        )
    timeline_note = (
        f'<p class="muted">{" ".join(timeline_notes)}</p>' if timeline_notes else ""
    )

    cycle_details: list[str] = []
    for batch_number, (line_number, record) in enumerate(cycles, 1):
        ids = _candidate_ids(record)
        structured_snapshot = {
            key: value
            for key, value in record.items()
            if key not in {"commands", "session_details"}
        }
        metrics_text = ", ".join(
            f"{label}: {_format_number(_metric_max(record, key))}%"
            for key, label in _METRICS
            if _metric_max(record, key) is not None
        ) or "No recognized metric"
        batch_buffer = next(
            (
                value
                for key in ("packet_buffer_congestion", "resource_monitor_packet_buffer")
                if (value := _metric_max(record, key)) is not None
            ),
            None,
        )
        batch_errors = _record_error_count(record)
        glance_parts = [
            f'<span class="glance-metric" data-level="{_level(batch_buffer)}">'
            f"buffers {_escape(_format_number(batch_buffer))}"
            f'{"%" if batch_buffer is not None else ""}</span>'
            if batch_buffer is not None
            else '<span class="glance-metric muted">no buffer reading</span>',
            f'<span class="muted">{len(ids)} session{"s" if len(ids) != 1 else ""}</span>',
        ]
        if batch_errors:
            glance_parts.append(
                f'<span class="pill bad">{batch_errors} error'
                f'{"s" if batch_errors != 1 else ""}</span>'
            )
        cycle_details.append(
            '<details class="cycle">'
            f'<summary><span>Batch {_escape(batch_number)}</span>'
            f'{"".join(glance_parts)}'
            f'<time datetime="{_escape(record.get("timestamp", ""))}" '
            f'title="{_escape(record.get("timestamp", ""))}">'
            f'{_escape(_clock_time(record.get("timestamp")) if record.get("timestamp") else "no timestamp")}</time>'
            f'<span class="pill">line {_escape(line_number)}</span></summary>'
            '<div class="cycle-body">'
            '<dl class="metadata">'
            f'<div><dt>Metrics</dt><dd>{_escape(metrics_text)}</dd></div>'
            f'<div><dt>Candidate sessions</dt><dd>{_escape(", ".join(ids) or "None")}</dd></div>'
            f'<div><dt>Firewall time</dt><dd>{_escape(_firewall_clock(record) or "Not collected")}</dd></div>'
            '</dl><h3>Structured snapshot</h3>'
            f'<pre class="raw">{_escape(structured_snapshot)}</pre>'
            '<h3>Commands</h3>'
            f'{_render_commands(record.get("commands"))}'
            '<h3>Session details</h3>'
            f'{_render_session_details(record.get("session_details"))}'
            "</div></details>"
        )

    event_details: list[str] = []
    for line_number, record in events:
        event_name = record.get("event", "record")
        metadata = {
            key: value
            for key, value in record.items()
            if key not in {"commands", "session_details"}
        }
        event_details.append(
            '<details class="cycle event">'
            f'<summary><span>{_escape(event_name)}</span>'
            f'<time datetime="{_escape(record.get("timestamp", ""))}" '
            f'title="{_escape(record.get("timestamp", ""))}">'
            f'{_escape(_clock_time(record.get("timestamp")) if record.get("timestamp") else "no timestamp")}</time>'
            f'<span class="pill">line {_escape(line_number)}</span></summary>'
            '<div class="cycle-body"><h3>Metadata</h3>'
            f'<pre class="raw">{_escape(metadata)}</pre>'
            '<h3>Commands</h3>'
            f'{_render_commands(record.get("commands"))}'
            '<h3>Session details</h3>'
            f'{_render_session_details(record.get("session_details"))}'
            "</div></details>"
        )

    details_html = "".join(cycle_details) or '<p class="muted">No batch to display.</p>'
    events_html = "".join(event_details) or '<p class="muted">No separate event.</p>'

    metric_headers = "".join(
        f"<th>{_escape(label)} %</th>" for _, label in timeline_metrics
    )

    buffer_peak_values = [
        value
        for key in ("packet_buffer_congestion", "resource_monitor_packet_buffer")
        if (value := metric_maxima.get(key)) is not None
    ]
    buffer_peak = max(buffer_peak_values) if buffer_peak_values else None
    glance_html = ""
    if cycles:
        severity_state, severity_label, severity_text = _severity(buffer_peak)
        top = attribution[0] if attribution else None
        if top is not None:
            top_kind = "session" if top.get("entity_type") == "session" else "source IP"
            top_html = (
                f"{_escape(top_kind)} <code>{_escape(top.get('identifier'))}</code>"
            )
        else:
            top_html = '<span class="muted">none identified</span>'
        facts = (
            ("Peak packet buffer", f"{_escape(_format_number(buffer_peak))}"
             f"{'%' if buffer_peak is not None else ''}"),
            ("Observed duration", _escape(_human_duration(duration))),
            ("Batches", _escape(len(cycles))),
            ("Triggers received", _escape(len(trigger_events))),
            ("Top offender", top_html),
            ("Denied packets", _escape(_format_number(drop_counter_summary["denied_total"]))),
            ("PBP engaged", _escape(pbp_active)),
            ("Stop reason", _escape(_stop_reason_label(stop_reason)) if stop_reason else "No stop marker"),
        )
        facts_html = "".join(
            f"<div><dt>{label}</dt><dd>{value}</dd></div>" for label, value in facts
        )
        glance_html = _render_section(
            "glance-title",
            "At a glance",
            f'<p class="headline"><strong>{_escape(severity_label)}.</strong> '
            f"{_escape(severity_text)}</p>"
            f'<dl class="key-facts">{facts_html}</dl>'
            f"{probable_cause_html}",
            section_class="glance",
            data_level=severity_state,
        )

    nav_items = [
        ("summary-title", "Summary"),
        ("pressure-title", "Pressure"),
        ("attribution-title", "Offenders"),
        ("drop-counters-title", "Drops"),
        ("session-table-title", "Sessions"),
        ("cpu-tracking-title", "CPU"),
        ("timeline-title", "Timeline"),
        ("cycles-title", "Batches"),
        ("events-title", "Events"),
    ]
    if glance_html:
        nav_items.insert(0, ("glance-title", "At a glance"))
    nav_html = '<nav class="toc" aria-label="Sections">' + "".join(
        f'<a href="#{anchor}">{label}</a>' for anchor, label in nav_items
    ) + "</nav>"
    # The Collapse all control is added by the report's own script, so the page
    # never shows a button that cannot work.
    report_script = REPORT_SCRIPT

    alert_text = _escape(_format_number(_PBP_ALERT_PERCENT))
    activate_text = _escape(_format_number(_PBP_ACTIVATE_PERCENT))
    sections_html = "".join(
        [
            _render_section(
                "summary-title",
                "Summary",
                summary_groups,
                intro="How much was collected, what state PBP was in, and the "
                "highest value each resource reached. Cards turn amber above the "
                f"{alert_text}% alert level and red above the {activate_text}% "
                "activate level.",
            ),
            _render_section(
                "pressure-title",
                "Pressure over time",
                pressure_chart_html
                or '<p class="muted">At least two batches are required to draw '
                "the pressure curve.</p>",
                intro="When the pressure rose and fell, batch by batch, and when "
                "the syslog triggers arrived relative to it.",
            ),
            _render_section(
                "attribution-title",
                "Offender attribution",
                attribution_html,
                intro="Which sessions and source addresses PAN-OS itself blamed "
                "for the buffer usage, with their flows and rates.",
            ),
            _render_section(
                "drop-counters-title",
                "Denied and dropped traffic",
                drop_counters_html,
                intro="What the dataplane discarded, and whether it was denied "
                "before a session existed (a flood the policy blocks) or dropped "
                "afterwards.",
            ),
            offender_logs_html,
            _render_section(
                "session-table-title",
                "Session table",
                session_table_html,
                intro="Whether new sessions followed the load, or packets arrived "
                "without creating any.",
            ),
            _render_section(
                "large-sessions-title",
                "Largest sessions",
                large_sessions_html,
                intro="Whether one long-lived high-volume transfer was consuming "
                "the link while the buffers filled. Such a session writes no "
                "traffic log until it closes, so it never appears in the offender "
                "ranking.",
            ),
            _render_section(
                "cpu-tracking-title",
                "Dataplane CPU core tracking",
                cpu_charts_html + cpu_tracking_html,
                intro="Whether every core rose together (aggregate load) or one "
                "core ran hot alone (a single high-rate flow pinned to it).",
            ),
            _render_section(
                "timeline-title",
                "Timeline",
                timeline_note
                + '<div class="table-wrap timeline-wrap"><table class="timeline">'
                "<thead><tr><th>Batch</th><th>Collector time</th><th>Firewall time</th>"
                f"<th>Elapsed (s)</th>{metric_headers}<th>Candidate sessions</th><th>Errors</th>"
                f"</tr></thead><tbody>{timeline_body}</tbody></table></div>",
                intro="One row per batch with every collected percentage. Hover a "
                "time for its full timestamp.",
            ),
            _render_section(
                "cycles-title",
                "Batch details",
                details_html,
                intro="The raw evidence for TAC: every command response of every "
                "batch, exactly as the firewall returned it.",
                pill=f"{_escape(len(cycles))} batches",
            ),
            _render_section(
                "events-title",
                "Events and metadata",
                events_html,
                pill=f"{_escape(len(events))} records",
                open=False,
            ),
        ]
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src '{REPORT_SCRIPT_CSP_HASH}'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
  <title>{_escape(title)}</title>
  <style>
    :root {{ color-scheme: light; --ink:#172033; --muted:#64748b; --line:#dbe3ee;
      --surface:#fff; --soft:#f4f7fb; --accent:#155e75; --accent2:#0f766e;
      --danger:#b42318; --warn:#92400e; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:var(--soft); color:var(--ink); font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }}
    header {{ padding:36px max(24px,calc((100vw - 1180px)/2)); color:#fff;
      background:linear-gradient(125deg,#0f172a,#155e75 58%,#0f766e); }}
    header p {{ margin:7px 0 0; color:#d9f4f2; }}
    h1 {{ margin:0; font-size:clamp(25px,4vw,42px); letter-spacing:-.025em; }}
    h2 {{ margin:0 0 14px; font-size:21px; }}
    h3 {{ margin:22px 0 10px; font-size:15px; }}
    h4 {{ margin:0 0 10px; color:#334155; font-size:13px; }}
    h5 {{ margin:12px 0 5px; }}
    main {{ width:min(1180px,calc(100% - 32px)); margin:24px auto 48px; }}
    section {{ margin:0 0 24px; }}
    .facts,.cards {{ display:grid; gap:12px; }}
    .facts {{ grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); margin-top:22px; }}
    .fact {{ padding:12px 14px; border:1px solid #ffffff35; border-radius:10px; background:#ffffff12; }}
    .fact span,.card-label {{ display:block; color:var(--muted); font-size:12px; font-weight:700; letter-spacing:.04em; text-transform:uppercase; }}
    .fact span {{ color:#a7f3d0; }}
    .fact strong {{ display:block; overflow-wrap:anywhere; margin-top:3px; }}
    .cards {{ grid-template-columns:repeat(auto-fit,minmax(145px,1fr)); }}
    .summary-group {{ margin:0 0 22px; }}
    .summary-group h3 {{ margin:0 0 10px; color:#475569; }}
    .state-cards {{ grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); }}
    .metric-families {{ display:grid; gap:12px; }}
    .metric-family {{ padding:14px; border:1px solid var(--line); border-radius:12px; background:#eaf0f6; }}
    .metric-cards {{ grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); }}
    .metric-card {{ min-height:104px; box-shadow:none; }}
    .card {{ min-height:108px; padding:16px; border:1px solid var(--line); border-radius:12px; background:var(--surface); box-shadow:0 5px 20px #0f172a0a; }}
    .card strong {{ display:block; margin:7px 0; font-size:25px; }}
    meter {{ width:100%; accent-color:var(--accent2); }}
    .warning {{ padding:16px 20px; border:1px solid #fbbf24; border-radius:12px; background:#fffbeb; color:var(--warn); }}
    .warning ul {{ margin:0; padding-left:20px; }}
    .table-wrap {{ overflow:auto; border:1px solid var(--line); border-radius:12px; background:#fff; scrollbar-gutter:stable; }}
    .timeline-wrap {{ max-height:min(72vh,760px); }}
    .timeline {{ min-width:1780px; }}
    .timeline th:first-child,.timeline td:first-child {{ position:sticky; left:0; z-index:1; background:#fff; box-shadow:1px 0 0 var(--line); }}
    .timeline th:first-child {{ z-index:3; background:#eef3f8; }}
    table {{ width:100%; border-collapse:collapse; white-space:nowrap; }}
    th,td {{ padding:10px 12px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }}
    th {{ position:sticky; top:0; background:#eef3f8; color:#334155; font-size:12px; text-transform:uppercase; }}
    tr:last-child td {{ border-bottom:0; }}
    .number {{ text-align:right; font-variant-numeric:tabular-nums; }}
    .sessions {{ max-width:280px; overflow:hidden; text-overflow:ellipsis; }}
    .wrap {{ max-width:360px; white-space:normal; overflow-wrap:anywhere; }}
    .empty,.muted {{ color:var(--muted); }}
    details.cycle {{ margin:10px 0; border:1px solid var(--line); border-radius:12px; background:#fff; overflow:hidden; }}
    details.cycle>summary {{ display:flex; align-items:center; gap:12px; padding:13px 16px; cursor:pointer; font-weight:700; }}
    details.cycle>summary time {{ margin-left:auto; color:var(--muted); font-weight:500; }}
    .cycle-body {{ padding:4px 16px 18px; border-top:1px solid var(--line); }}
    details.section-disclosure {{ border:1px solid var(--line); border-radius:12px; background:#fff; overflow:hidden; }}
    details.section-disclosure>summary {{ display:flex; align-items:center; gap:10px; padding:14px 16px; cursor:pointer; }}
    details.section-disclosure>summary h2 {{ margin:0; }}
    details.section-disclosure>.section-body {{ padding:2px 16px 16px; border-top:1px solid var(--line); }}
    details.section-fold {{ border:0; background:transparent; overflow:visible; }}
    details.section-fold>summary {{ padding:0; margin:0 0 14px; list-style:none; }}
    details.section-fold>summary::-webkit-details-marker {{ display:none; }}
    details.section-fold>summary::before {{ content:"▾"; width:18px; color:var(--accent); font-size:16px; transition:transform .15s; }}
    details.section-fold:not([open])>summary::before {{ transform:rotate(-90deg); }}
    details.section-fold:not([open])>summary {{ padding:12px 16px; border:1px solid var(--line); border-radius:12px; background:#fff; }}
    details.section-fold>summary h2 {{ margin:0; }}
    details.section-fold>.section-body {{ padding:0; border-top:0; }}
    details.section-fold>.section-body>.section-intro {{ margin-top:0; }}
    details.section-fold>summary:hover h2,
    details.section-fold>summary:focus-visible h2 {{ color:var(--accent); }}
    .glance>details.section-fold:not([open])>summary {{ padding:0; margin:0; border:0; background:transparent; }}
    .metadata {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:10px; }}
    .metadata div {{ padding:10px; border-radius:8px; background:var(--soft); }}
    dt {{ color:var(--muted); font-size:12px; font-weight:700; text-transform:uppercase; }}
    dd {{ margin:3px 0 0; overflow-wrap:anywhere; }}
    .command-metadata {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(155px,1fr)); gap:8px; margin:0; padding:12px; border-top:1px solid var(--line); }}
    .command-metadata div {{ min-width:0; padding:9px 10px; border:1px solid var(--line); border-radius:8px; background:#fff; }}
    .command-value {{ display:block; font-weight:700; font-variant-numeric:tabular-nums; overflow-wrap:anywhere; }}
    .command-value.good {{ color:#047857; }}
    .command-value.bad {{ color:var(--danger); }}
    details.raw-block {{ margin:8px 0; border-left:3px solid var(--accent); background:#f8fafc; }}
    details.raw-block>summary {{ display:flex; align-items:center; gap:9px; padding:9px 12px; cursor:pointer; }}
    .pill {{ margin-left:auto; padding:2px 8px; border-radius:999px; background:#dff6f2; color:#115e59; font-size:11px; font-weight:700; }}
    .pill.bad {{ background:#fee4e2; color:var(--danger); }}
    .signal-high {{ color:var(--danger); font-weight:800; }}
    .chart {{ display:block; max-width:100%; height:auto; margin:6px 0 4px; padding:10px 12px; border:1px solid var(--line); border-radius:12px; background:#fff; }}
    .chart text.axis {{ fill:#475569; font:11px ui-sans-serif,system-ui,sans-serif; }}
    .chart text.heat-label {{ font-size:10.5px; }}
    .chart-legend {{ display:flex; flex-wrap:wrap; gap:6px 14px; margin:2px 0 4px; color:#475569; font-size:12px; }}
    .chart-legend .key {{ display:inline-flex; align-items:center; gap:6px; }}
    .core-roles {{ gap:6px 8px; margin:6px 0 8px; }}
    .core-roles .key {{ padding:2px 9px; border-radius:999px; background:var(--soft); }}
    .core-roles .core-roles-title {{ padding:0; background:none; color:#64748b; }}
    .chart-legend i {{ width:13px; height:11px; border:1px solid #94a3b8; border-radius:3px; }}
    .chart-legend i.dashed {{ height:0; border:0; border-top:2px dashed #0f172a; border-radius:0; }}
    .chart-caption {{ margin:0 0 14px; font-size:12px; }}
    .verdict {{ margin:8px 0 10px; padding:11px 13px; border-left:4px solid var(--line); border-radius:8px; background:var(--soft); }}
    .verdict-isolated {{ border-left-color:var(--danger); background:#fef2f2; }}
    .verdict-collective {{ border-left-color:#0f766e; background:#f0fdfa; }}
    .verdict-mixed {{ border-left-color:#f59e0b; background:#fffbeb; }}
    code {{ overflow-wrap:anywhere; color:#075985; }}
    .payload-label {{ padding:0 12px; color:#475569; }}
    details.exact-response {{ margin:10px 12px 12px; border:1px solid var(--line); border-radius:8px; background:#fff; overflow:hidden; }}
    details.exact-response>summary {{ padding:9px 11px; cursor:pointer; color:#475569; font-weight:700; }}
    details.exact-response pre.raw {{ max-height:520px; }}
    pre.raw {{ overflow:auto; max-height:520px; margin:0; padding:12px; border-top:1px solid var(--line); background:#0f172a; color:#d9e5f5; font:12px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace; white-space:pre-wrap; overflow-wrap:anywhere; }}
    pre.raw-error {{ color:#fecaca; }}
    footer {{ width:min(1180px,calc(100% - 32px)); margin:0 auto 30px; color:var(--muted); font-size:12px; overflow-wrap:anywhere; }}
    .fact .fact-detail {{ display:inline; color:#a7f3d0; font-weight:500; font-size:12px; letter-spacing:0; text-transform:none; }}
    .toc {{ position:sticky; top:0; z-index:5; display:flex; flex-wrap:wrap; gap:4px 6px; padding:8px max(24px,calc((100vw - 1180px)/2)); background:#ffffffee; border-bottom:1px solid var(--line); backdrop-filter:blur(4px); }}
    .toc a {{ padding:5px 11px; border-radius:999px; color:#0f3f4f; font-size:13px; font-weight:600; text-decoration:none; }}
    .toc a:hover,.toc a:focus {{ background:#e0f2f1; }}
    .toc button.fold-all {{ margin-left:auto; padding:5px 13px; border:1px solid var(--line); border-radius:999px; background:#fff; color:#0f3f4f; font:600 13px/1.4 inherit; cursor:pointer; }}
    .toc button.fold-all:hover,.toc button.fold-all:focus {{ background:#e0f2f1; border-color:var(--accent); }}
    h2 {{ scroll-margin-top:56px; }}
    .section-intro {{ margin:-8px 0 14px; color:var(--muted); }}
    .glance {{ padding:18px 20px; border:1px solid var(--line); border-left:6px solid #64748b; border-radius:12px; background:#fff; }}
    .glance[data-level="ok"] {{ border-left-color:#047857; }}
    .glance[data-level="warn"] {{ border-left-color:#d97706; }}
    .glance[data-level="bad"] {{ border-left-color:var(--danger); }}
    .glance .headline {{ margin:0 0 14px; font-size:16px; }}
    .glance .headline strong {{ font-size:18px; }}
    .glance[data-level="ok"] .headline strong {{ color:#047857; }}
    .glance[data-level="warn"] .headline strong {{ color:#b45309; }}
    .glance[data-level="bad"] .headline strong {{ color:var(--danger); }}
    .key-facts {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:10px; margin:0 0 6px; }}
    .key-facts div {{ padding:9px 11px; border-radius:8px; background:var(--soft); }}
    .key-facts dd {{ font-size:17px; font-weight:700; }}
    .probable-cause {{ margin-top:14px; padding-top:10px; border-top:1px solid var(--line); }}
    .probable-cause h3 {{ margin:0 0 6px; }}
    .probable-cause p {{ margin:6px 0; }}
    .not-collected {{ color:var(--muted); font-size:15px; font-weight:600; }}
    .metric-card[data-level="none"] {{ background:#f8fafc; border-style:dashed; }}
    .metric-card[data-level="warn"] {{ border-color:#f59e0b; background:#fffbeb; }}
    .metric-card[data-level="bad"] {{ border-color:#f04438; background:#fef2f2; }}
    .metric-card[data-level="bad"] strong {{ color:var(--danger); }}
    .metric-card[data-level="warn"] strong {{ color:#b45309; }}
    td[data-level="warn"] {{ background:#fff7e6; color:#92400e; font-weight:700; }}
    td[data-level="bad"] {{ background:#fee4e2; color:var(--danger); font-weight:700; }}
    .bar-cell {{ position:relative; min-width:120px; }}
    .bar-cell .bar {{ position:absolute; left:6px; bottom:6px; height:4px; max-width:calc(100% - 12px); border-radius:2px; background:#94a3b8; }}
    .glance-metric {{ padding:2px 8px; border-radius:6px; background:#ecfdf5; color:#047857; font-size:12px; font-weight:700; }}
    .glance-metric[data-level="warn"] {{ background:#fffbeb; color:#b45309; }}
    .glance-metric[data-level="bad"] {{ background:#fee4e2; color:var(--danger); }}
    .glance-metric.muted {{ background:var(--soft); color:var(--muted); font-weight:500; }}
    details.cycle>summary .pill.bad {{ margin-left:0; }}
    details.cpu-tables {{ margin-top:14px; }}
    details.cpu-tables>summary h3 {{ margin:0; }}
    .chart text.peak-label {{ font-weight:700; fill:#0f172a; }}
    .chart-legend i.marker {{ width:0; height:0; border:0; border-left:6px solid transparent; border-right:6px solid transparent; border-top:9px solid #d97706; border-radius:0; }}
    @media print {{ body {{ background:#fff; }} header {{ background:#fff; color:#000; padding:16px 0; }} header p,.fact span,.fact-detail {{ color:#444; }} main,footer {{ width:100%; }} .toc {{ display:none; }} .card,.table-wrap,details.cycle,.glance {{ box-shadow:none; break-inside:avoid; }} }}
  </style>
</head>
<body>
  <header>
    <h1>{_escape(title)}</h1>
    <p>Static report derived from the JSONL capture. The JSONL file remains the original evidence.</p>
    <div class="facts">
      <div class="fact"><span>Start</span><strong>{_escape(_human_timestamp(started_at))}</strong></div>
      <div class="fact"><span>End</span><strong>{_escape(_human_timestamp(ended_at))}</strong></div>
      <div class="fact"><span>Duration</span><strong>{_escape(_human_duration(duration))}</strong></div>
      <div class="fact"><span>Stop reason</span><strong>{stop_reason_html}</strong></div>
      <div class="fact"><span>Target</span><strong>{_escape(target_name)}</strong></div>
      <div class="fact"><span>Device</span><strong>{_escape(device_name)}</strong></div>
      <div class="fact"><span>Model</span><strong>{_escape(device_model)}</strong></div>
      <div class="fact"><span>PAN-OS</span><strong>{_escape(software_version)}</strong></div>
      <div class="fact"><span>Collector version</span><strong>{_escape(collector_version)}</strong></div>
      <div class="fact"><span>Source</span><strong>{_escape(source.name)}</strong></div>
    </div>
  </header>
  {nav_html}
  <main>
    {warning_html}
    {glance_html}
    {sections_html}
  </main>
  <footer>
    Generated by PBP Monitoring v{_escape(__version__)} at {_escape(generated_at)} · JSONL SHA-256: <code>{_escape(source_hash)}</code> ·
    This report may contain sensitive IP addresses, ports, device names, and serial numbers.
  </footer>
  <script>{report_script}</script>
</body>
</html>
"""


def generate_html_report(jsonl_path: Path, html_path: Path | None = None) -> Path:
    """Generate an atomic, standalone HTML report and return its final path."""
    source = Path(jsonl_path)
    destination = Path(html_path) if html_path is not None else source.with_suffix(".html")

    if source.resolve() == destination.resolve():
        raise ValueError("The HTML destination must differ from the JSONL source")

    records, warnings, source_hash = _read_jsonl(source)
    rendered = _render_html(source, records, warnings, source_hash)
    destination.parent.mkdir(parents=True, exist_ok=True)

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())

        if os.name == "posix":
            os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, destination)
        temporary_path = None
        if os.name == "posix":
            os.chmod(destination, 0o600)
        return destination
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a self-contained HTML report from a PBP JSONL capture."
    )
    parser.add_argument("capture", type=Path, help="incident or API-check JSONL input file")
    parser.add_argument("-o", "--output", type=Path, help="optional HTML output path")
    args = parser.parse_args(argv)

    try:
        report = generate_html_report(args.capture, args.output)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"error: {exc}\n")
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
