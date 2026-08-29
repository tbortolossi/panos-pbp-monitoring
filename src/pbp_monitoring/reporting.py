#!/usr/bin/env python3
"""Generate a self-contained HTML report from a PBP incident JSONL capture."""

from __future__ import annotations

import argparse
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


def _render_cpu_tracking(
    cycles: Sequence[tuple[int, dict[str, Any]]],
) -> str:
    per_core: dict[
        tuple[str, str], list[tuple[int, str, float, float, int, int]]
    ] = {}
    timeline_rows: list[str] = []
    for batch_number, (_, record) in enumerate(cycles, 1):
        samples = _resource_cpu_samples(record)
        timestamp = str(record.get("timestamp") or "â€”")
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
            f'<td>{_escape(timestamp)}</td>'
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
        core_rows.append(
            "<tr>"
            f'<td>{_escape(dataplane)}</td>'
            f'<td class="number">{_escape(core_id)}</td>'
            f'<td class="number">{_escape(len(maximum_values))}</td>'
            f'<td class="number">{_escape(sum(observation[5] for observation in observations))}</td>'
            f'<td class="number">{_escape(_format_number(sum(average_values) / len(average_values)))}</td>'
            f'<td class="number">{_escape(_format_number(peak))}</td>'
            f'<td class="number">{_escape(_format_number(maximum_values[-1]))}</td>'
            f'<td class="number">{_escape(sum(observation[4] for observation in observations))}</td>'
            f'<td>Batch {_escape(peak_batch)}<br><span class="muted">{_escape(peak_time)}</span></td>'
            "</tr>"
        )

    return (
        '<p class="muted">Each batch covers the poll interval plus a two-second '
        "safety margin, so adjacent windows overlap. A high maxâ€“min spread with "
        "one hot core is useful "
        "corroborating evidence for flow-hash concentration. It does not, by "
        "itself, prove that a single session is responsible.</p>"
        '<h3>Per-core summary</h3><div class="table-wrap"><table><thead><tr>'
        "<th>Dataplane</th><th>Core</th><th>Windows</th><th>Returned points</th>"
        "<th>Window average %</th><th>Peak %</th><th>Latest window peak %</th>"
        "<th>Hot points â‰¥ 90%</th><th>Peak batch</th>"
        f"</tr></thead><tbody>{''.join(core_rows)}</tbody></table></div>"
        '<h3>CPU imbalance timeline</h3><div class="table-wrap"><table><thead><tr>'
        "<th>Batch</th><th>Collector time</th><th>Hottest core</th><th>Max %</th>"
        "<th>Core average %</th><th>Maxâ€“min spread</th><th>Imbalance signal</th>"
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
    for item in attribution:
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
    attribution_html = _render_attribution_table(attribution)
    cpu_tracking_html = _render_cpu_tracking(cycles)
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
    started_at = timestamps[0] if timestamps else "—"
    ended_at = timestamps[-1] if timestamps else "—"

    elapsed_values = [
        value
        for _, record in records
        for value in _numbers(record.get("elapsed_seconds"))
    ]
    duration = max(elapsed_values) if elapsed_values else None
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
                f'<meter min="0" max="100" value="{_escape(_format_number(bounded))}">'
                f'{_escape(_format_number(value))}%</meter>'
            )
        metric_cards[key] = (
            '<article class="card metric-card">'
            f'<span class="card-label">{_escape(card_labels[key])}</span>'
            f'<strong>{_escape(_format_number(value))}{"%" if value is not None else ""}</strong>'
            f"{meter}</article>"
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
            f'<strong>{_escape(_format_number(duration))}'
            f'{" s" if duration is not None else ""}</strong></article>',
            '<article class="card"><span class="card-label">Unique sessions</span>'
            f'<strong>{_escape(len(unique_sessions))}</strong></article>',
            '<article class="card"><span class="card-label">Ranked entities</span>'
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

    timeline_rows: list[str] = []
    for batch_number, (_, record) in enumerate(cycles, 1):
        metrics = [_metric_max(record, key) for key, _ in _METRICS]
        ids = _candidate_ids(record)
        id_text = ", ".join(ids) if ids else "—"
        clock = _firewall_clock(record) or "—"
        elapsed = next(iter(_numbers(record.get("elapsed_seconds"))), None)
        timeline_rows.append(
            "<tr>"
            f'<td class="number">{_escape(batch_number)}</td>'
            f'<td>{_escape(record.get("timestamp", "—"))}</td>'
            f'<td>{_escape(clock)}</td>'
            f'<td class="number">{_escape(_format_number(elapsed))}</td>'
            + "".join(
                f'<td class="number">{_escape(_format_number(value))}</td>'
                for value in metrics
            )
            + f'<td class="sessions">{_escape(id_text)}</td>'
            f'<td class="number">{_escape(_record_error_count(record))}</td>'
            "</tr>"
        )

    if timeline_rows:
        timeline_body = "".join(timeline_rows)
    else:
        column_count = len(_METRICS) + 6
        timeline_body = (
            f'<tr><td colspan="{column_count}" class="empty">No valid batch.</td></tr>'
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
        cycle_details.append(
            '<details class="cycle">'
            f'<summary><span>Batch {_escape(batch_number)}</span>'
            f'<time>{_escape(record.get("timestamp", "no timestamp"))}</time>'
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
            f'<time>{_escape(record.get("timestamp", "no timestamp"))}</time>'
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
        f"<th>{_escape(label)} %</th>" for _, label in _METRICS
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
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
    code {{ overflow-wrap:anywhere; color:#075985; }}
    .payload-label {{ padding:0 12px; color:#475569; }}
    details.exact-response {{ margin:10px 12px 12px; border:1px solid var(--line); border-radius:8px; background:#fff; overflow:hidden; }}
    details.exact-response>summary {{ padding:9px 11px; cursor:pointer; color:#475569; font-weight:700; }}
    details.exact-response pre.raw {{ max-height:520px; }}
    pre.raw {{ overflow:auto; max-height:520px; margin:0; padding:12px; border-top:1px solid var(--line); background:#0f172a; color:#d9e5f5; font:12px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace; white-space:pre-wrap; overflow-wrap:anywhere; }}
    pre.raw-error {{ color:#fecaca; }}
    footer {{ width:min(1180px,calc(100% - 32px)); margin:0 auto 30px; color:var(--muted); font-size:12px; overflow-wrap:anywhere; }}
    @media print {{ body {{ background:#fff; }} header {{ background:#fff; color:#000; padding:16px 0; }} header p,.fact span {{ color:#444; }} main,footer {{ width:100%; }} .card,.table-wrap,details.cycle {{ box-shadow:none; break-inside:avoid; }} }}
  </style>
</head>
<body>
  <header>
    <h1>{_escape(title)}</h1>
    <p>Static report derived from the JSONL capture. The JSONL file remains the original evidence.</p>
    <div class="facts">
      <div class="fact"><span>Start</span><strong>{_escape(started_at)}</strong></div>
      <div class="fact"><span>End</span><strong>{_escape(ended_at)}</strong></div>
      <div class="fact"><span>Stop reason</span><strong>{_escape(stop_reason)}</strong></div>
      <div class="fact"><span>Target</span><strong>{_escape(target_name)}</strong></div>
      <div class="fact"><span>Device</span><strong>{_escape(device_name)}</strong></div>
      <div class="fact"><span>Model</span><strong>{_escape(device_model)}</strong></div>
      <div class="fact"><span>PAN-OS</span><strong>{_escape(software_version)}</strong></div>
      <div class="fact"><span>Collector version</span><strong>{_escape(collector_version)}</strong></div>
      <div class="fact"><span>Source</span><strong>{_escape(source.name)}</strong></div>
    </div>
  </header>
  <main>
    {warning_html}
    <section aria-labelledby="summary-title">
      <h2 id="summary-title">Summary</h2>
      {summary_groups}
    </section>
    <section aria-labelledby="attribution-title">
      <h2 id="attribution-title">Offender attribution</h2>
      {attribution_html}
    </section>
    <section aria-labelledby="cpu-tracking-title">
      <h2 id="cpu-tracking-title">Dataplane CPU core tracking</h2>
      {cpu_tracking_html}
    </section>
    <section aria-labelledby="timeline-title">
      <h2 id="timeline-title">Timeline</h2>
      <div class="table-wrap timeline-wrap"><table class="timeline">
        <thead><tr><th>Batch</th><th>Collector time</th><th>Firewall time</th><th>Elapsed (s)</th>{metric_headers}<th>Sessions</th><th>Errors</th></tr></thead>
        <tbody>{timeline_body}</tbody>
      </table></div>
    </section>
    <section aria-labelledby="cycles-title">
      <h2 id="cycles-title">Batch details</h2>
      {details_html}
    </section>
    <section aria-label="Events and metadata">
      <details class="section-disclosure">
        <summary><h2>Events and metadata</h2><span class="pill">{_escape(len(events))} records</span></summary>
        <div class="section-body">{events_html}</div>
      </details>
    </section>
  </main>
  <footer>
    Generated by PBP Monitoring v{_escape(__version__)} at {_escape(generated_at)} · JSONL SHA-256: <code>{_escape(source_hash)}</code> ·
    This report may contain sensitive IP addresses, ports, device names, and serial numbers.
  </footer>
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
