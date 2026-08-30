"""Turn a capture into the PBP investigation, step by step.

The report used to be organised by data source: the PBP table, the counters,
the session table, the CPU. An engineer facing a customer's PBP alert asks a
different sequence of questions, and this module walks it in order:

1. How much pressure, on which resource, against the thresholds this firewall
   actually runs with?
2. Did PBP itself already name the offender?
3. Does ``show running resource-monitor ingress-backlogs`` hold a session?
4. If neither did, is it an elephant session, a burst of denied sessions, or
   aggregate load?

Every step states what it found *or* that it found nothing, and the closing
conclusion is composed only from the steps that were reached, so the report
cannot claim a flood on one line and low pressure on the next. Nothing here
reads the firewall: the input is the JSONL capture already collected.
"""

from __future__ import annotations

import html
import math
import re
from typing import Any, Iterable, Sequence

# PAN-OS packet buffer protection defaults: alert at 50 %, activate at 80 %.
DEFAULT_ALERT_PERCENT = 50.0
DEFAULT_ACTIVATE_PERCENT = 80.0
# Above this share the on-chip packet descriptors are the exhausted resource
# (PAN-OS troubleshooting guidance treats a sustained 80-90 % as critical).
DESCRIPTOR_EXHAUSTION_PERCENT = 80.0
# Ingress backlogs list a session from 2 % of the queue; that is the level at
# which PAN-OS itself considers it worth naming.
INGRESS_BACKLOG_PERCENT = 2.0
# A burst of denied sessions is only a candidate cause when the dataplane
# refused traffic at a rate that can fill buffers, not a handful of packets
# denied over the whole capture.
DENIED_BURST_RATE_PER_SECOND = 100.0
DENIED_BURST_TOTAL_PACKETS = 5000.0
# A long-lived transfer listed in most batches at this rate is what an
# elephant session looks like from the session table.
ELEPHANT_RATE_BITS_PER_SECOND = 100_000_000.0
SESSION_TABLE_CONSTRAINT_PERCENT = 80.0
# A storm of new sessions is slowpath work too, but from traffic the policy
# allows: many short sessions from a few sources, or a connection rate the
# session setup path cannot absorb.
NEW_SESSION_STORM_CPS = 500.0
NEW_SESSION_STORM_SESSIONS_PER_SOURCE = 100
AGGREGATE_CPU_PERCENT = 60.0

_MAX_NAMED = 3

# Platform families the maintainer troubleshoots. Cavium-based chassis expose
# the on-chip packet descriptor pool; the x86 platforms never return it, so
# the report must not present its absence as a collection failure.
_CAVIUM_PREFIXES = ("PA-220", "PA-8", "PA-30", "PA-32", "PA-50", "PA-52", "PA-70")
_X86_PREFIXES = ("PA-4", "PA-14", "PA-34", "PA-54", "PA-75")
_VIRTUAL_PREFIXES = ("VM-", "CN-", "PA-VM")

_UNIDENTIFIED_APPLICATIONS = {
    "undecided",
    "unknown",
    "unknown-udp",
    "unknown-tcp",
    "unknown-p2p",
    "incomplete",
    "insufficient-data",
    "not-applicable",
}

_STATE_LEVELS = {"positive": "bad", "negative": "ok", "unavailable": "none"}


def _escape(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _numbers(value: Any) -> Iterable[float]:
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, (int, float)):
        number = float(value)
        if math.isfinite(number):
            yield number
        return
    if isinstance(value, str):
        try:
            number = float(value.strip())
        except ValueError:
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


def _first_number(value: Any) -> float | None:
    return next(iter(_numbers(value)), None)


def _fmt(value: float | int | None) -> str:
    if value is None:
        return "—"
    if float(value).is_integer():
        return str(int(value))
    return f"{value:.2f}".rstrip("0").rstrip(".")


def _pct(value: float | None) -> str:
    return f"{_fmt(value)}%" if value is not None else "not returned"


def _metric_peak(cycles: Sequence[dict[str, Any]], *keys: str) -> float | None:
    values: list[float] = []
    for record in cycles:
        percentages = record.get("percentages")
        if not isinstance(percentages, dict):
            continue
        for key in keys:
            values.extend(_numbers(percentages.get(key)))
    return max(values) if values else None


def _metric_returned(cycles: Sequence[dict[str, Any]], *keys: str) -> bool:
    return _metric_peak(cycles, *keys) is not None


def hardware_generation(model: Any) -> dict[str, Any]:
    """Name the platform family a model belongs to and what it can report."""
    text = str(model or "").strip().upper()
    if not text or text == "—":
        return {"label": "unknown platform", "family": "unknown", "on_chip_descriptors": None}
    if text.startswith(_VIRTUAL_PREFIXES):
        return {"label": "virtual platform", "family": "virtual", "on_chip_descriptors": False}
    if text.startswith(_X86_PREFIXES):
        return {"label": "x86 platform (gen4)", "family": "x86", "on_chip_descriptors": False}
    if text.startswith(_CAVIUM_PREFIXES):
        return {"label": "Cavium platform (gen3)", "family": "cavium", "on_chip_descriptors": True}
    return {"label": "unknown platform", "family": "unknown", "on_chip_descriptors": None}


_ALERT_THRESHOLD_PATTERN = re.compile(r"alert threshold is\s*(\d+(?:\.\d+)?)\s*%", re.I)


def _configured_alert_percent(events: Sequence[dict[str, Any]]) -> float | None:
    """Read the alert threshold PAN-OS prints in its own congestion log."""
    values: list[float] = []
    for record in events:
        if str(record.get("event", "")).lower() != "trigger_received":
            continue
        message = record.get("message")
        if not isinstance(message, str):
            continue
        for match in _ALERT_THRESHOLD_PATTERN.finditer(message):
            values.extend(_numbers(match.group(1)))
    return max(values) if values else None


def _pbp_statuses(cycles: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        record["pbp_status"]
        for record in cycles
        if isinstance(record.get("pbp_status"), dict)
    ]


def _flow_text(item: dict[str, Any]) -> tuple[str, str]:
    """Describe an attributed entity's flow and its application context."""
    summary = item.get("session_summary")
    ingress = item.get("ingress_detail")
    flow: dict[str, Any] = {}
    application = None
    rule = None
    if isinstance(summary, dict):
        candidate = summary.get("c2s")
        if isinstance(candidate, dict):
            flow = candidate
        application = summary.get("application")
        rule = summary.get("rule")
    if not flow and isinstance(ingress, dict):
        flow = ingress
        application = application or ingress.get("application")
    source = flow.get("source_ip")
    destination = flow.get("destination_ip")
    if not (source or destination):
        return "", " · ".join(
            part
            for part in (
                f"app {application}" if application else "",
                f"rule {rule}" if rule else "",
            )
            if part
        )
    source_port = flow.get("source_port")
    destination_port = flow.get("destination_port")
    protocol = flow.get("protocol")
    tuple_text = (
        f"{source or '?'}{f':{source_port}' if source_port is not None else ''}"
        f" -> {destination or '?'}"
        f"{f':{destination_port}' if destination_port is not None else ''}"
    )
    if protocol is not None:
        tuple_text += f" / proto {protocol}"
    context = " · ".join(
        part
        for part in (
            f"app {application}" if application else "",
            f"rule {rule}" if rule else "",
        )
        if part
    )
    return tuple_text, context


def _entity_html(item: dict[str, Any]) -> str:
    kind = "session" if item.get("entity_type") == "session" else "source IP"
    text = f"{kind} <code>{_escape(item.get('identifier'))}</code>"
    tuple_text, context = _flow_text(item)
    details = [part for part in (tuple_text, context) if part]
    zones = ", ".join(str(zone) for zone in item.get("zones", []) if zone)
    if zones:
        details.append(f"zone {zones}")
    if details:
        text += f" ({_escape(' · '.join(details))})"
    return text


def _traffic_log_summary(events: Sequence[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Count, per unenriched source, what its traffic log said (rule, action)."""
    record = next(
        (
            item
            for item in reversed(events)
            if str(item.get("event", "")).lower() == "offender_traffic_logs"
        ),
        None,
    )
    summary: dict[str, dict[str, Any]] = {}
    if record is None or not isinstance(record.get("sources"), list):
        return summary
    for source in record["sources"]:
        if not isinstance(source, dict) or source.get("ok") is not True:
            continue
        entries = source.get("entries")
        if not isinstance(entries, list):
            continue
        denied = 0
        rules: dict[str, int] = {}
        applications: dict[str, int] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            action = str(entry.get("action") or "").lower()
            if action and action not in ("allow", "alert"):
                denied += 1
                rule = str(entry.get("rule") or "")
                if rule:
                    rules[rule] = rules.get(rule, 0) + 1
            application = str(entry.get("application") or "")
            if application:
                applications[application] = applications.get(application, 0) + 1
        summary[str(source.get("source_ip"))] = {
            "entries": len(entries),
            "denied": denied,
            "rules": sorted(rules, key=rules.get, reverse=True)[:2],
            "applications": sorted(applications, key=applications.get, reverse=True)[:3],
        }
    return summary


def build_diagnosis(
    *,
    cycles: Sequence[dict[str, Any]],
    events: Sequence[dict[str, Any]],
    attribution: Sequence[dict[str, Any]],
    drop_summary: dict[str, Any],
    session_series: Sequence[dict[str, Any]],
    large_sessions: dict[str, Any],
    cpu_verdicts: Sequence[dict[str, Any]],
    device: dict[str, Any],
) -> dict[str, Any]:
    """Walk the investigation and return its steps and conclusion.

    ``cpu_verdicts`` carries one entry per dataplane with ``state`` (``calm``,
    ``isolated``, ``collective`` or ``mixed``), the hottest core and its peak,
    exactly as the CPU section states them, so the two never disagree.
    """
    steps: list[dict[str, Any]] = []
    context = _context(cycles, events, device)

    pressure = _step_pressure(cycles, context)
    steps.append(pressure)
    low_significance = pressure["low_significance"]

    named = _step_pbp_named(cycles, attribution, events, low_significance)
    steps.append(named)

    backlogs = _step_ingress_backlogs(cycles, attribution, context)
    steps.append(backlogs)

    elsewhere = _step_elsewhere(
        drop_summary, session_series, large_sessions, cpu_verdicts, cycles,
        attribution, events, low_significance,
    )
    steps.append(elsewhere)

    headline = _headline(pressure, named, backlogs, elsewhere)
    conclusion = _conclusion(context, pressure, named, backlogs, elsewhere, len(cycles))
    return {
        "context": context,
        "steps": steps,
        "headline": headline,
        "conclusion": conclusion,
    }


def _context(
    cycles: Sequence[dict[str, Any]],
    events: Sequence[dict[str, Any]],
    device: dict[str, Any],
) -> dict[str, Any]:
    model = device.get("model") if isinstance(device, dict) else None
    statuses = _pbp_statuses(cycles)
    modes = sorted(
        {
            str(status.get("mode"))
            for status in statuses
            if status.get("mode") not in (None, "", "unknown")
        }
    )
    monitor_only = any(status.get("monitor_only") is True for status in statuses)
    enabled = (
        "disabled"
        if statuses and all(status.get("enabled") is False for status in statuses)
        else "enabled"
        if any(status.get("enabled") is True for status in statuses)
        else "unknown"
    )
    active_congestions = [
        value
        for status in statuses
        if status.get("active") is True
        and (value := _first_number(status.get("congestion_percentage"))) is not None
    ]
    alert = _configured_alert_percent(events)
    return {
        "model": str(model or "—"),
        "generation": hardware_generation(model),
        "software_version": str(device.get("software_version") or "—")
        if isinstance(device, dict)
        else "—",
        "pbp_modes": modes,
        "pbp_enabled": enabled,
        "monitor_only": monitor_only,
        "pbp_active_observed": any(status.get("active") is True for status in statuses),
        "mitigating_from_percent": min(active_congestions) if active_congestions else None,
        "alert_percent": alert,
        "alert_source": "firewall" if alert is not None else "default",
    }


def _step_pressure(cycles: Sequence[dict[str, Any]], context: dict[str, Any]) -> dict[str, Any]:
    buffer_peak = _metric_peak(
        cycles, "packet_buffer_congestion", "resource_monitor_packet_buffer"
    )
    on_chip_peak = _metric_peak(cycles, "resource_monitor_packet_descriptor_on_chip")
    descriptor_peak = _metric_peak(
        cycles, "descriptor_atomic", "descriptor_total", "resource_monitor_packet_descriptor"
    )
    sw_tags_peak = _metric_peak(cycles, "resource_monitor_sw_tags_descriptor")
    alert = context["alert_percent"] if context["alert_percent"] is not None else DEFAULT_ALERT_PERCENT
    generation = context["generation"]
    mitigating_from = context["mitigating_from_percent"]

    facts: list[tuple[str, str, str]] = [
        ("Packet buffer peak", _pct(buffer_peak), _level(buffer_peak, alert)),
    ]
    if generation["on_chip_descriptors"] is False:
        on_chip_text = f"none on this {generation['label']}"
        facts.append(("On-chip descriptors", on_chip_text, "none"))
    else:
        facts.append(
            (
                "On-chip descriptors",
                _pct(on_chip_peak),
                _level(on_chip_peak, alert, DESCRIPTOR_EXHAUSTION_PERCENT),
            )
        )
    facts.append(
        (
            "Packet descriptors",
            _pct(descriptor_peak),
            _level(descriptor_peak, alert, DESCRIPTOR_EXHAUSTION_PERCENT),
        )
    )
    if sw_tags_peak is not None:
        facts.append(("SW tag descriptors", _pct(sw_tags_peak), _level(sw_tags_peak, alert)))
    threshold_text = (
        f"alert {_fmt(alert)}% as printed by the firewall's own congestion log"
        if context["alert_source"] == "firewall"
        else f"PAN-OS defaults, alert {_fmt(DEFAULT_ALERT_PERCENT)}% and activate "
        f"{_fmt(DEFAULT_ACTIVATE_PERCENT)}%, because no trigger carried the configured value"
    )
    if mitigating_from is not None:
        threshold_text += (
            f"; PBP was observed mitigating from {_fmt(mitigating_from)}%, so the "
            "activate threshold is at or below that value"
        )
    facts.append(("Thresholds", threshold_text, "none"))

    descriptor_worst = max(
        (value for value in (on_chip_peak, descriptor_peak) if value is not None),
        default=None,
    )
    low_significance = False
    if buffer_peak is None and descriptor_worst is None:
        state, level = "unavailable", "none"
        verdict = (
            "No packet-buffer or packet-descriptor percentage was collected, so the "
            "pressure cannot be stated; the batch details keep the raw responses."
        )
    elif buffer_peak is not None and buffer_peak >= DEFAULT_ACTIVATE_PERCENT:
        state, level = "positive", "bad"
        verdict = (
            f"<strong>Packet buffers were exhausted.</strong> They peaked at "
            f"{_fmt(buffer_peak)}%, at or above the {_fmt(DEFAULT_ACTIVATE_PERCENT)}% "
            "level where PAN-OS drops with RED at full rate and counts down to discard "
            "or block. The firewall was protecting itself; the offender is what the "
            "next steps have to name."
        )
    elif descriptor_worst is not None and descriptor_worst >= DESCRIPTOR_EXHAUSTION_PERCENT:
        state, level = "positive", "bad"
        verdict = (
            f"<strong>Packet descriptors were exhausted while the buffers stayed at "
            f"{_pct(buffer_peak)}.</strong> Descriptors peaked at {_fmt(descriptor_worst)}%. "
            "That is the latency case: the queue in front of the dataplane cores "
            "fills before the buffers do, so buffer-based PBP may never activate and "
            "the culprit has to come from the ingress backlogs or from a single "
            "session pinned to one core."
        )
    elif buffer_peak is not None and buffer_peak >= DEFAULT_ALERT_PERCENT:
        state, level = "positive", "warn"
        verdict = (
            f"<strong>Elevated pressure without exhaustion.</strong> Packet buffers "
            f"peaked at {_fmt(buffer_peak)}%, above the {_fmt(DEFAULT_ALERT_PERCENT)}% "
            f"level and below the {_fmt(DEFAULT_ACTIVATE_PERCENT)}% level at which "
            "PAN-OS drops at full rate"
            + (
                f"; descriptors reached {_fmt(descriptor_worst)}%"
                if descriptor_worst is not None
                else ""
            )
            + ". The firewall was under real pressure"
            + (
                " and PBP was mitigating"
                if context["pbp_active_observed"]
                else "; whether PBP also mitigated depends on the activate threshold "
                "of this firewall"
            )
            + "."
        )
    else:
        state, level = "negative", "ok"
        low_significance = True
        verdict = (
            f"<strong>Low pressure.</strong> Packet buffers peaked at {_pct(buffer_peak)}"
            + (
                f" and descriptors at {_fmt(descriptor_worst)}%"
                if descriptor_worst is not None
                else ""
            )
            + f", below the {_fmt(DEFAULT_ALERT_PERCENT)}% PAN-OS alert default"
            + (
                f" although above the {_fmt(alert)}% alert threshold configured on "
                "this firewall"
                if context["alert_source"] == "firewall" and buffer_peak is not None and buffer_peak >= alert
                else ""
            )
            + ". "
        )
        if context["pbp_active_observed"]:
            verdict += (
                "PBP nevertheless activated"
                + (
                    f" from {_fmt(mitigating_from)}%"
                    if mitigating_from is not None
                    else ""
                )
                + f", far below the {_fmt(DEFAULT_ACTIVATE_PERCENT)}% default: the "
                "trigger is a threshold setting on this firewall, not resource "
                "exhaustion. Everything PBP ranked below is the ordinary traffic mix "
                "seen through a lowered threshold and must not be read as an attack."
            )
        else:
            verdict += (
                "Nothing in this capture shows the firewall short of buffers or "
                "descriptors; the trigger may have been brief, or the pressure was "
                "over before the first batch."
            )
    return {
        "number": 1,
        "key": "pressure",
        "title": "How much pressure, on which resource?",
        "state": state,
        "level": level,
        "verdict": verdict,
        "facts": facts,
        "anchor": "pressure-title",
        "buffer_peak": buffer_peak,
        "descriptor_peak": descriptor_worst,
        "low_significance": low_significance,
    }


def _level(value: float | None, alert: float, activate: float = DEFAULT_ACTIVATE_PERCENT) -> str:
    if value is None:
        return "none"
    if value >= activate:
        return "bad"
    if value >= alert:
        return "warn"
    return "ok"


def _step_pbp_named(
    cycles: Sequence[dict[str, Any]],
    attribution: Sequence[dict[str, Any]],
    events: Sequence[dict[str, Any]],
    low_significance: bool,
) -> dict[str, Any]:
    statuses = _pbp_statuses(cycles)
    pbp_seen = any("packet_buffer_protection" in item.get("evidence_sources", []) for item in attribution)
    activated = any(status.get("active") is True for status in statuses) or pbp_seen
    learned = [
        item
        for item in attribution
        if "packet_buffer_protection" in item.get("evidence_sources", [])
    ]
    marked = [item for item in learned if item.get("drop_state")]
    sessions = [item for item in marked if item.get("entity_type") == "session"]
    sources = [item for item in marked if item.get("entity_type") != "session"]
    logs = _traffic_log_summary(events)
    facts: list[tuple[str, str, str]] = [
        ("PBP activated", "yes" if activated else "no", "none"),
        ("Entries learned", _fmt(len(learned)), "none"),
        ("Marked for RED", _fmt(len(marked)), "none"),
    ]
    named: list[str] = []
    if not activated:
        state, level = "negative", "ok"
        verdict = (
            "<strong>PBP never activated, so it learned no offender.</strong> An "
            "alert-only PBP reports the utilization and nothing else: no threat "
            "log, no RED, no ranked session. The culprit has to come from the "
            "ingress backlogs or from the wider evidence."
        )
    elif not marked:
        state, level = "negative", "ok"
        verdict = (
            f"<strong>PBP activated and learned {len(learned)} entries, but marked "
            "none for RED.</strong> The work was spread over many small entries "
            "rather than concentrated on one session or source, which points away "
            "from a single offender and towards a burst or aggregate load."
        )
    else:
        state = "positive"
        level = "warn" if low_significance else "bad"
        parts: list[str] = []
        for item in sessions[:_MAX_NAMED]:
            named.append(_entity_html(item))
        for item in sources[:_MAX_NAMED]:
            text = _entity_html(item)
            log = logs.get(str(item.get("identifier")))
            if log:
                if log["denied"]:
                    text += (
                        f" — its traffic log shows {log['denied']} of {log['entries']} "
                        "recent flows denied"
                        + (f" by rule {_escape(', '.join(log['rules']))}" if log["rules"] else "")
                    )
                elif log["applications"]:
                    text += (
                        f" — its traffic log shows {_escape(', '.join(log['applications']))}"
                    )
            named.append(text)
        if sessions:
            parts.append(
                f"<strong>PBP marked {len(sessions)} session{'s' if len(sessions) != 1 else ''} "
                "for RED</strong>: these are the entries whose dataplane work PBP "
                "learned as the largest, the same ones its threat logs 8507/8508/8509 "
                "report. That is the firewall's own designation and the place to "
                "start, not a proof by itself; the tuple and the application come "
                "from <code>show session id</code>."
            )
        if sources:
            parts.append(
                f"<strong>PBP marked {len(sources)} source address"
                f"{'es' if len(sources) != 1 else ''} for RED without a session</strong>: "
                "that is slowpath work, traffic that never completed session setup, "
                "typically a burst denied by policy or a scan; the traffic log recovered "
                "at monitor stop says what it was."
            )
        if low_significance:
            parts.append(
                "Read this list with the low pressure of step 1 in mind: at that level "
                "the ranking is the busiest ordinary traffic, not an attack."
            )
        verdict = " ".join(parts)
    return {
        "number": 2,
        "key": "pbp",
        "title": "Did the firewall already name the offender?",
        "state": state,
        "level": level,
        "verdict": verdict,
        "facts": facts,
        "named": named,
        "sessions": sessions,
        "sources": sources,
        "anchor": "attribution-title",
    }


def _step_ingress_backlogs(
    cycles: Sequence[dict[str, Any]],
    attribution: Sequence[dict[str, Any]],
    context: dict[str, Any],
) -> dict[str, Any]:
    collected = [record for record in cycles if isinstance(record.get("ingress_backlogs"), dict)]
    atomic_peak: float | None = None
    total_peak: float | None = None
    for record in collected:
        for dataplane in record["ingress_backlogs"].get("dataplanes") or []:
            if not isinstance(dataplane, dict):
                continue
            atomic = _first_number(dataplane.get("atomic_percentage"))
            total = _first_number(dataplane.get("total_percentage"))
            if atomic is not None:
                atomic_peak = atomic if atomic_peak is None else max(atomic_peak, atomic)
            if total is not None:
                total_peak = total if total_peak is None else max(total_peak, total)
    candidates = [
        item
        for item in attribution
        if item.get("entity_type") == "session"
        and (
            "ingress_backlogs" in item.get("evidence_sources", [])
            or item.get("ingress_percentage") is not None
        )
    ]
    candidates.sort(key=lambda item: -(float(item.get("ingress_percentage") or 0.0)))
    facts: list[tuple[str, str, str]] = [
        ("Batches with the command", _fmt(len(collected)), "none"),
        ("Queue peak (ATOMIC / TOTAL)", f"{_pct(atomic_peak)} / {_pct(total_peak)}", "none"),
        ("Sessions listed", _fmt(len(candidates)), "none"),
    ]
    named: list[str] = []
    generation = context["generation"]
    if not collected and not candidates:
        state, level = "unavailable", "none"
        verdict = (
            "<strong>The ingress backlogs were not collected</strong> in this "
            "capture, so this step cannot be answered."
        )
    elif candidates:
        state, level = "positive", "bad"
        unidentified = []
        slowpath_denied = []
        for item in candidates[:_MAX_NAMED]:
            text = _entity_html(item)
            share = item.get("ingress_percentage")
            if share is not None:
                text += f" holding {_fmt(share)}% of the queue"
            detail = item.get("ingress_detail")
            application = (
                str(detail.get("application") or "").lower()
                if isinstance(detail, dict)
                else ""
            )
            summary = item.get("session_summary")
            if not application and isinstance(summary, dict):
                application = str(summary.get("application") or "").lower()
            if application in _UNIDENTIFIED_APPLICATIONS:
                unidentified.append(str(item.get("identifier")))
            groups = {str(group).lower() for group in item.get("group_ids", [])}
            status = summary.get("status") if isinstance(summary, dict) else None
            if "flow_slowpath" in groups and status == "bad_key":
                slowpath_denied.append(str(item.get("identifier")))
                text += (
                    " — queued in <code>flow_slowpath</code> and unknown to "
                    "<code>show session id</code> (Bad Key)"
                )
            named.append(text)
        verdict = (
            f"<strong>{len(candidates)} session{'s' if len(candidates) != 1 else ''} "
            f"held at least {_fmt(INGRESS_BACKLOG_PERCENT)}% of the work queue.</strong> "
            "This view is independent of the PBP learning: it is the queue of "
            "packets waiting for a dataplane core, and a session that dominates it "
            "is the one holding the descriptors."
        )
        if unidentified:
            verdict += (
                f" Session{'s' if len(unidentified) != 1 else ''} "
                f"{_escape(', '.join(unidentified))} carr{'y' if len(unidentified) != 1 else 'ies'} "
                "an undecided or unknown application at that share, which is the "
                "signature of attack traffic rather than a legitimate transfer."
            )
        if slowpath_denied:
            verdict += (
                f" Session{'s' if len(slowpath_denied) != 1 else ''} "
                f"{_escape(', '.join(slowpath_denied))} sit{'' if len(slowpath_denied) != 1 else 's'} "
                "in <code>flow_slowpath</code> with no session behind the ID: that is "
                "traffic denied by policy and re-evaluated packet by packet, in "
                "order, on one core (same six-tuple, typically UDP syslog). The "
                "source and destination in the backlog entry are the offender; the "
                "<code>flow_policy_deny</code> counter in step 4 confirms it."
            )
    else:
        state, level = "negative", "ok"
        verdict = (
            f"<strong>No session held {_fmt(INGRESS_BACKLOG_PERCENT)}% of the work "
            f"queue</strong> in any of the {len(collected)} batches (queue peak "
            f"ATOMIC {_pct(atomic_peak)}, TOTAL {_pct(total_peak)}). "
        )
        if generation["family"] == "x86":
            verdict += (
                "PAN-OS documents this command for the hardware queue of the "
                f"Cavium chassis; on this {generation['label']} an empty result is not "
                "proof that no session dominated, so the next step carries the weight."
            )
        else:
            verdict += "Whatever filled the buffers was not one session waiting in the queue."
    return {
        "number": 3,
        "key": "backlogs",
        "title": "Does the ingress backlog hold a session?",
        "state": state,
        "level": level,
        "verdict": verdict,
        "facts": facts,
        "named": named,
        "anchor": "ingress-title",
    }


_INTERFACE_ERROR_COUNTERS = ("rx_discards", "rx_missed_error", "rx_error", "tx_error")


def _interface_error_deltas(
    cycles: Sequence[dict[str, Any]],
) -> list[tuple[str, dict[str, float]]] | None:
    """Growth of the error counters of every interface sampled at least twice.

    The port counters are cumulative since boot, so only their movement during
    the capture says anything; an interface sampled once contributes zero.
    """
    first: dict[str, dict[str, float]] = {}
    last: dict[str, dict[str, float]] = {}
    for record in cycles:
        interfaces = record.get("interface_counters")
        if not isinstance(interfaces, dict):
            continue
        for name, payload in interfaces.items():
            counters = payload.get("counters") if isinstance(payload, dict) else None
            if not isinstance(counters, dict):
                continue
            values = {
                key: value
                for key in _INTERFACE_ERROR_COUNTERS
                if (value := _first_number(counters.get(key))) is not None
            }
            if not values:
                continue
            first.setdefault(str(name), values)
            last[str(name)] = values
    if not first:
        return None
    return [
        (
            name,
            {
                key: max(0.0, last[name].get(key, 0.0) - first[name].get(key, 0.0))
                for key in first[name]
            },
        )
        for name in sorted(first)
    ]


def _flood_corroborations(events: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Count the zone-protection or DoS flood logs received during the capture."""
    destinations: set[str] = set()
    count = 0
    for record in events:
        if str(record.get("event", "")).lower() != "flood_corroboration":
            continue
        count += 1
        metadata = record.get("metadata")
        if isinstance(metadata, dict) and metadata.get("destination_ip"):
            destinations.add(str(metadata["destination_ip"]))
    return {"count": count, "destinations": sorted(destinations)}


def _step_elsewhere(
    drop_summary: dict[str, Any],
    session_series: Sequence[dict[str, Any]],
    large_sessions: dict[str, Any],
    cpu_verdicts: Sequence[dict[str, Any]],
    cycles: Sequence[dict[str, Any]],
    attribution: Sequence[dict[str, Any]],
    events: Sequence[dict[str, Any]] = (),
    low_significance: bool = False,
) -> dict[str, Any]:
    hypotheses: list[dict[str, Any]] = []
    batch_count = len(cycles)

    # 4a — elephant session: one hot core, or a long-lived transfer near link speed.
    isolated = [verdict for verdict in cpu_verdicts if verdict.get("state") == "isolated"]
    elephant_sessions = []
    for session in large_sessions.get("sessions") or []:
        peak = _first_number(session.get("peak_bits_per_second"))
        listed = int(_first_number(session.get("batches")) or 0)
        if (
            peak is not None
            and peak >= ELEPHANT_RATE_BITS_PER_SECOND
            and listed >= max(2, math.ceil(batch_count / 2))
        ):
            elephant_sessions.append((session, peak, listed))
    elephant_sessions.sort(key=lambda entry: -entry[1])
    named_elephants = [
        f"session <code>{_escape(session.get('session_id'))}</code> ("
        f"{_escape(session.get('source_ip') or '?')} -> "
        f"{_escape(session.get('destination_ip') or '?')}"
        + (f":{_escape(session.get('destination_port'))}" if session.get("destination_port") is not None else "")
        + (f" · app {_escape(session.get('application'))}" if session.get("application") else "")
        + f") listed in {listed} of {batch_count} batches, peak "
        f"{_fmt(round(peak / 1_000_000.0, 1))} Mbit/s"
        for session, peak, listed in elephant_sessions[:_MAX_NAMED]
    ]
    if isolated or elephant_sessions:
        parts = []
        for verdict in isolated:
            parts.append(
                f"{_escape(verdict.get('dataplane'))} core {_escape(verdict.get('hottest_core'))} "
                f"peaked at {_fmt(verdict.get('hottest_value'))}% while the median "
                f"comparable core stayed at {_fmt(verdict.get('median'))}%"
            )
        text = "<strong>One core ran hot alone</strong>: " + "; ".join(parts) + ". " if parts else ""
        if elephant_sessions:
            text += (
                "<strong>A long-lived high-rate transfer was present through the "
                "capture</strong>, which is what an elephant session looks like: it "
                "writes no traffic log while it runs and PBP never names it."
            )
        elif isolated:
            text += (
                "No session above the largest-sessions threshold matched it, so the "
                "flow pinned to that core is either below the volume threshold or "
                "offloaded; the offender ranking and the session rates are the next "
                "place to look."
            )
        hypotheses.append(
            {"key": "elephant", "title": "Elephant session", "state": "positive", "text": text, "named": named_elephants}
        )
    else:
        sampled = bool(cpu_verdicts)
        hypotheses.append(
            {
                "key": "elephant",
                "title": "Elephant session",
                "state": "negative" if sampled or large_sessions.get("status") else "unavailable",
                "text": (
                    "No core ran hot alone"
                    + (
                        f" and no session at or above {_fmt(ELEPHANT_RATE_BITS_PER_SECOND / 1_000_000)} "
                        "Mbit/s stayed listed through the capture"
                        if large_sessions.get("status")
                        else ""
                    )
                    + "."
                    if sampled or large_sessions.get("status")
                    else "Neither the per-core CPU nor the largest sessions were collected."
                ),
                "named": [],
            }
        )

    # 4b — burst of denied sessions.
    family_totals = drop_summary.get("family_totals") or {}
    policy_total = float(family_totals.get("policy", 0.0))
    dos_total = float(family_totals.get("dos", 0.0))
    denied_total = policy_total + dos_total
    denied_peak_rate = max(
        (
            float(item["peak_rate"])
            for item in drop_summary.get("items") or []
            if item.get("family_key") in ("policy", "dos") and item.get("peak_rate") is not None
        ),
        default=0.0,
    )
    packets_without_sessions = False
    allocated = [item["allocated"] for item in session_series if item.get("allocated") is not None]
    packet_rates = [item["pps"] for item in session_series if item.get("pps") is not None]
    if allocated and packet_rates and min(allocated) > 0 and min(packet_rates) > 0:
        packets_without_sessions = (
            max(packet_rates) / min(packet_rates) >= 2 and max(allocated) / min(allocated) < 1.2
        )
    ip_only = [
        item
        for item in attribution
        if item.get("entity_type") != "session" and item.get("drop_state")
    ]
    floods = _flood_corroborations(events)
    flood_text = ""
    if floods["count"]:
        flood_text = (
            f" {floods['count']} zone-protection or DoS flood log(s) corroborated the "
            "incident"
            + (f" targeting {_escape(', '.join(floods['destinations']))}" if floods["destinations"] else "")
            + "."
        )
    counted = drop_summary.get("counted_batches") or 0
    if floods["count"] or (
        counted
        and (
            denied_peak_rate >= DENIED_BURST_RATE_PER_SECOND
            or denied_total >= DENIED_BURST_TOTAL_PACKETS
        )
    ):
        text = (
            f"<strong>The dataplane refused {_fmt(denied_total)} packets before session "
            f"setup</strong> (policy deny {_fmt(policy_total)}, DoS or zone protection "
            f"{_fmt(dos_total)}), peaking at {_fmt(denied_peak_rate)}/s. Traffic denied "
            "by policy is processed serially in the slowpath and never creates a "
            "session, so it fills buffers and descriptors while the session table "
            "barely moves"
            + (
                "; the packet rate did rise while the session count stayed flat"
                if packets_without_sessions
                else ""
            )
            + "."
        )
        if ip_only:
            text += (
                f" PBP marked {len(ip_only)} source address{'es' if len(ip_only) != 1 else ''} "
                "without a session for RED, which is the same burst seen from the PBP side."
            )
        text += flood_text
        hypotheses.append(
            {"key": "denied", "title": "Burst of denied sessions", "state": "positive", "text": text, "named": [_entity_html(item) for item in ip_only[:_MAX_NAMED]]}
        )
    elif counted:
        hypotheses.append(
            {
                "key": "denied",
                "title": "Burst of denied sessions",
                "state": "negative",
                "text": (
                    f"Only {_fmt(denied_total)} packets were denied before session setup over "
                    f"{_fmt(counted)} counted batches, peaking at {_fmt(denied_peak_rate)}/s: "
                    "far too few to fill a buffer pool."
                ),
                "named": [],
            }
        )
    else:
        hypotheses.append(
            {
                "key": "denied",
                "title": "Burst of denied sessions",
                "state": "unavailable",
                "text": "No trusted global-counter delta was collected, so denied traffic cannot be counted.",
                "named": [],
            }
        )

    # 4c — storm of new sessions the policy allows.
    cps_peak = max(
        (item["cps"] for item in session_series if item.get("cps") is not None),
        default=None,
    )
    sessions_per_source: dict[str, int] = {}
    for item in attribution:
        if item.get("entity_type") != "session":
            continue
        summary = item.get("session_summary")
        flow = summary.get("c2s") if isinstance(summary, dict) else None
        source = flow.get("source_ip") if isinstance(flow, dict) else None
        if source:
            sessions_per_source[str(source)] = sessions_per_source.get(str(source), 0) + 1
    busiest = sorted(sessions_per_source.items(), key=lambda entry: -entry[1])
    tracked_sources = {
        str(item.get("identifier"))
        for item in attribution
        if item.get("entity_type") != "session" and item.get("drop_state")
    }
    storm_sources = [
        (source, count)
        for source, count in busiest
        if count >= NEW_SESSION_STORM_SESSIONS_PER_SOURCE and source in tracked_sources
    ]
    if (cps_peak is not None and cps_peak >= NEW_SESSION_STORM_CPS) or storm_sources:
        text = "<strong>Session setup itself was the load</strong>: "
        parts = []
        if cps_peak is not None and cps_peak >= NEW_SESSION_STORM_CPS:
            parts.append(f"the firewall accepted up to {_fmt(cps_peak)} new connections per second")
        if storm_sources:
            parts.append(
                "PBP ranked "
                + ", ".join(
                    f"{count} sessions from <code>{_escape(source)}</code>"
                    for source, count in storm_sources[:_MAX_NAMED]
                )
            )
        text += "; ".join(parts) + (
            ". Many short sessions from one source are counted by PBP in both "
            "the slowpath and the fastpath, which is why it tracks the source "
            "address rather than any single session."
        )
        hypotheses.append(
            {
                "key": "storm",
                "title": "Storm of new sessions",
                "state": "positive",
                "text": text,
                "named": [
                    f"source IP <code>{_escape(source)}</code> owning {count} ranked sessions"
                    for source, count in storm_sources[:_MAX_NAMED]
                ],
            }
        )
    else:
        hypotheses.append(
            {
                "key": "storm",
                "title": "Storm of new sessions",
                "state": "negative" if session_series or attribution else "unavailable",
                "text": (
                    (
                        f"New connections peaked at {_fmt(cps_peak)}/s"
                        if cps_peak is not None
                        else "The connection rate was not collected"
                    )
                    + (
                        f" and the busiest source owned {busiest[0][1]} ranked sessions."
                        if busiest
                        else "."
                    )
                    if session_series or attribution
                    else "Neither the session table nor the offender ranking was collected."
                ),
                "named": [],
            }
        )

    # 4d — errors on the interfaces the evidence names.
    interface_deltas = _interface_error_deltas(cycles)
    if interface_deltas is None:
        hypotheses.append(
            {
                "key": "interfaces",
                "title": "Interface errors",
                "state": "unavailable",
                "text": "No interface counter was collected (the evidence named no ingress interface).",
                "named": [],
            }
        )
    elif any(value > 0 for _, counters in interface_deltas for value in counters.values()):
        named_interfaces = [
            f"<code>{_escape(name)}</code>: "
            + ", ".join(
                f"{_escape(counter)} +{_fmt(value)}"
                for counter, value in counters.items()
                if value > 0
            )
            for name, counters in interface_deltas
            if any(value > 0 for value in counters.values())
        ]
        hypotheses.append(
            {
                "key": "interfaces",
                "title": "Interface errors",
                "state": "positive",
                "text": (
                    "<strong>The port counters of the evidence interfaces moved during "
                    "the capture</strong>: missed or discarded receive frames mean the "
                    "port could not hand packets to the dataplane, and transmit errors "
                    "mean the egress side was congested. Either keeps packets in the "
                    "buffers without any session being responsible."
                ),
                "named": named_interfaces,
            }
        )
    else:
        hypotheses.append(
            {
                "key": "interfaces",
                "title": "Interface errors",
                "state": "negative",
                "text": (
                    "No receive discard, missed frame, or transmit error was counted on "
                    + ", ".join(f"<code>{_escape(name)}</code>" for name, _ in interface_deltas)
                    + "."
                ),
                "named": [],
            }
        )

    # 4e — aggregate load.
    collective = [
        verdict
        for verdict in cpu_verdicts
        if verdict.get("state") == "collective"
        and (_first_number(verdict.get("hottest_value")) or 0.0) >= AGGREGATE_CPU_PERCENT
    ]
    table_peak = max(
        (item["utilization"] for item in session_series if item.get("utilization") is not None),
        default=None,
    )
    table_constrained = table_peak is not None and table_peak >= SESSION_TABLE_CONSTRAINT_PERCENT
    if collective or table_constrained:
        parts = []
        for verdict in collective:
            parts.append(
                f"every comparable core of {_escape(verdict.get('dataplane'))} rose together to "
                f"{_fmt(verdict.get('hottest_value'))}%"
            )
        if table_constrained:
            parts.append(
                f"the session table reached {_fmt(table_peak)}% of its capacity, where PAN-OS "
                "accelerates aging and can refuse new sessions"
            )
        hypotheses.append(
            {
                "key": "aggregate",
                "title": "Aggregate load",
                "state": "positive",
                "text": (
                    "<strong>The whole dataplane was loaded, not one flow</strong>: "
                    + "; ".join(parts)
                    + ". That is sizing or inspection cost (security profiles, "
                    "decryption, server response inspection) rather than a single "
                    "responsible party."
                ),
                "named": [],
            }
        )
    else:
        hypotheses.append(
            {
                "key": "aggregate",
                "title": "Aggregate load",
                "state": "negative" if cpu_verdicts or session_series else "unavailable",
                "text": (
                    "Dataplane cores did not rise together"
                    + (
                        f" and the session table peaked at {_fmt(table_peak)}%"
                        if table_peak is not None
                        else ""
                    )
                    + "."
                    if cpu_verdicts or session_series
                    else "Neither the per-core CPU nor the session table was collected."
                ),
                "named": [],
            }
        )

    positives = [hypothesis for hypothesis in hypotheses if hypothesis["state"] == "positive"]
    if positives and low_significance:
        state, level = "negative", "ok"
        verdict = (
            "<strong>"
            + ", ".join(hypothesis["title"] for hypothesis in positives)
            + ("</strong> would be supported" if len(positives) == 1 else "</strong> would be supported")
            + ", but step 1 found no shortage of buffers or descriptors, so nothing "
            "here caused an incident; the signals are listed for completeness."
        )
    elif positives:
        state, level = "positive", "bad"
        verdict = (
            "<strong>"
            + ", ".join(hypothesis["title"] for hypothesis in positives)
            + ("</strong> is supported." if len(positives) == 1 else "</strong> are supported.")
        )
    elif all(hypothesis["state"] == "unavailable" for hypothesis in hypotheses):
        state, level = "unavailable", "none"
        verdict = "None of the wider evidence was collected."
    else:
        state, level = "negative", "ok"
        verdict = (
            "<strong>None of the wider hypotheses is supported by this capture.</strong>"
        )
    return {
        "number": 4,
        "key": "elsewhere",
        "title": "If not, where else?",
        "state": state,
        "level": level,
        "verdict": verdict,
        "facts": [],
        "hypotheses": hypotheses,
        "anchor": "cpu-tracking-title",
    }


def _headline(
    pressure: dict[str, Any],
    named: dict[str, Any],
    backlogs: dict[str, Any],
    elsewhere: dict[str, Any],
) -> dict[str, str]:
    if pressure["state"] == "unavailable":
        return {"level": "none", "label": "Pressure unknown", "text": "No utilization was collected."}
    if pressure["low_significance"]:
        return {
            "level": "ok",
            "label": "Low pressure",
            "text": (
                "The firewall was never short of buffers or descriptors; "
                + (
                    "the trigger is a lowered threshold."
                    if named["state"] == "positive"
                    else "the trigger left no offender to name."
                )
            ),
        }
    if named["state"] == "positive":
        first = named["named"][0] if named["named"] else "an entry"
        return {
            "level": pressure["level"],
            "label": "Offender named by the firewall",
            "text": f"PBP marked {first} for RED.",
        }
    if backlogs["state"] == "positive":
        first = backlogs["named"][0] if backlogs["named"] else "a session"
        return {
            "level": pressure["level"],
            "label": "Offender in the ingress backlog",
            "text": f"The work queue was held by {first}.",
        }
    if pressure["state"] == "positive" and elsewhere["state"] != "positive":
        return {
            "level": pressure["level"],
            "label": "No responsible party identified",
            "text": (
                "The pressure is real but nothing in this capture names its cause; "
                "a software defect is possible and a Tech Support File is the next step."
            ),
        }
    if elsewhere["state"] == "positive":
        titles = [h["title"] for h in elsewhere["hypotheses"] if h["state"] == "positive"]
        return {
            "level": pressure["level"],
            "label": ", ".join(titles),
            "text": "PBP and the ingress backlog named nobody; the wider evidence explains the pressure.",
        }
    return {
        "level": pressure["level"],
        "label": "No responsible party identified",
        "text": "Nothing in this capture names a cause.",
    }


def _conclusion(
    context: dict[str, Any],
    pressure: dict[str, Any],
    named: dict[str, Any],
    backlogs: dict[str, Any],
    elsewhere: dict[str, Any],
    batch_count: int,
) -> list[str]:
    sentences: list[str] = []
    generation = context["generation"]
    intro = (
        f"{_escape(context['model'])} ({_escape(generation['label'])}), PAN-OS "
        f"{_escape(context['software_version'])}, PBP {_escape(context['pbp_enabled'])}"
        + (f" in {_escape(', '.join(context['pbp_modes']))} mode" if context["pbp_modes"] else "")
        + (" (monitor only)" if context["monitor_only"] else "")
        + f", {batch_count} batches collected."
    )
    sentences.append(intro)
    if pressure["state"] == "unavailable":
        sentences.append("No utilization percentage was collected, so the pressure level cannot be stated.")
        return sentences
    buffer_text = _pct(pressure["buffer_peak"])
    descriptor_text = (
        f", packet descriptors at {_fmt(pressure['descriptor_peak'])}%"
        if pressure["descriptor_peak"] is not None
        else ""
    )
    alert_text = (
        f"the {_fmt(context['alert_percent'])}% alert threshold configured on the firewall"
        if context["alert_source"] == "firewall"
        else f"the {_fmt(DEFAULT_ALERT_PERCENT)}% default alert threshold"
    )
    sentences.append(
        f"Packet buffers peaked at {buffer_text}{descriptor_text}, against {alert_text}"
        + (
            f"; PBP was mitigating from {_fmt(context['mitigating_from_percent'])}%"
            if context["mitigating_from_percent"] is not None
            else ""
        )
        + "."
    )
    if pressure["low_significance"]:
        sentences.append(
            "The firewall was not short of resources. "
            + (
                "PBP activated only because its activate threshold is set below the "
                "observed utilization; the entries it ranked are the ordinary traffic "
                "mix and do not designate an offender."
                if named["state"] == "positive"
                else "No offender was learned and none is designated."
            )
        )
        return sentences
    if named["state"] == "positive":
        sentences.append(
            "PBP designated: " + "; ".join(named["named"]) + "."
        )
    else:
        sentences.append(
            "PBP designated nobody: "
            + (
                "it never activated during the capture."
                if "never activated" in named["verdict"]
                else "it activated but marked no entry for RED."
            )
        )
    if backlogs["state"] == "positive":
        sentences.append("Ingress backlog: " + "; ".join(backlogs["named"]) + ".")
    elif backlogs["state"] == "negative":
        sentences.append(
            f"No session held {_fmt(INGRESS_BACKLOG_PERCENT)}% of the ingress work queue."
        )
    else:
        sentences.append("The ingress backlog was not collected.")
    positives = [
        h for h in elsewhere["hypotheses"]
        if h["state"] == "positive" and elsewhere["state"] == "positive"
    ]
    negatives = [h for h in elsewhere["hypotheses"] if h["state"] == "negative"]
    for hypothesis in positives:
        sentence = f"{hypothesis['title']}: {hypothesis['text']}"
        if hypothesis["named"]:
            sentence += " Designated: " + "; ".join(hypothesis["named"]) + "."
        sentences.append(sentence)
    if negatives:
        sentences.append(
            "Not observed: " + " ".join(h["text"] for h in negatives)
        )
    if named["state"] != "positive" and backlogs["state"] != "positive" and not positives:
        sentences.append(
            "No single responsible party is identifiable from this capture. "
            "Sustained pressure with low traffic is the software-defect scenario "
            "of the PAN-OS troubleshooting guidance: a Tech Support File taken "
            "while the pressure lasts, with the PBP threat logs (8507, 8508, "
            "8509) and the buffer latency reading, is the evidence to add."
        )
    return sentences


def render_diagnosis(diagnosis: dict[str, Any]) -> str:
    """Render the investigation as the report's opening block."""
    context = diagnosis["context"]
    headline = diagnosis["headline"]
    chips = [
        f"model {context['model']}",
        context["generation"]["label"],
        f"PAN-OS {context['software_version']}",
        "PBP " + context["pbp_enabled"]
        + (f" · {', '.join(context['pbp_modes'])}" if context["pbp_modes"] else "")
        + (" · monitor only" if context["monitor_only"] else ""),
    ]
    if context["alert_percent"] is not None:
        chips.append(f"alert threshold {_fmt(context['alert_percent'])}% (from the firewall)")
    if context["mitigating_from_percent"] is not None:
        chips.append(f"PBP mitigating from {_fmt(context['mitigating_from_percent'])}%")
    context_html = '<p class="chart-legend diagnosis-context">' + "".join(
        f'<span class="key">{_escape(chip)}</span>' for chip in chips
    ) + "</p>"

    steps_html = []
    for step in diagnosis["steps"]:
        facts_html = ""
        if step.get("facts"):
            facts_html = '<dl class="step-facts">' + "".join(
                f'<div data-level="{_escape(level)}"><dt>{_escape(label)}</dt>'
                f"<dd>{_escape(value)}</dd></div>"
                for label, value, level in step["facts"]
            ) + "</dl>"
        named_html = ""
        if step.get("named"):
            named_html = '<ol class="step-named">' + "".join(
                f"<li>{item}</li>" for item in step["named"]
            ) + "</ol>"
        hypotheses_html = ""
        if step.get("hypotheses"):
            hypotheses_html = '<ul class="hypotheses">' + "".join(
                f'<li class="hypothesis hypothesis-{_escape(h["state"])}">'
                f'<span class="hypothesis-mark" aria-hidden="true"></span>'
                f"<strong>{_escape(h['title'])}</strong> — {h['text']}"
                + (
                    '<ol class="step-named">' + "".join(f"<li>{item}</li>" for item in h["named"]) + "</ol>"
                    if h.get("named")
                    else ""
                )
                + "</li>"
                for h in step["hypotheses"]
            ) + "</ul>"
        steps_html.append(
            f'<li class="step step-{_escape(step["state"])}" data-level="{_escape(step["level"])}">'
            f'<div class="step-head"><span class="step-number" aria-hidden="true">{step["number"]}</span>'
            f'<h3>{_escape(step["title"])}</h3>'
            f'<a class="step-evidence" href="#{_escape(step["anchor"])}">evidence</a></div>'
            f'<p class="step-verdict">{step["verdict"]}</p>'
            f"{named_html}{hypotheses_html}{facts_html}</li>"
        )
    conclusion_html = "".join(f"<p>{sentence}</p>" for sentence in diagnosis["conclusion"])
    return (
        f'<p class="headline"><strong>{_escape(headline["label"])}.</strong> '
        f'{headline["text"]}</p>'
        f"{context_html}"
        f'<ol class="steps">{"".join(steps_html)}</ol>'
        '<div class="probable-cause"><h3 id="conclusion-title">Conclusion for the case</h3>'
        f"{conclusion_html}</div>"
    )
