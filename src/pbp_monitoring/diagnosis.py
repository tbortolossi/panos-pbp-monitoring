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
import statistics
from datetime import datetime
from typing import Any, Callable, Iterable, Sequence

# PAN-OS packet buffer protection defaults: alert at 50 %, activate at 80 %.
DEFAULT_ALERT_PERCENT = 50.0
DEFAULT_ACTIVATE_PERCENT = 80.0
# Above this share the on-chip packet descriptors are the exhausted resource
# (PAN-OS troubleshooting guidance treats a sustained 80-90 % as critical).
DESCRIPTOR_EXHAUSTION_PERCENT = 80.0
# A congestion reading this far below the configured activate threshold is
# still consistent with it: PAN-OS reports whole percents while the dataplane
# mitigates on its own fraction, so only a clear gap contradicts the read.
MITIGATION_THRESHOLD_MARGIN_PERCENT = 1.0
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

# Signature thresholds derived from eight closed TAC packet-buffer cases
# (PAN-OS 10.2.9 - 11.2.10, PA-1420 - PA-7080). Each fires on positive
# evidence only: the counter deltas sample fractions of a second, so the
# absence of a low-rate counter proves nothing and no signature ever claims
# a negative.
ARP_STORM_RATE_PER_SECOND = 1000.0
ARP_GRATUITOUS_SHARE = 0.9
FRAGMENTATION_RATE_PER_SECOND = 500.0
FRAGMENTATION_REASSEMBLY_RATIO = 4.0
PROXY_RETRANSMIT_RATE_PER_SECOND = 100.0
POOL_HELD_PERCENT = 80.0
LEAK_SESSION_TABLE_PERCENT = 5.0
SESSION_COLLAPSE_RATIO = 0.5
SESSION_COLLAPSE_FLOOR = 1000.0
CHASSIS_IMBALANCE_MEDIAN_PERCENT = 20.0
LATENCY_LONG_TAIL_RATIO = 100.0
RECENT_BOOT_DAYS = 3.0
# A resource-monitor history whose oldest sample sits this far below its newest
# one only ever climbed: that is a leak, not a burst that recovered. The
# per-second view a monitor collects can never show it, because the monitor
# only starts once the trigger has already fired.
HISTORY_CLIMB_PERCENT = 10.0
# ...and its median has to have moved with it. A spike happening right now
# raises the newest sample above the oldest exactly as a leak does; only a
# leak also leaves the middle of the window elevated.
HISTORY_CLIMB_MEDIAN_SHARE = 0.3
# A history window whose maximum is that far above its own average is a burst:
# the level spiked and came back.
HISTORY_BURST_RATIO = 2.0
# The share of congestion events that has to fall inside one three-hour window
# before the recurrence is called a schedule rather than an accident, and the
# number of events below which the histogram says nothing at all.
RECURRENCE_WINDOW_HOURS = 3
RECURRENCE_WINDOW_SHARE = 0.4
RECURRENCE_MIN_EVENTS = 12
# Applications whose elephant flows are the operator's own infrastructure:
# blocking them trades an incident for an outage.
BACKUP_APPLICATIONS = frozenset(
    {
        "netbackup",
        "veeam",
        "veritas-pbx",
        "ms-ds-smb",
        "iscsi",
        "nfs",
        "rsync",
        "vmware",
        "commvault",
    }
)

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
    """Every finite number reachable in a parsed JSON value.

    The one copy the diagnosis and both reports read. JSON carries integers of
    unbounded size, so a firewall response - or a corrupted capture line - can
    hold a value ``float()`` refuses: it is skipped like any other unusable
    reading rather than ending the report.
    """
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


def _level(
    value: float | int | None,
    alert: float = DEFAULT_ALERT_PERCENT,
    activate: float = DEFAULT_ACTIVATE_PERCENT,
) -> str:
    """Classify a utilization percentage against the PBP thresholds.

    The single classifier of the collector: the diagnosis passes the thresholds
    this firewall actually runs with, the report tables call it with the PAN-OS
    defaults, and neither can rank a percentage the other would rank
    differently.
    """
    if value is None:
        return "none"
    if float(value) >= activate:
        return "bad"
    if float(value) >= alert:
        return "warn"
    return "ok"


def latest_event(
    events: Sequence[dict[str, Any]], event: str
) -> dict[str, Any] | None:
    """The last record of one event kind, which is the one monitor stop wrote.

    Both the diagnosis and the report's own renderers read the queries taken at
    monitor stop, so they locate them here rather than each walking the journal
    with its own copy of the rule.
    """
    return next(
        (
            record
            for record in reversed(events)
            if str(record.get("event", "")).lower() == event
        ),
        None,
    )


def start_event(events: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """The ``monitor_started`` record, which carries the once-per-incident reads.

    Everything read once while the incident was starting — the cumulative
    counters, the utilization history, the interface map, the zone-protection
    table and the HA role — is persisted there. Both reports and the diagnosis
    locate it through this one helper, so none of them can disagree about
    which record they read.
    """
    for record in events:
        if str(record.get("event", "")).lower() in {"monitor_started", "started"}:
            return record
    return {}


#: The resource-monitor windows, from the shortest to the longest. A capture
#: from a firewall that does not keep one of them simply has no entry for it.
HISTORY_WINDOW_ORDER = ("minute", "hour", "day", "week")
#: How long one sample of each window covers, for dating an onset in words.
HISTORY_WINDOW_SAMPLE = {
    "minute": ("minute", 1.0 / 60.0),
    "hour": ("hour", 1.0),
    "day": ("day", 24.0),
    "week": ("week", 168.0),
}


def history_windows(events: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """The resource-monitor history blocks read at monitor start, ordered."""
    history = start_event(events).get("resource_monitor_history")
    if not isinstance(history, dict):
        return []
    windows = [
        window
        for window in history.get("windows") or []
        if isinstance(window, dict)
    ]
    windows.sort(
        key=lambda window: (
            str(window.get("dataplane") or ""),
            HISTORY_WINDOW_ORDER.index(str(window.get("window")))
            if str(window.get("window")) in HISTORY_WINDOW_ORDER
            else len(HISTORY_WINDOW_ORDER),
        )
    )
    return windows


def history_trend(
    events: Sequence[dict[str, Any]], metric: str = "packet_buffer"
) -> dict[str, Any]:
    """Read one metric's history as a climb, a burst, or a flat level.

    A leak and a flood look identical in the per-second view a monitor
    collects: both end at a high percentage. They separate over hours and
    days. A window whose oldest sample sits well below its newest one only
    ever climbed, and the sample where the climb starts dates the onset; a
    window whose maximum towers over its own average spiked and recovered.
    """
    verdicts: list[dict[str, Any]] = []
    for window in history_windows(events):
        metrics = window.get("metrics")
        if not isinstance(metrics, dict):
            continue
        readings = metrics.get(metric)
        if not isinstance(readings, dict):
            continue
        maximum = readings.get("maximum")
        average = readings.get("average")
        summary = maximum if isinstance(maximum, dict) else average
        if not isinstance(summary, dict):
            continue
        latest = _first_number(summary.get("latest"))
        oldest = _first_number(summary.get("oldest"))
        peak = _first_number(summary.get("peak"))
        mean = _first_number(summary.get("mean"))
        if latest is None or oldest is None:
            continue
        series = readings.get("maximum_series") or readings.get("average_series")
        samples = [
            value
            for item in (series if isinstance(series, list) else [])
            if (value := _first_number(item)) is not None
        ]
        rise = latest - oldest
        # A spike that is happening right now also has a high newest sample
        # and a low oldest one, so the rise alone cannot separate a leak from
        # a burst. What separates them is how much of the window sat high: a
        # leak has been elevated for a good part of it, a burst has not, so
        # the median has to have moved with the level.
        sustained = (
            statistics.median(samples)
            >= oldest + rise * HISTORY_CLIMB_MEDIAN_SHARE
            if samples
            else False
        )
        shape = "flat"
        if rise >= HISTORY_CLIMB_PERCENT and sustained:
            shape = "climbing"
        elif (
            peak is not None
            and mean is not None
            and mean > 0
            and peak / mean >= HISTORY_BURST_RATIO
        ):
            shape = "burst"
        onset = None
        if shape == "climbing" and isinstance(series, list) and series:
            # The series runs newest first, so the onset is the last sample
            # still at the old level, counted back from now.
            floor = oldest + max(1.0, rise * 0.1)
            index = len(series) - 1
            for position, value in enumerate(series):
                number = _first_number(value)
                if number is not None and number <= floor:
                    index = position
                    break
            unit, hours = HISTORY_WINDOW_SAMPLE.get(
                str(window.get("window")), ("sample", 1.0)
            )
            onset = {
                "samples_ago": index,
                "unit": unit,
                "hours_ago": round(index * hours, 2),
            }
        verdicts.append(
            {
                "dataplane": window.get("dataplane"),
                "window": window.get("window"),
                "shape": shape,
                "latest": latest,
                "oldest": oldest,
                "peak": peak,
                "mean": mean,
                "rise": round(rise, 2),
                "onset": onset,
            }
        )
    climbing = [verdict for verdict in verdicts if verdict["shape"] == "climbing"]
    return {
        "metric": metric,
        "available": bool(verdicts),
        "windows": verdicts,
        "shape": (
            "climbing"
            if climbing
            else "burst"
            if any(verdict["shape"] == "burst" for verdict in verdicts)
            else "flat"
            if verdicts
            else "unavailable"
        ),
        "climbing_windows": [str(verdict["window"]) for verdict in climbing],
    }


_CONGESTION_TIME_FORMATS = ("%Y/%m/%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S")
_WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


def _congestion_moment(entry: dict[str, Any]) -> datetime | None:
    for key in ("time_generated", "receive_time"):
        text = str(entry.get(key) or "").strip()
        if not text:
            continue
        for pattern in _CONGESTION_TIME_FORMATS:
            try:
                return datetime.strptime(text[:19], pattern)
            except ValueError:
                continue
    return None


def congestion_recurrence(events: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Fold the firewall's own congestion log into a recurrence histogram.

    The congestion line is written once a minute while the buffer is above the
    alert level, it survives reboots, and it is the only PBP trace a
    monitor-only latency-mode device leaves at all. Counting its timestamps by
    hour of day and day of week is what separates a scheduled job from an
    attack: a backup window fires in the same three hours every night, and a
    flood does not.

    No collection of its own: the histogram is derived from the single
    congestion query the monitor already runs at stop.
    """
    record = latest_event(events, "congestion_system_logs") or {}
    entries = [
        entry for entry in record.get("entries") or [] if isinstance(entry, dict)
    ]
    hours = [0] * 24
    weekdays = [0] * 7
    moments: list[datetime] = []
    for entry in entries:
        moment = _congestion_moment(entry)
        if moment is None:
            continue
        moments.append(moment)
        hours[moment.hour] += 1
        weekdays[moment.weekday()] += 1
    percentages = [
        value
        for entry in entries
        if (value := _first_number(entry.get("percent"))) is not None
    ]
    counted = len(moments)
    peak_window = None
    if counted >= RECURRENCE_MIN_EVENTS:
        best_start, best_total, best_head = 0, -1, -1
        for start in range(24):
            total = sum(
                hours[(start + offset) % 24]
                for offset in range(RECURRENCE_WINDOW_HOURS)
            )
            # Several windows can hold the same events; the one that starts on
            # the busiest hour is the one an operator recognizes as the job's
            # window, rather than an equally valid window starting two hours
            # before anything happens.
            if (total, hours[start]) > (best_total, best_head):
                best_start, best_total, best_head = start, total, hours[start]
        share = best_total / counted if counted else 0.0
        peak_window = {
            "start_hour": best_start,
            "end_hour": (best_start + RECURRENCE_WINDOW_HOURS) % 24,
            "events": best_total,
            "share": round(share, 3),
            "scheduled": share >= RECURRENCE_WINDOW_SHARE,
        }
    return {
        "collected": bool(record),
        "ok": bool(record.get("ok")),
        "error": record.get("error"),
        "entries": len(entries),
        "dated_entries": counted,
        "hours": hours,
        "weekdays": weekdays,
        "weekday_labels": list(_WEEKDAYS),
        "first_seen": min(moments).isoformat(sep=" ") if moments else None,
        "last_seen": max(moments).isoformat(sep=" ") if moments else None,
        "span_days": (
            round((max(moments) - min(moments)).total_seconds() / 86400.0, 2)
            if len(moments) > 1
            else 0.0
        ),
        "peak_percent": max(percentages) if percentages else None,
        "peak_window": peak_window,
    }


def zone_protection_summary(events: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """The per-zone flood protection state and PBP drops read at start.

    The finding the corpus keeps producing is not "PBP fired": it is that PBP
    fired in a zone where flood protection was never enabled, so PBP was doing
    zone protection's job with a blunter tool.
    """
    table = start_event(events).get("zone_protection")
    if not isinstance(table, dict):
        return {"collected": False, "zones": [], "unprotected": []}
    zones = [zone for zone in table.get("zones") or [] if isinstance(zone, dict)]
    unprotected = [
        zone
        for zone in zones
        if zone.get("flood_protection_enabled") is False
        and (_first_number(zone.get("pbp_drop")) or 0.0) > 0
    ]
    return {
        "collected": bool(table.get("parsed")) or bool(zones),
        "zones": zones,
        "unprotected": unprotected,
        "dropping_zones": [
            zone
            for zone in zones
            if (_first_number(zone.get("pbp_drop")) or 0.0) > 0
        ],
    }


def ha_summary(events: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """The high-availability role of the monitored unit, read once at start."""
    state = start_event(events).get("ha_state")
    if not isinstance(state, dict):
        return {"collected": False}
    return {"collected": bool(state.get("parsed")), **state}


def inflight_monitoring_summary(events: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """The on-box ingress-backlog auto-collection state, read once at start."""
    state = start_event(events).get("inflight_monitoring")
    if not isinstance(state, dict):
        return {"collected": False}
    return {"collected": bool(state.get("parsed")), **state}


def raw_counter_bracket(events: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """The cumulative counters read at start and at stop, and their growth.

    A counter that moved fourteen times over an hour never appears in a
    per-batch delta whose window is a fraction of a second. The bracket is
    what makes it visible, and it is computed once, at collection time, so the
    report and the diagnosis cannot each derive a different growth.
    """
    started = start_event(events).get("global_counters_raw")
    stopped = latest_event(events, "global_counters_raw") or {}
    start_counters = (
        started.get("counters") if isinstance(started, dict) else None
    )
    stop_parsed = stopped.get("global_counters_raw")
    stop_counters = (
        stop_parsed.get("counters") if isinstance(stop_parsed, dict) else None
    )
    growth = stopped.get("growth_since_start")
    return {
        "collected": bool(start_counters) or bool(stop_counters),
        "start": start_counters if isinstance(start_counters, dict) else {},
        "stop": stop_counters if isinstance(stop_counters, dict) else {},
        "growth": growth if isinstance(growth, dict) else {},
    }


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


def buffer_latency_statuses(cycles: Sequence[dict[str, Any]]) -> list[str]:
    """Every non-empty ``buffer_latency`` status, in batch order.

    Shared by the diagnosis (which reports the first status a batch carried)
    and the HTML report's Buffer latency section, so the two can never name a
    different status for the same run.
    """
    return [
        str(record["buffer_latency"].get("status"))
        for record in cycles
        if isinstance(record.get("buffer_latency"), dict)
        and record["buffer_latency"].get("status")
    ]


def uptime_days(value: Any) -> float | None:
    """Parse PAN-OS's own uptime wording (``60 days, 4:22:03``) into days."""
    if not isinstance(value, str):
        return None
    match = re.search(r"(\d+)\s+days?,\s*(\d+):(\d+):(\d+)", value)
    if match is None:
        return None
    days, hours, minutes, seconds = (int(group) for group in match.groups())
    return round(days + (hours * 3600 + minutes * 60 + seconds) / 86400.0, 3)


#: What `show running resource-monitor ingress-backlogs` reports, per platform
#: family, and whether the node is expected to exist there.
#:
#: On the Cavium chassis the queue the command reports is the on-chip
#: descriptor queue itself. PAN-OS 10.2 brought the command to the x86
#: platforms, where the same percentages are the dataplane's in-flight work
#: entries over `max-inflight-num` (32768 by default) - the software
#: equivalent of that queue, not on-chip descriptors. A VM-Series runs that
#: same x86 dataplane and the metric means the same thing there; it was left
#: out of the x86 support (PAN-222805, still rejected on 11.2.3-h3), so the
#: PAN-OS CLI parser is expected to refuse the node and no credential, role or
#: network change repairs that.
#:
#: Nothing here is a verdict. What a firewall actually answered decides
#: whether the step has evidence: a VM-Series that returns data is read from
#: its data, and a platform whose family is listed as an in-flight one still
#: has nothing to read when it rejected the node. These entries only choose
#: the wording, per family: the metric the percentages measure, whether that
#: metric is the software in-flight queue, and the sentence to print when the
#: firewall answered that the node does not exist.
_IN_FLIGHT_WORK_METRIC = (
    "the in-flight work entries of the dataplane, as a percentage of its "
    "<code>max-inflight-num</code> (32768 by default)"
)
_GENERIC_NODE_ABSENT_REASON = (
    "This firewall answered that it has no <code>show running "
    "resource-monitor ingress-backlogs</code> node, so its own CLI parser "
    "rejected the command."
)
_VM_SERIES_NODE_ABSENT_REASON = (
    "PAN-OS introduced <code>show running resource-monitor "
    "ingress-backlogs</code> for the x86 platforms in 10.2 and left VM-Series "
    "out of that support, so this firewall rejected the node."
)
#: family -> (metric prose, metric is the in-flight work queue, absent reason)
_INGRESS_BACKLOG_METRICS = {
    "cavium": (
        "the on-chip descriptor queue of the chassis",
        False,
        _GENERIC_NODE_ABSENT_REASON,
    ),
    "x86": (_IN_FLIGHT_WORK_METRIC, True, _GENERIC_NODE_ABSENT_REASON),
    "virtual": (_IN_FLIGHT_WORK_METRIC, True, _VM_SERIES_NODE_ABSENT_REASON),
    "unknown": (
        "the work queue in front of the dataplane cores",
        False,
        _GENERIC_NODE_ABSENT_REASON,
    ),
}


def _generation(label: str, family: str, on_chip_descriptors: bool | None) -> dict[str, Any]:
    metric, in_flight, absent_reason = _INGRESS_BACKLOG_METRICS[family]
    return {
        "label": label,
        "family": family,
        "on_chip_descriptors": on_chip_descriptors,
        "ingress_backlog_metric": metric,
        "ingress_backlog_in_flight": in_flight,
        "ingress_backlog_absent_reason": absent_reason,
    }


def hardware_generation(model: Any) -> dict[str, Any]:
    """Name the platform family a model belongs to and what it can report."""
    text = str(model or "").strip().upper()
    if not text or text == "—":
        return _generation("unknown platform", "unknown", None)
    if text.startswith(_VIRTUAL_PREFIXES):
        return _generation("virtual platform", "virtual", False)
    if text.startswith(_X86_PREFIXES):
        return _generation("x86 platform (gen4)", "x86", False)
    if text.startswith(_CAVIUM_PREFIXES):
        return _generation("Cavium platform (gen3)", "cavium", True)
    return _generation("unknown platform", "unknown", None)


def command_succeeded(record: Any) -> bool:
    """Did this stored command record come back with a usable answer?

    Accepts the legacy string form a very old capture carries as well as the
    structured record. `orchestrator` re-exports it.
    """
    if isinstance(record, str):
        return not record.startswith("ERROR:")
    return isinstance(record, dict) and record.get("ok") is True


#: Evidence that exists only on some platforms or PAN-OS releases. A command
#: listed here stays mandatory: it is downgraded to a note only when the
#: firewall itself answers that the node does not exist, never when the read
#: fails for a reason the operator could fix. PAN-OS introduced
#: `ingress-backlogs` for the x86 platforms in 10.2 and left VM-Series out of
#: that support (PAN-222805, still rejected on 11.2.3-h3), so the CLI parser
#: refuses the node there.
#:
#: An absent node is not reduced evidence: no role, no upgrade and no
#: configuration makes a VM-Series answer this command. Reporting it amber
#: would leave every VM-Series permanently amber, which is how an operator
#: learns to stop reading amber, so it is recorded as a note beside a check
#: that passes.
PLATFORM_DEPENDENT_COMMAND_EVIDENCE = {
    "ingress_backlogs": "the per-dataplane ingress backlog work-queue levels",
}

#: Fragments PAN-OS uses to reject a command its parser does not know on this
#: platform or release, as opposed to one it knows and could not run.
_UNSUPPORTED_NODE_MARKERS = (
    "unexpected here",
    "is unexpected",
    "no such node",
    "unknown command",
)


def command_node_unsupported(record: Any) -> bool:
    """Did the firewall reject the command as a node it does not have?

    A rejection by the PAN-OS CLI parser means the command does not exist on
    this model or release, which no credential, role or network change would
    repair. Every other failure - a timeout, an HTTP status, a denied
    permission - stays a collection failure.

    This reads nothing but the stored record, so the validation that runs the
    command and the diagnosis that reads it back out of a capture classify a
    rejection identically. `orchestrator` re-exports it.
    """
    if not isinstance(record, dict) or record.get("ok") is True:
        return False
    error = str(record.get("error") or "").lower()
    if not error.startswith("panosapierror:"):
        return False
    return any(marker in error for marker in _UNSUPPORTED_NODE_MARKERS)


def command_outcome(record: Any, name: str) -> str:
    """What one stored command record establishes for the batch that ran it.

    Four outcomes, and only the first one carries evidence:

    * ``succeeded`` - the firewall answered, so the parsed field means what it
      says.
    * ``unsupported`` - the PAN-OS CLI parser rejected the command as a node
      this platform does not have, which no credential, role or upgrade
      repairs. Only the commands declared platform-dependent qualify: a
      mandatory command rejected by an old release is a real gap in the
      evidence and stays a failure.
    * ``failed`` - every other unanswered read: a timeout, an HTTP status, a
      denied permission. An operator can act on it.
    * ``missing`` - the batch never carried the command at all, which is what
      a capture written before the command existed looks like.

    This is the single classification every reader uses - the diagnosis steps,
    the report health view and the read-only validation - so a batch is never
    described one way in the report and another way in the check.
    """
    if record is None:
        return "missing"
    if command_succeeded(record):
        return "succeeded"
    if name in PLATFORM_DEPENDENT_COMMAND_EVIDENCE and command_node_unsupported(record):
        return "unsupported"
    return "failed"


def command_outcomes(
    cycles: Sequence[dict[str, Any]],
    name: str,
    legacy_evidence: Callable[[dict[str, Any]], bool] | None = None,
) -> dict[str, int]:
    """Split the batches by what one per-batch command actually returned.

    `batches` counts the batches that attempted the read, not every cycle, so
    the three outcomes always add up to it.

    A capture written before the raw command travelled in the batch record
    carries nothing but the parsed field, and every parser answers a
    well-formed empty structure to a failed read. Such a batch therefore
    counts as one that never asked, unless `legacy_evidence` recognizes in the
    parsed field something only a real answer produces.
    """
    counts = {"batches": 0, "succeeded": 0, "unsupported": 0, "failed": 0}
    for record in cycles:
        commands = record.get("commands")
        payload = commands.get(name) if isinstance(commands, dict) else None
        outcome = command_outcome(payload, name)
        if outcome == "missing":
            if legacy_evidence is not None and legacy_evidence(record):
                counts["batches"] += 1
                counts["succeeded"] += 1
            continue
        counts["batches"] += 1
        counts[outcome] += 1
    return counts


def collected_field(record: dict[str, Any], field: str) -> dict[str, Any] | None:
    """The parsed field of a batch, or None when that read never answered.

    Since the write-time gate, a per-batch command that failed persists
    ``{"error": ...}`` in place of a parsed structure the firewall never
    returned. A reader must not mistake that marker for a firewall that
    answered nothing was wrong, so every reader asks this question here.
    """
    value = record.get(field)
    if not isinstance(value, dict):
        return None
    if set(value) == {"error"}:
        return None
    return value


def _legacy_ingress_evidence(record: dict[str, Any]) -> bool:
    """Did a capture without the raw command still record a real backlog read?"""
    parsed = record.get("ingress_backlogs")
    return isinstance(parsed, dict) and bool(
        parsed.get("dataplanes") or parsed.get("candidates")
    )


def _legacy_pbp_evidence(record: dict[str, Any]) -> bool:
    """Did a capture without the raw command still record a real PBP read?

    `extract_pbp_status` leaves every state undecided when it is handed the
    empty string of a failed read, so a status that decided anything - or a
    single offender row - is the proof the firewall answered.
    """
    status = collected_field(record, "pbp_status")
    if status is not None and any(
        status.get(key) is not None
        for key in ("enabled", "active", "congestion_percentage")
    ):
        return True
    offenders = record.get("pbp_offenders")
    return isinstance(offenders, list) and bool(offenders)


def _legacy_session_evidence(record: dict[str, Any]) -> bool:
    """Did a capture without the raw command still record a real session read?"""
    info = collected_field(record, "session_info")
    if info is None:
        return False
    if isinstance(info.get("dataplanes"), list) and info["dataplanes"]:
        return True
    totals = info.get("totals")
    return isinstance(totals, dict) and any(
        isinstance(value, (int, float)) for value in totals.values()
    )


def pbp_read_collection(cycles: Sequence[dict[str, Any]]) -> dict[str, int]:
    """Split the batches by what the PBP read returned."""
    return command_outcomes(cycles, "packet_buffer_protection", _legacy_pbp_evidence)


def session_info_collection(cycles: Sequence[dict[str, Any]]) -> dict[str, int]:
    """Split the batches by what the session-table read returned."""
    return command_outcomes(cycles, "session_info", _legacy_session_evidence)


def ingress_backlog_collection(cycles: Sequence[dict[str, Any]]) -> dict[str, int]:
    """Split the batches by what the ingress-backlogs read actually returned.

    A batch whose command the firewall rejected as a node it does not have
    carries no backlog evidence, and neither does one that timed out. Only the
    batches that ran the command can answer the question, so they are the only
    ones counted. The two failure modes stay apart: a rejected node is a
    platform capability gap nothing on the collector side can fix, while a
    timeout or a denied permission is a collection fault an operator acts on.
    """
    return command_outcomes(cycles, "ingress_backlogs", _legacy_ingress_evidence)


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


DEFAULT_LATENCY_ALERT_MS = 50.0
DEFAULT_LATENCY_ACTIVATE_MS = 200.0
DEFAULT_LATENCY_MAX_TOLERATE_MS = 500.0


def _configured_settings(events: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """The PBP settings read from the running configuration.

    The read at stop wins over the read at start when both parsed and differ:
    a monitor started during a commit reads the old configuration while the
    dataplane already applies the new thresholds. The result says whether
    that happened, and whether the read at start returned nothing at all - in
    which case the values are the ones in force at stop and may not describe
    the whole run.
    """
    start: dict[str, Any] = {}
    reread: dict[str, Any] = {}
    changed = False
    start_unknown = False
    for record in events:
        event = str(record.get("event", "")).lower()
        settings = record.get("pbp_settings")
        if event == "pbp_settings_reread":
            start_unknown = bool(record.get("start_settings_unknown"))
        if not isinstance(settings, dict) or settings.get("status") != "parsed":
            continue
        if event == "monitor_started" and not start:
            start = settings
        elif event == "pbp_settings_reread":
            reread = settings
            changed = bool(record.get("changed_since_start"))
    chosen = reread if reread and changed else (start or reread)
    if not chosen:
        return {}
    return {
        **chosen,
        "changed_during_run": changed,
        "start_unknown": start_unknown and not changed,
    }


def _threat_log_summary(events: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Count the PBP threat logs captured at monitor stop, per ID and source.

    ``bounded`` says whether the query carried a ``receive_time`` filter. When
    the firewall clock could not be read the query returns the most recent PBP
    threat logs of the device, of any age: they corroborate at best, and the
    diagnosis must never present them as confirming this incident.
    """
    record = latest_event(events, "pbp_threat_logs")
    summary: dict[str, Any] = {
        "collected": record is not None,
        "ok": bool(record and record.get("ok") is True),
        "error": record.get("error") if record else None,
        "bounded": bool(
            record.get("time_bounded") or record.get("since_firewall_time")
        )
        if record
        else False,
        "counts": {},
        "sources": {},
        "entries": [],
    }
    if not summary["ok"] or not isinstance(record.get("entries"), list):
        return summary
    for entry in record["entries"]:
        if not isinstance(entry, dict):
            continue
        threat_id = entry.get("threat_id")
        try:
            threat_id = int(threat_id)
        except (TypeError, ValueError):
            continue
        summary["counts"][threat_id] = summary["counts"].get(threat_id, 0) + 1
        source = entry.get("source_ip")
        if source:
            item = summary["sources"].setdefault(str(source), {"ids": set(), "count": 0})
            item["ids"].add(threat_id)
            item["count"] += 1
        summary["entries"].append(entry)
    return summary


_THREAT_LABELS = {8507: "PBP Packet Drop", 8508: "PBP Session Discarded", 8509: "PBP IP Blocked"}


def syslog_alert_known(context: dict[str, Any]) -> bool:
    """Whether the alert percentage in the context came from the syslog text."""
    return context.get("alert_percent") is not None and (
        context.get("configured_alert_percent") is None
        or context["alert_percent"] != context["configured_alert_percent"]
    )


_BUFFER_BACKED_POOL_MARKERS = (
    "packet buffer",
    "packet descriptor",
    "descriptor",
    "pkt buf",
    # "pki pool dflt" is the on-chip packet pool, the congestion alert's own
    # denominator: it fills with the buffers, by construction.
    "pki pool",
)


def _is_buffer_backed_pool(pool: dict[str, Any]) -> bool:
    """Whether a diagnostic pool is the packet buffer or descriptor memory.

    Such a pool near full during buffer pressure describes the pressure, not
    resources held by a leak, so the leak signature must not read it as one.
    """
    name = str(pool.get("name") or "").strip().lower()
    return any(marker in name for marker in _BUFFER_BACKED_POOL_MARKERS)


def _pbp_statuses(cycles: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """The PBP states the firewall actually returned, failed reads excluded."""
    return [
        status
        for record in cycles
        if (status := collected_field(record, "pbp_status")) is not None
    ]


def _ingress_candidate_entities(
    attribution: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    """The sessions the ingress work queue named, in queue-share order.

    Step 3 of the investigation and the Ingress backlog table list the same
    sessions in the same order because they call this one selector.
    """
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
    return candidates


#: PAN-OS named the backlog entry an internal tag itself, in the "Special
#: Notes" column of its TOP SESSIONS table. That column is the only evidence
#: the collector accepts for a tag.
SPECIAL_TAG_NOTED = "noted"
#: `show session id` answered Bad Key: the ID exists in the backlog but no
#: session is behind it. Established by the lookup, never guessed.
NO_SESSION_BAD_KEY = "bad_key"
#: What an internal tag actually is, in one phrase, wherever it is explained.
INTERNAL_TAG_DESCRIPTION = (
    "host proxy for WildFire, or log forwarding to the management plane"
)


def _count(number: int, singular: str, plural: str | None = None) -> str:
    """"3 sessions" or "1 session": one place decides, so no sentence disagrees."""
    return f"{_fmt(number)} {singular if number == 1 else plural or singular + 's'}"


def _special_tag_field(item: dict[str, Any], key: str) -> Any:
    """Read a special-tag field from wherever this view carries it.

    The same fact rides on the aggregated entity, on the backlog entry it came
    from and on the session summary, depending on which renderer built the
    item. One scan keeps every caller reading the same value.
    """
    for source in (item, item.get("ingress_detail"), item.get("session_summary")):
        if isinstance(source, dict) and source.get(key):
            return source[key]
    return None


def _no_session_behind(item: dict[str, Any]) -> str | None:
    """Why no session lies behind this backlog SESS-ID, or None if one does.

    Two things can say it, and they are not interchangeable. PAN-OS naming the
    row in its "Special Notes" column means the entry is the firewall's own
    traffic and never an offender. `show session id` answering Bad Key means
    the packets never created a session, which is exactly what traffic denied
    by policy looks like. Every view resolves this once, here, so a Bad Key row
    and the diagnosis sentence about it can never disagree.
    """
    if _special_tag_field(item, "special_reason") == SPECIAL_TAG_NOTED:
        return SPECIAL_TAG_NOTED
    summary = item.get("session_summary")
    status = summary.get("status") if isinstance(summary, dict) else None
    return NO_SESSION_BAD_KEY if status == "bad_key" else None


def _is_policy_deny_shape(item: dict[str, Any], groups: Iterable[Any] = ()) -> bool:
    """`flow_slowpath` with no session behind the ID: denied by policy.

    An internal tag never enters this rule: it is the firewall's own traffic,
    not packets a security policy refused.
    """
    return _no_session_behind(item) == NO_SESSION_BAD_KEY and "flow_slowpath" in {
        str(group).lower() for group in groups
    }


def special_tag_label(item: dict[str, Any]) -> str:
    """The one wording for a backlog SESS-ID with no session behind it.

    The diagnosis step, the Ingress table and the offender ranking all render
    this string, so the three never describe the same entry differently.
    """
    kind = _no_session_behind(item)
    if kind == SPECIAL_TAG_NOTED:
        return "internal tag, not a session"
    return "missing session / Bad Key" if kind == NO_SESSION_BAD_KEY else ""


def merge_special_fields(target: dict[str, Any], source: dict[str, Any]) -> None:
    """Carry the special-tag fields of one observation onto an aggregate.

    A reason PAN-OS stated is sticky: once any batch has seen the note, the
    entity stays an internal tag for the whole capture, because a later batch
    that merely truncated the column must not turn it back into a session.
    """
    reason = source.get("special_reason")
    if reason and (
        target.get("special_reason") is None or reason == SPECIAL_TAG_NOTED
    ):
        target["special_reason"] = str(reason)
    note = source.get("special_note")
    if note and not target.get("special_note"):
        target["special_note"] = str(note)


def _flow_parts(item: dict[str, Any]) -> tuple[str, str]:
    """Describe an attributed entity's flow and its application context.

    The single description of a ranked entity: the diagnosis names the entity
    in a sentence and the report puts the same two strings in its table cells,
    so a session can never be shown with one application in the verdict and
    another in the evidence. Both are empty when nothing was parsed; the caller
    decides what an empty cell looks like.
    """
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
        # The session summary wins when it named an application; the ingress
        # backlog entry only fills the gap. Overwriting with the backlog's
        # value would blank an application `show session id` did return.
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
    tuple_text, context = _flow_parts(item)
    details = [part for part in (tuple_text, context) if part]
    zones = ", ".join(str(zone) for zone in item.get("zones", []) if zone)
    if zones:
        details.append(f"zone {zones}")
    if details:
        text += f" ({_escape(' · '.join(details))})"
    return text


def _traffic_log_summary(events: Sequence[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Count, per unenriched source, what its traffic log said (rule, action)."""
    record = latest_event(events, "offender_traffic_logs")
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
    signal_summary: dict[str, Any] | None = None,
    diagnostic_pools: Sequence[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Walk the investigation and return its steps and conclusion.

    ``cpu_verdicts`` carries one entry per dataplane with ``state`` (``calm``,
    ``isolated``, ``collective`` or ``mixed``), the hottest core and its peak,
    exactly as the CPU section states them, so the two never disagree.
    ``signal_summary`` and ``diagnostic_pools`` are the root-cause counter
    families and the held-pool table exactly as the evidence sections render
    them, for the same reason.
    """
    steps: list[dict[str, Any]] = []
    # The threat logs taken at monitor stop are read once, here, and handed to
    # every step that needs them: two scans could not disagree, but one scan
    # makes it impossible for a later change to make them.
    threat_logs = _threat_log_summary(events)
    context = _context(cycles, events, device, threat_logs)

    pressure = _step_pressure(cycles, context)
    steps.append(pressure)
    low_significance = pressure["low_significance"]

    named = _step_pbp_named(cycles, attribution, events, low_significance, threat_logs)
    steps.append(named)

    backlogs = _step_ingress_backlogs(cycles, attribution, context)
    steps.append(backlogs)

    elsewhere = _step_elsewhere(
        drop_summary, session_series, large_sessions, cpu_verdicts, cycles,
        attribution, events, low_significance,
        context=context,
        signal_summary=signal_summary,
        diagnostic_pools=diagnostic_pools,
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
    threat_logs: dict[str, Any] | None = None,
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
    settings = _configured_settings(events)
    configured_alert = _first_number(settings.get("alert_percent"))
    configured_activate = _first_number(settings.get("activate_percent"))
    syslog_alert = _configured_alert_percent(events)
    # The congestion of the first batch that caught PBP mitigating: the level
    # at which mitigation started. A later batch reading lower is ordinary
    # decay - PBP stays listed active while the congestion falls back - and
    # says nothing about the activate threshold.
    mitigating_from = next(
        (
            value
            for status in statuses
            if status.get("active") is True
            and (value := _first_number(status.get("congestion_percentage")))
            is not None
        ),
        None,
    )
    if settings:
        alert = configured_alert if configured_alert is not None else DEFAULT_ALERT_PERCENT
        activate = configured_activate if configured_activate is not None else DEFAULT_ACTIVATE_PERCENT
        alert_source = "configuration"
        # PBP cannot start mitigating below its activate threshold. When it
        # does, the read did not return the thresholds in force — a commit
        # landing during the read is one explanation, a threshold set outside
        # this xpath is another — so state the contradiction and fall back
        # rather than asserting a cause the capture cannot prove. Only the
        # onset counts, and only beyond a rounding margin: an incident decaying
        # below the threshold while PBP is still listed active contradicts
        # nothing.
        if (
            mitigating_from is not None
            and mitigating_from < activate - MITIGATION_THRESHOLD_MARGIN_PERCENT
        ):
            alert_source = "inconsistent"
            alert = syslog_alert if syslog_alert is not None else alert
    elif syslog_alert is not None:
        alert, activate, alert_source = syslog_alert, None, "firewall"
    else:
        alert, activate, alert_source = None, None, "default"
    latency_values = [
        value
        for record in cycles
        if isinstance(record.get("buffer_latency"), dict)
        and (value := _first_number(record["buffer_latency"].get("peak_ms"))) is not None
    ]
    latency_statuses = buffer_latency_statuses(cycles)
    latency_status = latency_statuses[0] if latency_statuses else None
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
        "mitigating_from_percent": mitigating_from,
        "alert_percent": alert,
        "activate_percent": activate,
        "alert_source": alert_source,
        "configured_alert_percent": configured_alert,
        "configured_activate_percent": configured_activate,
        # What the firewall's own congestion log announced, kept beside the
        # configuration read so a report can name the two when they disagree.
        "syslog_alert_percent": syslog_alert,
        "settings_changed_during_run": bool(settings.get("changed_during_run")) if settings else False,
        # The read at start returned no PBP configuration while the read at
        # stop did: the values describe the end of the run, and the report
        # says so rather than presenting them as the run's thresholds.
        "settings_start_unknown": bool(settings.get("start_unknown")) if settings else False,
        "configured_enabled": settings.get("enabled") if settings else None,
        "latency_alert_ms": _first_number(settings.get("latency_alert_ms")) if settings else None,
        "latency_activate_ms": _first_number(settings.get("latency_activate_ms")) if settings else None,
        "latency_max_tolerate_ms": _first_number(settings.get("latency_max_tolerate_ms")) if settings else None,
        "latency_peak_ms": max(latency_values) if latency_values else None,
        "latency_status": latency_status,
        "threat_logs": threat_logs
        if threat_logs is not None
        else _threat_log_summary(events),
        "uptime": str(device.get("uptime"))
        if isinstance(device, dict) and device.get("uptime")
        else None,
        "uptime_days": uptime_days(
            device.get("uptime") if isinstance(device, dict) else None
        ),
        # The once-per-incident state and history reads. Everything below is
        # derived from the capture alone; a capture taken before these
        # commands existed simply reports them as not collected.
        "ha": ha_summary(events),
        "zone_protection": zone_protection_summary(events),
        "inflight_monitoring": inflight_monitoring_summary(events),
        "buffer_history": history_trend(events),
        "recurrence": congestion_recurrence(events),
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
    latency_peak = context["latency_peak_ms"]
    latency_activate = context["latency_activate_ms"] or DEFAULT_LATENCY_ACTIVATE_MS
    mitigating_from = context["mitigating_from_percent"]
    descriptor_worst = max(
        (value for value in (on_chip_peak, descriptor_peak) if value is not None),
        default=None,
    )
    # The severity of each resource, decided once against the thresholds this
    # firewall runs with. The step states these levels, the layered report's
    # proof tiles show the same ones, and neither re-derives them.
    buffer_level = _level(buffer_peak, alert)
    descriptor_level = _level(descriptor_worst, alert, DESCRIPTOR_EXHAUSTION_PERCENT)

    facts: list[tuple[str, str, str]] = [
        ("Packet buffer peak", _pct(buffer_peak), buffer_level),
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
    if context["alert_source"] == "configuration":
        threshold_text = (
            f"alert {_fmt(alert)}% and activate {_fmt(context['activate_percent'])}%, "
            "read from the running configuration"
        )
        if context["settings_changed_during_run"]:
            threshold_text += (
                " at monitor stop; the values read at start differed, so a "
                "commit landed during the incident"
            )
        elif context["settings_start_unknown"]:
            threshold_text += (
                " at monitor stop; the read at monitor start returned no PBP "
                "configuration, so the start-of-run settings are unknown and "
                "these values may not describe the whole run"
            )
        if context["configured_enabled"] is False:
            threshold_text += "; PBP is disabled in the configuration"
    elif context["alert_source"] == "inconsistent":
        threshold_text = (
            f"the running configuration read alert "
            f"{_fmt(context['configured_alert_percent'] if context['configured_alert_percent'] is not None else DEFAULT_ALERT_PERCENT)}% "
            f"and activate {_fmt(context['configured_activate_percent'] if context['configured_activate_percent'] is not None else DEFAULT_ACTIVATE_PERCENT)}%, "
            f"yet PBP was mitigating at {_fmt(mitigating_from)}%, which it cannot do "
            "below its activate threshold, so the read does not describe the "
            "thresholds that were in force"
            + (
                f"; the firewall's own congestion log says alert {_fmt(alert)}%"
                if context["alert_percent"] is not None and syslog_alert_known(context)
                else ""
            )
        )
    elif context["alert_source"] == "firewall":
        threshold_text = f"alert {_fmt(alert)}% as printed by the firewall's own congestion log"
    else:
        threshold_text = (
            f"PAN-OS defaults, alert {_fmt(DEFAULT_ALERT_PERCENT)}% and activate "
            f"{_fmt(DEFAULT_ACTIVATE_PERCENT)}%, because neither the configuration "
            "nor a trigger carried the configured value"
        )
    if mitigating_from is not None and context["alert_source"] != "inconsistent":
        threshold_text += (
            f"; PBP was observed mitigating from {_fmt(mitigating_from)}%"
            + (
                ""
                if context["alert_source"] == "configuration"
                else ", so the activate threshold is at or below that value"
            )
        )
    facts.append(("Thresholds", threshold_text, "none"))
    latency_alert = context["latency_alert_ms"] or DEFAULT_LATENCY_ALERT_MS
    latency_level = "none"
    if latency_peak is not None:
        latency_level = (
            "bad" if latency_peak >= latency_activate
            else "warn" if latency_peak >= latency_alert
            else "ok"
        )
        facts.append(
            (
                "Buffer latency peak",
                f"{_fmt(latency_peak)} ms (latency alert {_fmt(latency_alert)} ms, "
                f"activate {_fmt(latency_activate)} ms)",
                latency_level,
            )
        )
    elif context["latency_status"] == "disabled":
        facts.append(("Buffer latency", "measurement disabled on the firewall", "none"))

    low_significance = False
    if buffer_peak is None and descriptor_worst is None and latency_peak is None:
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
            f"{_pct(buffer_peak)}.</strong> Descriptors peaked at {_fmt(descriptor_worst)}%"
            + (
                f" and the buffer latency at {_fmt(latency_peak)} ms"
                if latency_peak is not None
                else ""
            )
            + ". That is the latency case: the queue in front of the dataplane cores "
            "fills before the buffers do, so buffer-based PBP may never activate and "
            "the culprit has to come from the ingress backlogs or from a single "
            "session pinned to one core."
        )
    elif latency_peak is not None and latency_peak >= latency_activate:
        state, level = "positive", "bad"
        verdict = (
            f"<strong>Dataplane latency reached {_fmt(latency_peak)} ms while the "
            f"buffers stayed at {_pct(buffer_peak)}.</strong> That is above the "
            f"{_fmt(latency_activate)} ms latency activate threshold"
            + (
                ", and this firewall runs latency-based PBP, so it was mitigating on "
                "latency rather than on buffer utilization"
                if "latency" in context["pbp_modes"]
                else ", the level at which latency-based PBP would act; this firewall "
                "runs buffer-based PBP, which does not see it"
            )
            + ". Packets waited in front of the dataplane cores; the culprit has to "
            "come from the ingress backlogs or from a single session pinned to one core."
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
                if context["alert_source"] != "default" and buffer_peak is not None and buffer_peak >= alert
                else ""
            )
            + (
                f" and the buffer latency stayed at {_fmt(latency_peak)} ms"
                if latency_peak is not None
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
                + (
                    f" with the activate threshold configured at {_fmt(context['activate_percent'])}%"
                    if context["activate_percent"] is not None and context["alert_source"] == "configuration"
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
        "latency_peak_ms": latency_peak,
        "buffer_level": buffer_level,
        "descriptor_level": descriptor_level,
        "latency_level": latency_level,
        "low_significance": low_significance,
    }


def _step_pbp_named(
    cycles: Sequence[dict[str, Any]],
    attribution: Sequence[dict[str, Any]],
    events: Sequence[dict[str, Any]],
    low_significance: bool,
    threat_logs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    statuses = _pbp_statuses(cycles)
    collection = pbp_read_collection(cycles)
    # A firewall too loaded to answer `show session packet-buffer-protection`
    # is the very condition this collector exists for. Its failed reads parse
    # to an undecided status, which must never become "PBP never activated".
    read_failed = collection["succeeded"] == 0 and collection["failed"] > 0
    if threat_logs is None:
        threat_logs = _threat_log_summary(events)
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
        (
            "PBP activated",
            "yes" if activated else "unknown" if read_failed else "no",
            "none",
        ),
        ("Entries learned", _fmt(len(learned)), "none"),
        ("Marked for RED", _fmt(len(marked)), "none"),
    ]
    if collection["failed"]:
        # Only stated when a read actually failed: a row reading zero on every
        # healthy capture is a row an operator stops seeing.
        facts.append(("Batches with the PBP read", _fmt(collection["succeeded"]), "none"))
        facts.append(("Batches with a failed read", _fmt(collection["failed"]), "warn"))
    # A query the firewall clock could not bound returns the most recent PBP
    # threat logs of the device, of any age. They stay in the report as
    # corroboration, but nothing here may be counted as evidence of *this*
    # incident: not the verdict, not the designations, not the level.
    bounded = bool(threat_logs["bounded"])
    confirming_counts = threat_logs["counts"] if bounded else {}
    if threat_logs["collected"]:
        if threat_logs["ok"]:
            counted = ", ".join(
                f"{count} × {threat_id} {_THREAT_LABELS.get(threat_id, '')}".strip()
                for threat_id, count in sorted(threat_logs["counts"].items())
            )
            if not counted:
                counted = (
                    "none in the window"
                    if bounded
                    else "none in the most recent entries"
                )
            elif not bounded:
                counted += (
                    " — not limited to the incident window: the firewall clock "
                    "could not be read, so these entries may predate it"
                )
            facts.append(
                ("PBP threat logs", counted, "bad" if confirming_counts else "ok")
            )
        else:
            facts.append(("PBP threat logs", f"query failed: {threat_logs['error'] or 'unknown'}", "none"))
    named: list[str] = []
    blocked = sorted(
        (source for source, item in threat_logs["sources"].items() if 8509 in item["ids"]),
        key=lambda source: -threat_logs["sources"][source]["count"],
    )
    discarded = sorted(
        (source for source, item in threat_logs["sources"].items() if 8508 in item["ids"]),
        key=lambda source: -threat_logs["sources"][source]["count"],
    )
    threat_text = ""
    if threat_logs["ok"] and threat_logs["counts"] and not bounded:
        threat_text = (
            " The firewall's threat log holds "
            + ", ".join(
                f"{count} × {_THREAT_LABELS.get(threat_id, threat_id)} ({threat_id})"
                for threat_id, count in sorted(threat_logs["counts"].items())
            )
            + ", but the query could not be limited to the incident window - the "
            "firewall clock could not be read - so these are simply the most "
            "recent PBP threat logs of the device and may belong to an earlier "
            "episode. They corroborate at best: they neither confirm this "
            "incident nor name a source for it."
        )
    elif threat_logs["ok"] and threat_logs["counts"]:
        threat_text = (
            " The firewall's own threat log confirms it: "
            + ", ".join(
                f"{count} × {_THREAT_LABELS.get(threat_id, threat_id)} ({threat_id})"
                for threat_id, count in sorted(threat_logs["counts"].items())
            )
            + (
                "; source address"
                + ("es " if len(blocked) != 1 else " ")
                + ", ".join(f"<code>{_escape(source)}</code>" for source in blocked[:_MAX_NAMED])
                + (" were" if len(blocked) != 1 else " was")
                + " placed in the block table (8509)"
                if blocked
                else ""
            )
            + (
                "; a session of "
                + ", ".join(f"<code>{_escape(source)}</code>" for source in discarded[:_MAX_NAMED])
                + " was discarded (8508)"
                if discarded
                else ""
            )
            + "."
        )
    unavailable_reason = ""
    if not activated and not confirming_counts and read_failed:
        state, level = "failed", "warn"
        unavailable_reason = (
            f"read failed in {collection['failed']} of "
            f"{collection['batches']} batches"
        )
        verdict = (
            f"<strong>The PBP read failed in all {collection['failed']} of the "
            f"{collection['batches']} batches</strong>, so whether the firewall "
            "activated PBP and whom it designated is unknown. This is not a "
            "negative result: a firewall loaded enough to leave "
            "<code>show session packet-buffer-protection</code> unanswered is "
            "exactly the state this step exists to read. The failure - a "
            "timeout, or a permission the API role does not have - is worth "
            "repairing before the next incident; until then the ingress "
            "backlogs and the wider evidence carry this question."
            + threat_text
        )
    elif not activated and not confirming_counts:
        state, level = "negative", "ok"
        verdict = (
            "<strong>PBP never activated, so it learned no offender.</strong> An "
            "alert-only PBP reports the utilization and nothing else: no threat "
            "log, no RED, no ranked session. The culprit has to come from the "
            "ingress backlogs or from the wider evidence."
            + threat_text
        )
    elif not marked and not confirming_counts:
        state, level = "negative", "ok"
        verdict = (
            f"<strong>PBP activated and learned {len(learned)} entries, but marked "
            "none for RED.</strong> The work was spread over many small entries "
            "rather than concentrated on one session or source, which points away "
            "from a single offender and towards a burst or aggregate load."
            + threat_text
        )
    elif not marked:
        state = "positive"
        level = "warn" if low_significance else "bad"
        for source in [*blocked, *[item for item in discarded if item not in blocked]][:_MAX_NAMED]:
            item = threat_logs["sources"][source]
            named.append(
                f"source IP <code>{_escape(source)}</code> — "
                + ", ".join(_THREAT_LABELS.get(threat_id, str(threat_id)) for threat_id in sorted(item["ids"]))
            )
        if not named:
            for source, item in sorted(threat_logs["sources"].items(), key=lambda pair: -pair[1]["count"])[:_MAX_NAMED]:
                named.append(f"source IP <code>{_escape(source)}</code> — {item['count']} PBP Packet Drop log(s)")
        verdict = (
            "<strong>No batch caught an entry marked for RED, but the firewall's "
            "threat log did.</strong> PBP had already acted before or between the "
            "batches; the designations below come from the threat log captured at "
            "monitor stop, with the same caveat: the firewall's own list, not a proof."
            + threat_text
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
        if threat_text:
            parts.append(threat_text.strip())
        if low_significance:
            parts.append(
                "Read this list with the low pressure of step 1 in mind: at that level "
                "the ranking is the busiest ordinary traffic, not an attack."
            )
        verdict = " ".join(parts)
    # A batch that answered nothing is worth naming wherever the step landed.
    # The "read failed" verdict already speaks of nothing else.
    if state != "failed" and collection["failed"]:
        verdict += (
            f" Not every batch answered: the PBP read failed in "
            f"{collection['failed']} of the {collection['batches']} batches, "
            "which therefore carry no PBP evidence."
        )
    return {
        "number": 2,
        "key": "pbp",
        "title": "Did the firewall already name the offender?",
        "finding_title": "Offender named by PBP",
        "state": state,
        "level": level,
        "verdict": verdict,
        "facts": facts,
        "named": named,
        "sessions": sessions,
        "sources": sources,
        "anchor": "attribution-title",
        # One line saying why this step has no answer, for a report that folds
        # it away beside the other unanswered questions.
        "unavailable_reason": unavailable_reason,
        # What this step reports is PBP's own ranking. Under the low pressure
        # of step 1 that ranking is the busiest ordinary traffic, and a report
        # must be able to tell it apart from an observation made independently
        # of PBP.
        "ranking_derived": True,
    }


#: What the on-box read itself established, which is not the same question as
#: what the state says. `absent` is an answer — the release does not have the
#: feature, so `pan_ingress_backlogs.log` is known to hold nothing and there
#: is nothing for the operator to enable. `not_collected` is a lost read, and
#: leaves the tech support file's contents genuinely unknown. Reporting the
#: two the same way would send an operator hunting for a setting that does not
#: exist, or leave a failed read looking like a settled fact.
INFLIGHT_MONITORING_READ = "read"
INFLIGHT_MONITORING_ABSENT = "absent"
INFLIGHT_MONITORING_NOT_COLLECTED = "not_collected"

#: The management-plane log PAN-OS writes when the on-box collection fires,
#: and the command that turns the collection on. Both are named by the step
#: and by the report, from here, so the two can never print different ones.
INGRESS_BACKLOG_LOG_PATH = "/var/log/pan/pan_ingress_backlogs.log"
INGRESS_BACKLOG_ENABLE_COMMAND = "set session inflight_monitoring yes"
#: PAN-OS defaults, used only when the firewall did not return its own values
#: and always rendered as assumed rather than as the firewall's own.
DEFAULT_INGRESS_BACKLOG_THRESHOLD_PERCENT = 80
DEFAULT_INGRESS_BACKLOG_DURATION_SECONDS = 3


def inflight_monitoring_state(summary: dict[str, Any] | None) -> dict[str, Any]:
    """The one reading of the on-box collection state every renderer formats.

    The fact line of step 3, the step's verdict and the Ingress section of both
    reports each used to decide on their own whether a missing threshold meant
    the PAN-OS default or an unknown, and they could disagree inside one page.
    They now all format this dict.

    `enabled` is True only for a boolean True, so a firewall answering
    something neither renderer expected is reported as unknown rather than as
    enabled. `threshold_percent` and `duration_seconds` are the values to
    print, and `defaulted` says they are the PAN-OS defaults assumed because
    the nodes were not returned — never presented as the firewall's own.
    `status` separates a release without the feature from a read that failed.
    """
    summary = summary or {}
    enabled = summary.get("enabled")
    threshold = _first_number(summary.get("threshold_percent"))
    duration = _first_number(summary.get("duration_seconds"))
    status = str(
        summary.get("status")
        or (INFLIGHT_MONITORING_READ if enabled is not None else INFLIGHT_MONITORING_NOT_COLLECTED)
    )
    return {
        "enabled": True if enabled is True else False if enabled is False else None,
        "status": status,
        "threshold_percent": (
            threshold if threshold is not None else DEFAULT_INGRESS_BACKLOG_THRESHOLD_PERCENT
        ),
        "duration_seconds": (
            duration if duration is not None else DEFAULT_INGRESS_BACKLOG_DURATION_SECONDS
        ),
        "defaulted": threshold is None or duration is None,
    }


def inflight_monitoring_settings_text(state: dict[str, Any]) -> str:
    """`80% for 3 s`, saying so when those are assumed defaults."""
    text = f"{_pct(state['threshold_percent'])} for {_fmt(state['duration_seconds'])} s"
    if state["defaulted"]:
        text += ", PAN-OS defaults: the nodes were not returned"
    return text


def inflight_monitoring_fact(state: dict[str, Any]) -> str:
    """The on-box auto-collection state as one line of the step's fact table."""
    if state["enabled"] is True:
        return f"enabled ({inflight_monitoring_settings_text(state)})"
    if state["enabled"] is False:
        return "disabled"
    if state["status"] == INFLIGHT_MONITORING_ABSENT:
        return "not available on this PAN-OS release"
    return "not read"


def inflight_monitoring_note(state: dict[str, Any]) -> str:
    """What the on-box collection state means for the evidence and the operator.

    The mechanism itself is explained once, beside `INCIDENT_START_COMMANDS`
    in the orchestrator.
    """
    log = f"<code>{_escape(INGRESS_BACKLOG_LOG_PATH)}</code>"
    if state["enabled"] is True:
        return (
            " <strong>The on-box auto-collection was enabled.</strong> Each time "
            f"the in-flight usage stayed above {_escape(inflight_monitoring_settings_text(state))}, "
            "the firewall ran <code>show running resource-monitor "
            "ingress-backlogs</code> itself and appended it to "
            f"{log} on the management plane, which the tech support file "
            "carries. That sampling is taken every 100 ms, finer than any poll "
            "this collector can run, so ask TAC to read that file for the "
            "sub-second bursts."
        )
    if state["enabled"] is False:
        return (
            " <strong>The on-box auto-collection was disabled</strong>, so "
            f"{log} in the tech support file holds nothing for this incident "
            "and the sub-second bursts between two polls were never recorded. "
            "Enabling it on the firewall, with "
            f"<code>{_escape(INGRESS_BACKLOG_ENABLE_COMMAND)}</code>, makes the "
            "next incident carry that evidence; it survives a reboot. That is a "
            "configuration change on the firewall and the operator's decision: "
            "this collector is observational and never makes it."
        )
    if state["status"] == INFLIGHT_MONITORING_ABSENT:
        return (
            " <strong>The on-box auto-collection is not available on this "
            "PAN-OS release</strong>, which returned none of its settings, so "
            f"{log} is not in the tech support file and there is nothing to "
            "enable on this firewall."
        )
    return (
        " <strong>The on-box auto-collection state was not read</strong> in "
        f"this capture, so whether {log} holds anything is unknown."
    )


def _step_ingress_backlogs(
    cycles: Sequence[dict[str, Any]],
    attribution: Sequence[dict[str, Any]],
    context: dict[str, Any],
) -> dict[str, Any]:
    collected = [
        backlog
        for record in cycles
        if (backlog := collected_field(record, "ingress_backlogs")) is not None
    ]
    atomic_peak: float | None = None
    total_peak: float | None = None
    for backlog in collected:
        for dataplane in backlog.get("dataplanes") or []:
            if not isinstance(dataplane, dict):
                continue
            atomic = _first_number(dataplane.get("atomic_percentage"))
            total = _first_number(dataplane.get("total_percentage"))
            if atomic is not None:
                atomic_peak = atomic if atomic_peak is None else max(atomic_peak, atomic)
            if total is not None:
                total_peak = total if total_peak is None else max(total_peak, total)
    candidates = _ingress_candidate_entities(attribution)
    # An entry PAN-OS named an internal tag in its own "Special Notes" column
    # is the firewall's own traffic. It is listed, but it is not a session and
    # answers none of this step's questions, so it is partitioned off once here
    # rather than guarded against in every rule below.
    tags = [
        item
        for item in candidates
        if _no_session_behind(item) == SPECIAL_TAG_NOTED
    ]
    sessions = [item for item in candidates if item not in tags]
    inflight = inflight_monitoring_state(context.get("inflight_monitoring"))
    collection = ingress_backlog_collection(cycles)
    succeeded = collection["succeeded"]
    unsupported = collection["unsupported"]
    failed = collection["failed"]
    facts: list[tuple[str, str, str]] = [
        ("Batches with the command", _fmt(succeeded), "none"),
    ]
    if unsupported:
        # A node the platform does not have is a fact about the firewall, not
        # something an operator can repair, so it is stated and not flagged.
        facts.append(("Batches without the node", _fmt(unsupported), "none"))
    if failed:
        facts.append(("Batches with a failed read", _fmt(failed), "warn"))
    if tags:
        facts.append(("Internal tags listed", _fmt(len(tags)), "none"))
    facts.extend(
        [
            ("Queue peak (ATOMIC / TOTAL)", f"{_pct(atomic_peak)} / {_pct(total_peak)}", "none"),
            ("Sessions listed", _fmt(len(sessions)), "none"),
            # Informational, never amber: disabled is the PAN-OS default, so
            # colouring it would put a warning on nearly every capture and
            # dilute what amber means on the rows that carry the step's own
            # verdict.
            ("On-box auto-collection", inflight_monitoring_fact(inflight), "none"),
        ]
    )
    named: list[str] = []
    node_unsupported = False
    generation = context["generation"]
    # What the firewall answered decides the state, never the model. A batch
    # that returned data is evidence whatever the platform is said to support,
    # and a platform said to support the command still has none when every
    # batch came back rejected. The generation only chooses the wording.
    node_absent = succeeded == 0 and unsupported > 0
    read_failed = succeeded == 0 and unsupported == 0 and failed > 0
    def _missing_note(include_rejected: bool) -> str:
        """Name every batch that answered nothing, so the counts add up.

        `include_rejected` is False on the verdict that has already stated its
        own rejection count, so no batch is counted to the reader twice.
        """
        parts: list[str] = []
        if include_rejected and unsupported:
            parts.append(f"the firewall rejected it as an absent node in {unsupported}")
        if failed:
            parts.append(f"the read failed for another reason in {failed}")
        if not parts:
            return ""
        return (
            " Not every batch answered: "
            + " and ".join(parts)
            + f" of the {collection['batches']} batches, which therefore carry "
            "no backlog evidence."
        )
    # Sessions extracted from the backlog output are evidence the command
    # returned, so they answer the step before any failure count is read.
    unavailable_reason = ""
    if not sessions and node_absent:
        state, level = "unavailable", "none"
        node_unsupported = True
        unavailable_reason = "not available on this platform"
        verdict = (
            "<strong>The ingress backlog is not available on this "
            "platform.</strong> "
            + generation["ingress_backlog_absent_reason"]
            + f" It was rejected in {unsupported} of the "
            f"{collection['batches']} batches. That is a note about the "
            "platform, not a collection fault, an error or a negative result: "
            "it says nothing about whether a session dominated the work queue. "
            "Here the global counter delta of step 4 (<code>show counter "
            "global filter delta yes</code>) carries the weight of this "
            "question."
        )
    elif not sessions and read_failed:
        state, level = "failed", "warn"
        unavailable_reason = (
            f"read failed in {failed} of {collection['batches']} batches"
        )
        verdict = (
            f"<strong>The ingress backlog read failed in all {failed} of the "
            f"{collection['batches']} batches.</strong> The firewall did not "
            "reject the node, so the command exists here; the reads did not "
            "complete - a timeout or a permission the API role does not have. "
            "This step holds no evidence either way, and the failure is worth "
            "repairing before the next incident."
        )
    elif not sessions and not succeeded:
        state, level = "unavailable", "none"
        unavailable_reason = "not collected"
        verdict = (
            "<strong>The ingress backlogs were not collected</strong> in this "
            "capture, so this step cannot be answered."
        )
    elif sessions or tags:
        state, level = ("positive", "bad") if sessions else ("negative", "ok")
        unidentified = []
        slowpath_denied = []
        for item in sessions[:_MAX_NAMED]:
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
            if _is_policy_deny_shape(item, groups):
                slowpath_denied.append(str(item.get("identifier")))
                text += (
                    " — queued in <code>flow_slowpath</code> and unknown to "
                    "<code>show session id</code> (Bad Key)"
                )
            named.append(text)
        for item in tags[:_MAX_NAMED]:
            text = (
                f"internal tag <code>{_escape(item.get('identifier'))}</code> "
                f"({INTERNAL_TAG_DESCRIPTION}), {special_tag_label(item)}"
            )
            share = item.get("ingress_percentage")
            if share is not None:
                text += f" holding {_fmt(share)}% of the queue"
            note = _special_tag_field(item, "special_note")
            if note:
                text += f" — PAN-OS notes: {_escape(note)}"
            named.append(text)
        if sessions:
            verdict = (
                f"<strong>{_count(len(sessions), 'session')} "
                f"held at least {_fmt(INGRESS_BACKLOG_PERCENT)}% of the work queue.</strong> "
                "This view is independent of the PBP learning: it is the queue of "
                "packets waiting for a dataplane core, and a session that dominates it "
                "is the one holding the descriptors."
            )
            if tags:
                verdict += (
                    f" A further {_count(len(tags), 'entry', 'entries')} in the "
                    "table PAN-OS flagged in its own <code>Special Notes</code> "
                    f"column as an internal tag ({INTERNAL_TAG_DESCRIPTION}): "
                    "that is the firewall's own traffic, not a session, and no "
                    "<code>show session id</code> was spent on it."
                )
        else:
            verdict = (
                f"<strong>Only internal tags held the work queue.</strong> Every "
                f"one of the {_count(len(tags), 'entry', 'entries')} the backlog "
                f"listed is flagged by PAN-OS itself as an internal tag "
                f"({INTERNAL_TAG_DESCRIPTION}), so this step names no session and "
                "no offending flow."
            )
        if unidentified:
            verdict += (
                f" {_count(len(unidentified), 'Session')} "
                f"{_escape(', '.join(unidentified))} carr{'y' if len(unidentified) != 1 else 'ies'} "
                "an undecided or unknown application at that share, which is the "
                "signature of attack traffic rather than a legitimate transfer."
            )
        if slowpath_denied:
            verdict += (
                f" {_count(len(slowpath_denied), 'Session')} "
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
            f"queue</strong> in any of the {succeeded} batches that ran the command "
            f"(queue peak ATOMIC {_pct(atomic_peak)}, TOTAL {_pct(total_peak)}). "
        )
        if generation["ingress_backlog_in_flight"]:
            verdict += (
                f"On this {generation['label']} these percentages are "
                f"{generation['ingress_backlog_metric']}, the software equivalent "
                "of the on-chip descriptor queue, so an empty result means no "
                "session dominated the in-flight work at the sampled instants."
            )
        else:
            verdict += "Whatever filled the buffers was not one session waiting in the queue."
    # A batch that answered nothing is worth naming wherever the step landed.
    # The "read failed" verdict already speaks of nothing else, and the "not
    # available" verdict has already stated its own rejection count.
    if state != "failed":
        verdict += _missing_note(include_rejected=not node_unsupported)
    verdict += inflight_monitoring_note(inflight)
    return {
        "number": 3,
        "key": "backlogs",
        "title": "Does the ingress backlog hold a session?",
        "finding_title": "Session holding the ingress backlog",
        "state": state,
        "level": level,
        "verdict": verdict,
        "facts": facts,
        "named": named,
        "anchor": "ingress-title",
        # The work queue is read independently of the PBP learning, so this
        # step never reports what PBP ranked.
        "ranking_derived": False,
        # Whether the absence of an answer is the platform lacking the node,
        # so the conclusion never calls a capability gap a lost collection.
        "node_unsupported": node_unsupported,
        # One line saying why this step has no answer, for a report that folds
        # it away beside other unanswered questions and must not blur them
        # into "not collected".
        "unavailable_reason": unavailable_reason,
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


# Root-cause counter families, surfaced regardless of severity. The decisive
# counters of most real packet-buffer cases are info or warn, so a
# drop-severity table never shows them. Names verified on anonymized captures
# of closed TAC cases across PAN-OS 10.2.9 - 11.2.10.
#
# This is the one registry of counter names in the collector: the report's
# family table renders it, and the signatures below read their thresholds from
# the same names, so a counter renamed here can never leave a threshold
# silently summing nothing. The field is called ``family`` because the
# aggregated summary a report hands back keys each family under ``key``.
SIGNAL_COUNTER_FAMILIES: tuple[dict[str, Any], ...] = (
    {
        "family": "pbp",
        "label": "Packet buffer protection",
        "names": (
            "flow_dos_pbp_drop",
            "flow_dos_pbp_cnt_drop",
            "flow_dos_pbp_ifp_zone",
            "flow_dos_pbp_block_host",
            "pkt_buf_protect_red",
            "pkt_buf_protect_discard",
            "pkt_buf_protect_block_ip",
        ),
        "prefixes": (),
        "note": (
            "PBP's own mitigation, under both naming families: PAN-OS 10.2/11.x "
            "counts it as flow_dos_pbp_*, other releases as pkt_buf_protect_*."
        ),
    },
    {
        "family": "block_collateral",
        "label": "Blocked-source collateral",
        "names": ("flow_dos_drop_ip_blocked",),
        "prefixes": (),
        "note": (
            "Packets dropped because their source sits in the block table. When "
            "a block-ip hits a NAT device, a proxy or a backup server, this "
            "counter is the size of the silent outage it causes."
        ),
    },
    {
        "family": "arp_storm",
        "label": "ARP / L2 storm",
        "names": ("flow_arp_pkt_rcv", "flow_arp_rcv_gratuitous"),
        "prefixes": (),
        "note": (
            "An ARP flood creates no session, so PBP can neither name nor block "
            "it and the offender ranking stays empty while the buffer fills. A "
            "gratuitous share near 100% is a gratuitous-ARP storm; the fix is "
            "at layer 2, and a firewall reboot changes nothing."
        ),
    },
    {
        "family": "fragmentation",
        "label": "IP fragmentation",
        "names": (
            "flow_ipfrag_recv",
            "flow_ipfrag_merge",
            "flow_ipfrag_fwd",
            "flow_ipfrag_pkt_alloc_err",
        ),
        "prefixes": (),
        "note": (
            "Reassembly holds buffers until every fragment arrives. A received/"
            "completed ratio well above the packets' natural fragment count, or "
            "any flow_ipfrag_pkt_alloc_err, ties fragmentation directly to "
            "buffer exhaustion."
        ),
    },
    {
        "family": "allocation_failure",
        "label": "Buffer allocation failures",
        "names": ("pkt_alloc_failure", "buf_alloc_fail", "hw_buf_alloc_fail"),
        "prefixes": (),
        "note": (
            "The dataplane asked for a buffer and got none - exhaustion is no "
            "longer a percentage but a fact, whatever PBP did about it."
        ),
    },
    {
        "family": "proxy_retransmit",
        "label": "Decryption proxy retransmit",
        "names": (
            "tcp_fptcp_rxmt",
            "tcp_fptcp_fast_retransmit",
            "tcp_fptcp_max_rxmt",
        ),
        "prefixes": (),
        "note": (
            "The SSL forward proxy's own TCP stack retransmitting: each unacked "
            "segment holds a buffer, and on ASIC platforms an on-chip "
            "descriptor. A sustained rate under decryption is the distributed "
            "descriptor-exhaustion signature."
        ),
    },
    {
        "family": "out_of_order",
        "label": "Out-of-order / one-way TCP",
        "names": (
            "tcp_exceed_flow_seg_limit",
            "tcp_drop_packet",
            "tcp_out_of_sync",
            "flow_tcp_non_syn",
        ),
        "prefixes": (),
        "note": (
            "Out-of-order queues hold buffers while reassembly waits. Sustained "
            "rates point at an asymmetric or one-way feed - a TAP or mirror "
            "port is the classic source, and long application timeouts keep "
            "those queues alive."
        ),
    },
    {
        "family": "zone_flood",
        "label": "Zone-protection flood counters",
        "names": (),
        "prefixes": ("flow_dos_red_", "flow_dos_syncookie_"),
        "note": (
            "Zone protection absorbing a flood where it is enabled. PBP RED "
            "climbing while these stay at zero means the flood reached the "
            "buffer through a zone whose flood protection is off."
        ),
    },
)


def _family_names(family: str) -> tuple[str, ...]:
    """Every counter name one root-cause family declares."""
    for definition in SIGNAL_COUNTER_FAMILIES:
        if definition["family"] == family:
            return tuple(definition["names"])
    return ()


#: The counters each signature reads, per family. Kept beside the registry so
#: a test can prove no signature reads a name the family table does not
#: collect: a threshold reading a counter nobody aggregates is a signature
#: that can never fire, and nothing in the output would say so.
HYPOTHESIS_COUNTERS: dict[str, dict[str, tuple[str, ...]]] = {
    "arp_storm": {
        "received": ("flow_arp_pkt_rcv",),
        "gratuitous": ("flow_arp_rcv_gratuitous",),
    },
    "fragmentation": {
        "received": ("flow_ipfrag_recv",),
        "merged": ("flow_ipfrag_merge",),
        "allocation_errors": ("flow_ipfrag_pkt_alloc_err",),
    },
    "allocation_failure": {"failures": _family_names("allocation_failure")},
    "proxy_retransmit": {
        "retransmits": ("tcp_fptcp_rxmt", "tcp_fptcp_fast_retransmit"),
    },
    "pbp": {
        "drops": ("flow_dos_pbp_drop", "pkt_buf_protect_red"),
        "blocked_hosts": ("flow_dos_pbp_block_host", "pkt_buf_protect_block_ip"),
    },
    "block_collateral": {"collateral": _family_names("block_collateral")},
}


def _signal_family_counters(
    signal_summary: dict[str, Any] | None, key: str
) -> dict[str, dict[str, Any]]:
    """Index one root-cause counter family by counter name."""
    for family in (signal_summary or {}).get("families") or []:
        if family.get("key") == key:
            return {
                str(counter.get("name")): counter
                for counter in family.get("counters") or []
                if isinstance(counter, dict)
            }
    return {}


def _signal_total(
    counters: dict[str, dict[str, Any]], name: str, *more: str
) -> float:
    """Sum the named counters of one family.

    The names are required. Summing whatever the family happened to carry
    would turn a renamed or uncollected counter into a zero reading instead of
    the collection gap it is.
    """
    return sum(
        value
        for candidate in (name, *more)
        if (counter := counters.get(candidate)) is not None
        and (value := _first_number(counter.get("total"))) is not None
    )


def _signal_peak_rate(
    counters: dict[str, dict[str, Any]], name: str, *more: str
) -> float:
    """The fastest per-second rate any of the named counters reached."""
    return max(
        (
            value
            for candidate in (name, *more)
            if (counter := counters.get(candidate)) is not None
            and (value := _first_number(counter.get("peak_rate"))) is not None
        ),
        default=0.0,
    )


def _step_elsewhere(
    drop_summary: dict[str, Any],
    session_series: Sequence[dict[str, Any]],
    large_sessions: dict[str, Any],
    cpu_verdicts: Sequence[dict[str, Any]],
    cycles: Sequence[dict[str, Any]],
    attribution: Sequence[dict[str, Any]],
    events: Sequence[dict[str, Any]] = (),
    low_significance: bool = False,
    context: dict[str, Any] | None = None,
    signal_summary: dict[str, Any] | None = None,
    diagnostic_pools: Sequence[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    hypotheses: list[dict[str, Any]] = []
    batch_count = len(cycles)
    context = context or {}
    # `show session info` is the only command that says how many sessions
    # exist while the buffers are full. When every batch failed to read it,
    # the session table is unknown - not flat - and the hypotheses that read
    # it say so instead of ruling a storm out.
    session_reads = session_info_collection(cycles)
    session_read_failed = (
        session_reads["succeeded"] == 0 and session_reads["failed"] > 0
    )
    session_read_note = (
        f" The session table read failed in all {session_reads['failed']} of the "
        f"{session_reads['batches']} batches, so the session count is unknown."
        if session_read_failed
        else ""
    )

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
            backup_applications = sorted(
                {
                    str(session.get("application")).lower()
                    for session, _, _ in elephant_sessions
                    if str(session.get("application") or "").lower()
                    in BACKUP_APPLICATIONS
                }
            )
            if backup_applications:
                text += (
                    " The application"
                    + ("s" if len(backup_applications) != 1 else "")
                    + " ("
                    + ", ".join(f"<code>{_escape(app)}</code>" for app in backup_applications)
                    + ") is backup or storage traffic: these flows are the "
                    "operator's own infrastructure. Align PBP thresholds, QoS "
                    "or the job schedule with the backup window rather than "
                    "blocking the source - a blocked media server silently "
                    "interrupts every client that converges on it."
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
                    + session_read_note
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
    elif session_read_failed and not session_series:
        # Every read of the session table failed, so the new-connection rate
        # is unknown. Ranked sessions alone cannot rule a storm out.
        hypotheses.append(
            {
                "key": "storm",
                "title": "Storm of new sessions",
                "state": "unavailable",
                "text": (
                    f"The session table read failed in all {session_reads['failed']} "
                    f"of the {session_reads['batches']} batches, so the rate of new "
                    "connections could not be read and a storm can be neither "
                    "confirmed nor excluded."
                    + (
                        f" The busiest source owned {busiest[0][1]} ranked sessions."
                        if busiest
                        else ""
                    )
                ),
                "named": [],
                "unavailable_reason": (
                    f"session table read failed in {session_reads['failed']} of "
                    f"{session_reads['batches']} batches"
                ),
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
                "unavailable_reason": (
                    ""
                    if session_series or attribution
                    else "neither the session table nor the offender ranking was collected"
                ),
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

    # --- Corpus signatures. Each of the blocks below encodes one incident
    # class verified on the eight-case TAC corpus, and fires on positive
    # evidence only: the counter deltas sample fractions of a second, so a
    # signature that did not fire proves nothing and none of these ever
    # claims a negative.
    activate_percent = (
        _first_number(context.get("activate_percent")) or DEFAULT_ACTIVATE_PERCENT
    )
    buffer_series: list[float | None] = []
    for record in cycles:
        percentages = record.get("percentages")
        values = (
            list(_numbers(percentages.get("packet_buffer_congestion")))
            + list(_numbers(percentages.get("resource_monitor_packet_buffer")))
            if isinstance(percentages, dict)
            else []
        )
        buffer_series.append(max(values) if values else None)
    buffer_last = next(
        (value for value in reversed(buffer_series) if value is not None), None
    )
    buffer_peak = max(
        (value for value in buffer_series if value is not None), default=None
    )

    # ARP / L2 storm: a flood that never creates a session, so every
    # session-driven view above stays empty while the buffer fills.
    arp_counters = HYPOTHESIS_COUNTERS["arp_storm"]
    arp = _signal_family_counters(signal_summary, "arp_storm")
    arp_rate = _signal_peak_rate(arp, *arp_counters["received"])
    arp_total = _signal_total(arp, *arp_counters["received"])
    if arp_rate >= ARP_STORM_RATE_PER_SECOND:
        gratuitous_share = (
            _signal_total(arp, *arp_counters["gratuitous"]) / arp_total
            if arp_total > 0
            else None
        )
        hypotheses.append(
            {
                "key": "l2_storm",
                "title": "ARP / L2 storm",
                "state": "positive",
                "text": (
                    f"<strong>The dataplane received ARP at up to {_fmt(arp_rate)}/s</strong>"
                    + (
                        f", {_fmt(round(gratuitous_share * 100.0, 1))}% of it gratuitous"
                        if gratuitous_share is not None
                        and gratuitous_share >= ARP_GRATUITOUS_SHARE
                        else ""
                    )
                    + ". An ARP flood creates no session: PBP can neither name nor "
                    "block it, the offender ranking stays empty, and a firewall "
                    "reboot changes nothing. Locate the ingress port with "
                    "<code>show counter interface all</code> - one interface or "
                    "aggregate group whose rx-broadcast and rx-multicast dwarf its "
                    "rx-unicast names the entry point - and remediate at layer 2 "
                    "(storm control, or disconnecting the offending device)."
                ),
                "named": [],
            }
        )

    # Fragmentation pressure: reassembly holds buffers until the last
    # fragment arrives, and allocation errors inside the defrag path tie the
    # fragments directly to the exhaustion.
    frag_counters = HYPOTHESIS_COUNTERS["fragmentation"]
    frag = _signal_family_counters(signal_summary, "fragmentation")
    frag_rate = _signal_peak_rate(frag, *frag_counters["received"])
    frag_received = _signal_total(frag, *frag_counters["received"])
    frag_completed = _signal_total(frag, *frag_counters["merged"])
    frag_alloc_errors = _signal_total(frag, *frag_counters["allocation_errors"])
    allocation_failures = _signal_total(
        _signal_family_counters(signal_summary, "allocation_failure"),
        *HYPOTHESIS_COUNTERS["allocation_failure"]["failures"],
    )
    frag_ratio = frag_received / frag_completed if frag_completed > 0 else None
    if frag_rate >= FRAGMENTATION_RATE_PER_SECOND or (
        frag_ratio is not None
        and frag_ratio > FRAGMENTATION_REASSEMBLY_RATIO
        and frag_received >= DENIED_BURST_TOTAL_PACKETS
    ):
        text = (
            f"<strong>IP fragments arrived at up to {_fmt(frag_rate)}/s</strong>"
            + (
                f" at {_fmt(round(frag_ratio, 1))} fragments per reassembled packet"
                if frag_ratio is not None
                else ""
            )
            + ". Reassembly holds a buffer for every fragment until the last one "
            "arrives, so heavy fragmentation occupies the pool out of proportion "
            "to its bandwidth."
        )
        if frag_alloc_errors > 0 or allocation_failures > 0:
            text += (
                f" Allocation failed {_fmt(frag_alloc_errors)} time(s) inside the "
                f"defragmentation path and {_fmt(allocation_failures)} time(s) "
                "overall: fragmentation was exhausting the pool, not merely using "
                "it."
            )
        text += (
            " Fragmented UDP tunnels (VPN or WireGuard-style traffic) are the "
            "classic source; identify the flows before considering "
            "<code>discard-ip-frag</code> zone protection on the ingress zone."
        )
        hypotheses.append(
            {
                "key": "fragmentation",
                "title": "Fragmentation pressure",
                "state": "positive",
                "text": text,
                "named": [],
            }
        )

    # Distributed proxy/retransmit exhaustion: aggregate SSL-proxy packet
    # rate with no single offender - blocking what PBP names punishes
    # victims.
    fptcp = _signal_family_counters(signal_summary, "proxy_retransmit")
    fptcp_rate = _signal_peak_rate(
        fptcp, *HYPOTHESIS_COUNTERS["proxy_retransmit"]["retransmits"]
    )
    on_chip_peak = _metric_peak(
        cycles,
        "resource_monitor_packet_descriptor_on_chip",
        "descriptor_atomic",
        "descriptor_total",
    )
    if fptcp_rate >= PROXY_RETRANSMIT_RATE_PER_SECOND:
        hypotheses.append(
            {
                "key": "proxy_retransmit",
                "title": "Decryption proxy pressure",
                "state": "positive",
                "text": (
                    f"<strong>The decryption proxy's own TCP stack retransmitted at "
                    f"up to {_fmt(fptcp_rate)}/s</strong>. Each unacknowledged "
                    "segment holds a buffer - and on ASIC platforms an on-chip "
                    "packet descriptor"
                    + (
                        f" - and the descriptors did reach {_fmt(on_chip_peak)}%"
                        if on_chip_peak is not None
                        and on_chip_peak >= DESCRIPTOR_EXHAUSTION_PERCENT
                        else ""
                    )
                    + ". This pressure is the sum of many proxied sessions, not one "
                    "offender: blocking the sources PBP names punishes victims. "
                    "Reduce or reshape the decryption load, and on Octeon "
                    "platforms ask TAC about the legacy-retransmit knob for this "
                    "pattern."
                ),
                "named": [],
            }
        )

    # Held resources: buffer occupancy decoupled from session load, pools
    # pinned near full, or a latency long tail - the leak class. Positive
    # evidence that buffers are being kept, not processed.
    # A pool backed by the packet buffer or by the packet descriptors is full
    # *because* the buffers are full: during a flood its occupancy is the
    # incident itself, not memory nobody frees. It is leak evidence only when
    # the buffers were not under pressure at the same time.
    buffers_under_pressure = (
        buffer_peak is not None and buffer_peak >= DEFAULT_ALERT_PERCENT
    )
    held_pools = [
        pool
        for pool in diagnostic_pools or []
        if (_first_number(pool.get("used_percentage")) or 0.0)
        >= POOL_HELD_PERCENT
        and not (buffers_under_pressure and _is_buffer_backed_pool(pool))
    ]
    # Decoupling is judged against the PAN-OS default alert level, never a
    # lowered configured threshold: a lab firewall alerting at 1% with 4%
    # buffers is a threshold artifact, not held memory.
    decoupled = (
        buffer_peak is not None
        and buffer_peak >= DEFAULT_ALERT_PERCENT
        and table_peak is not None
        and table_peak <= LEAK_SESSION_TABLE_PERCENT
        and buffer_last is not None
        and buffer_last >= DEFAULT_ALERT_PERCENT
    )
    latency_peaks: list[float] = []
    latency_averages: list[float] = []
    for record in cycles:
        latency = record.get("buffer_latency")
        if not isinstance(latency, dict):
            continue
        for dataplane in latency.get("dataplanes") or []:
            if not isinstance(dataplane, dict):
                continue
            latency_peaks.extend(_numbers(dataplane.get("last_max_ms")))
            latency_averages.extend(
                value
                for value in _numbers(dataplane.get("last_avg_ms"))
                if value > 0
            )
    latency_ratio = (
        max(latency_peaks) / statistics.median(latency_averages)
        if latency_peaks and latency_averages
        else None
    )
    long_tail = (
        latency_ratio is not None and latency_ratio >= LATENCY_LONG_TAIL_RATIO
    )
    if held_pools or decoupled or long_tail:
        parts = []
        if decoupled:
            parts.append(
                f"packet buffers held {_fmt(buffer_last)}% at the end of the "
                f"capture while the session table never exceeded {_fmt(table_peak)}% "
                "- occupancy decoupled from session load"
            )
        if held_pools:
            parts.append(
                "dataplane pools stayed near full (see the diagnostic pools table)"
            )
        if long_tail:
            parts.append(
                f"a few packets waited {_fmt(round(latency_ratio, 0))}x longer than "
                "the median buffer latency - a long tail, not uniform congestion"
            )
        quiet_cores = bool(cpu_verdicts) and not collective
        text = (
            "<strong>Resources were held, not processed</strong>: "
            + "; ".join(parts)
            + (
                ", while the dataplane cores stayed quiet"
                if quiet_cores
                else ""
            )
            + ". That is the leak signature: occupancy that survives an idle "
            "period and clears only at a dataplane restart is a software leak, "
            "not traffic. If it recurs, capture the dataplane "
            "<code>pan_task</code> logs within minutes of an episode (at debug "
            "level they rotate in about a minute) and review later maintenance "
            "releases of PAN-OS "
            + _escape(str(context.get("software_version") or "this release"))
            + " for buffer-leak fixes before treating the traffic as the cause"
            + (
                " - the held proxy pools point at the SSL-proxy leak class"
                if any(
                    str(pool.get("name") or "").strip().lower()
                    in {"timer pool", "proxy_flow", "ssl_st", "fptcp_seg"}
                    for pool in held_pools
                )
                else ""
            )
            + "."
        )
        hypotheses.append(
            {
                "key": "held_resources",
                "title": "Held resources (leak signature)",
                "state": "positive",
                "text": text,
                "named": [
                    f"<code>{_escape(pool.get('name'))}</code>"
                    + (
                        f" on {_escape(pool.get('dataplane'))}"
                        if pool.get("dataplane")
                        else ""
                    )
                    + f" at {_fmt(_first_number(pool.get('used_percentage')))}% used"
                    for pool in held_pools[:_MAX_NAMED]
                ],
            }
        )

    # Flood through an unprotected zone: PBP dropping hard while the
    # zone-protection flood counters never moved - PBP doing zone
    # protection's job. Worded as a suspicion to verify, not a verdict:
    # the capture does not read `show zone-protection`.
    pbp_counters = _signal_family_counters(signal_summary, "pbp")
    pbp_drop_names = HYPOTHESIS_COUNTERS["pbp"]["drops"]
    pbp_drop_total = _signal_total(pbp_counters, *pbp_drop_names)
    pbp_drop_rate = _signal_peak_rate(pbp_counters, *pbp_drop_names)
    zone_flood_counters = _signal_family_counters(signal_summary, "zone_flood")
    if (
        pbp_drop_total >= DENIED_BURST_TOTAL_PACKETS
        and not zone_flood_counters
        and (
            packets_without_sessions
            or (cps_peak is not None and cps_peak >= NEW_SESSION_STORM_CPS)
        )
    ):
        hypotheses.append(
            {
                "key": "unprotected_flood",
                "title": "Flood through an unprotected zone",
                "state": "positive",
                "text": (
                    f"<strong>PBP dropped {_fmt(pbp_drop_total)} packets (up to "
                    f"{_fmt(pbp_drop_rate)}/s) while no zone-protection flood "
                    "counter moved</strong> in the counted deltas. When a flood "
                    "reaches the packet buffer with the zone flood counters "
                    "silent, the classic cause is flood protection disabled on "
                    "the ingress zone - PBP is then the last line, doing zone "
                    "protection's job one buffer at a time. Verify on the "
                    "firewall with <code>show zone-protection</code>: a zone "
                    "whose profile has a flood mechanism disabled prints no "
                    "line at all for it."
                ),
                "named": [],
            }
        )

    # Single-dataplane saturation on a chassis: one DP pinned while the
    # median idles - a flow group hashed onto one dataplane, not capacity.
    imbalance: tuple[str, float, float, int] | None = None
    for record in cycles:
        percentages = record.get("percentages")
        dataplanes = (
            percentages.get("resource_monitor_dataplanes")
            if isinstance(percentages, dict)
            else None
        )
        if not isinstance(dataplanes, list) or len(dataplanes) < 2:
            continue
        readings = [
            (str(entry.get("dataplane") or "?"), value)
            for entry in dataplanes
            if isinstance(entry, dict)
            and (value := _first_number(entry.get("packet_buffer"))) is not None
        ]
        if len(readings) < 2:
            continue
        # The median must describe the OTHER dataplanes, not the saturated
        # one: folding the worst reading into its own baseline drags the
        # median up (on a 2-DP chassis it could never fall at or below the
        # threshold at all, so the signature could never fire) and a middle
        # value on 3+ DPs can mask a real imbalance. Exclude the worst
        # reading by position, not by value, so a tie at the worst value does
        # not remove more than the one saturated dataplane.
        ordered = sorted(readings, key=lambda item: item[1], reverse=True)
        worst_name, worst_value = ordered[0]
        peer_values = [value for _, value in ordered[1:]]
        if not peer_values:
            # No peers to compare against (a single dataplane slipped past
            # the len(readings) < 2 guard above cannot happen, but stay
            # defensive): there is no imbalance to name.
            continue
        median_value = statistics.median(peer_values)
        if (
            worst_value >= activate_percent
            and median_value <= CHASSIS_IMBALANCE_MEDIAN_PERCENT
            and (imbalance is None or worst_value > imbalance[1])
        ):
            imbalance = (worst_name, worst_value, median_value, len(peer_values))
    if imbalance is not None:
        worst_name, worst_value, median_value, peer_count = imbalance
        hypotheses.append(
            {
                "key": "chassis_imbalance",
                "title": "Single-dataplane saturation",
                "state": "positive",
                "text": (
                    f"<strong>Dataplane {_escape(worst_name)} reached "
                    f"{_fmt(worst_value)}% packet buffer while the median of "
                    f"the other {peer_count} dataplane"
                    f"{'s' if peer_count != 1 else ''} stayed at "
                    f"{_fmt(median_value)}%"
                    "</strong>. Sessions are pinned to a dataplane by their flow "
                    "hash, so one heavy flow group saturates its dataplane while "
                    "the chassis as a whole has headroom. The remedy is per-flow "
                    "- the offenders and backlog sessions on that dataplane - "
                    "not capacity."
                ),
                "named": [],
            }
        )

    # Session-table collapse: the firewall stopped admitting sessions while
    # the buffer stayed high - the terminal stage, where tunnels and routing
    # adjacencies start failing.
    if allocated:
        peak_allocated = max(allocated)
        last_allocated = allocated[-1]
        if (
            peak_allocated >= SESSION_COLLAPSE_FLOOR
            and last_allocated <= SESSION_COLLAPSE_RATIO * peak_allocated
            and buffer_last is not None
            and buffer_last >= DEFAULT_ALERT_PERCENT
        ):
            hypotheses.append(
                {
                    "key": "session_collapse",
                    "title": "Session-table collapse",
                    "state": "positive",
                    "text": (
                        f"<strong>Allocated sessions fell from "
                        f"{_fmt(peak_allocated)} to {_fmt(last_allocated)} while "
                        f"the packet buffer still read {_fmt(buffer_last)}%"
                        "</strong>. Buffers pinned while the session table drains "
                        "means the firewall was no longer admitting sessions - "
                        "the late stage of exhaustion, where VPN tunnels and "
                        "routing adjacencies through the firewall start failing. "
                        "Treat the incident as severe even where the traffic "
                        "rates look modest."
                    ),
                    "named": [],
                }
            )

    # Block-ip collateral: PBP escalated to blocking sources. The block
    # itself is silent for its whole duration, so the report must say who
    # was blocked and what that costs when the source is shared
    # infrastructure.
    threat_summary = context.get("threat_logs") or {}
    threat_bounded = bool(
        threat_summary.get("bounded") if isinstance(threat_summary, dict) else False
    )
    # Threat logs the firewall clock could not bound may predate this
    # incident, so they never establish that PBP blocked during it.
    threat_counts = (
        (threat_summary.get("counts") if isinstance(threat_summary, dict) else {})
        if threat_bounded
        else {}
    ) or {}
    blocked_hosts = _signal_total(
        pbp_counters, *HYPOTHESIS_COUNTERS["pbp"]["blocked_hosts"]
    )
    block_events = _first_number(threat_counts.get(8509)) or 0.0
    block_collateral = _signal_total(
        _signal_family_counters(signal_summary, "block_collateral"),
        *HYPOTHESIS_COUNTERS["block_collateral"]["collateral"],
    )
    if blocked_hosts > 0 or block_events > 0:
        blocked_sources = [
            f"<code>{_escape(source)}</code>"
            for source, item in (
                (threat_summary.get("sources") or {}) if threat_bounded else {}
            ).items()
            if isinstance(item, dict) and 8509 in (item.get("ids") or set())
        ]
        hypotheses.append(
            {
                "key": "block_collateral",
                "title": "Source blocking and its collateral",
                "state": "positive",
                "text": (
                    "<strong>PBP escalated to blocking source addresses</strong> ("
                    + ", ".join(
                        part
                        for part in (
                            f"{_fmt(block_events)} PBP IP Blocked threat log(s)"
                            if block_events > 0
                            else "",
                            f"{_fmt(blocked_hosts)} block-host counter event(s)"
                            if blocked_hosts > 0
                            else "",
                        )
                        if part
                    )
                    + ")."
                    + (
                        f" {_fmt(block_collateral)} packets were then dropped "
                        "from blocked sources - the size of the outage the "
                        "blocks caused."
                        if block_collateral > 0
                        else ""
                    )
                    + " A blocked source stays silently blocked for the whole "
                    "block duration. If it is a NAT gateway, a proxy or a "
                    "backup media server, every host behind or converging on it "
                    "loses traffic with no log of its own: check what the named "
                    "sources are before treating them as attackers."
                ),
                "named": blocked_sources[:_MAX_NAMED],
            }
        )

    # 4h - a level that only climbed. The per-second view a monitor collects
    # cannot tell a leak from a flood: both end high. The hour, day and week
    # blocks read once at monitor start can, and that read is the only reason
    # this hypothesis exists at all.
    history = context.get("buffer_history") or {}
    if history.get("shape") == "climbing":
        climbing = [
            window
            for window in history.get("windows") or []
            if window.get("shape") == "climbing"
        ]
        named_windows = [
            f"the {_escape(window.get('window'))} history of "
            f"{_escape(window.get('dataplane'))} rose from "
            f"{_fmt(window.get('oldest'))}% to {_fmt(window.get('latest'))}%"
            + (
                f", starting about {_fmt((window.get('onset') or {}).get('samples_ago'))} "
                f"{_escape((window.get('onset') or {}).get('unit'))}(s) ago"
                if window.get("onset")
                else ""
            )
            for window in climbing[:_MAX_NAMED]
        ]
        sessions_flat = any(
            (readings := (window.get("metrics") or {}).get("session"))
            and isinstance(readings, dict)
            and (summary := readings.get("maximum") or readings.get("average"))
            and isinstance(summary, dict)
            and (peak := _first_number(summary.get("peak"))) is not None
            and peak <= LEAK_SESSION_TABLE_PERCENT
            for window in history_windows(events)
        )
        hypotheses.append(
            {
                "key": "buffer_leak_history",
                "title": "Buffer level that only climbed",
                "state": "positive",
                "text": (
                    "<strong>The buffer utilization this firewall recorded "
                    "before the incident only ever rose</strong>: "
                    + "; ".join(
                        f"over the {_escape(window.get('window'))} window it went "
                        f"from {_fmt(window.get('oldest'))}% to "
                        f"{_fmt(window.get('latest'))}%"
                        for window in climbing[:_MAX_NAMED]
                    )
                    + ". A flood fills the buffers and lets them drain again; a "
                    "level that climbs and never returns is buffers that are "
                    "allocated and not released."
                    + (
                        " The session table stayed near empty over the same "
                        "windows, which rules out the load itself as the "
                        "explanation and points at a leak rather than traffic."
                        if sessions_flat
                        else ""
                    )
                    + " Date the start of the climb against the last change on "
                    "this firewall - a PAN-OS upgrade, a new feature, a new "
                    "peer - before looking at the traffic of the last hour."
                ),
                "named": named_windows,
            }
        )

    # 4i - PBP doing zone protection's job. The zone-protection table is the
    # only read that says whether the zone the drops came from had any flood
    # protection configured at all.
    zone_protection = context.get("zone_protection") or {}
    unprotected = zone_protection.get("unprotected") or []
    if unprotected:
        hypotheses.append(
            {
                "key": "unprotected_zone",
                "title": "PBP covering an unprotected zone",
                "state": "positive",
                "text": (
                    "<strong>PBP dropped packets in "
                    + ("a zone" if len(unprotected) == 1 else "zones")
                    + " whose zone-protection profile has every flood type "
                    "disabled.</strong> PBP is a last resort that acts on the "
                    "whole buffer: it cannot tell a flood from legitimate "
                    "traffic and it drops both. Zone protection is the tool "
                    "that was meant to absorb this, and on "
                    + ("this zone" if len(unprotected) == 1 else "these zones")
                    + " it is not enabled. Configuring SYN, UDP and ICMP flood "
                    "protection on the zone the traffic enters is the fix; "
                    "raising the PBP threshold is not."
                ),
                "named": [
                    f"zone <code>{_escape(zone.get('zone'))}</code>"
                    + (
                        f" (profile <code>{_escape(zone.get('profile'))}</code>)"
                        if zone.get("profile")
                        else ""
                    )
                    + f": {_fmt(zone.get('pbp_drop'))} packets dropped by PBP, "
                    "no flood protection enabled"
                    for zone in unprotected[:_MAX_NAMED]
                ],
            }
        )

    # 4j - the same three hours every night. Zero collection of its own: the
    # congestion query already run at stop carries weeks of timestamps.
    recurrence = context.get("recurrence") or {}
    peak_window = recurrence.get("peak_window") or {}
    if peak_window.get("scheduled"):
        hypotheses.append(
            {
                "key": "scheduled_recurrence",
                "title": "A recurring window, not an attack",
                "state": "positive",
                "text": (
                    "<strong>"
                    f"{_fmt(round(float(peak_window.get('share') or 0.0) * 100))}% of "
                    f"the {_fmt(recurrence.get('dated_entries'))} congestion events "
                    "this firewall logged fall inside the same three hours of the "
                    f"day ({int(peak_window.get('start_hour') or 0):02d}:00 - "
                    f"{int(peak_window.get('end_hour') or 0):02d}:00).</strong> "
                    "An attack does not keep office hours. A window that repeats "
                    "at the same time on different days is a scheduled job - a "
                    "backup, a replication, a database export - and the fix is "
                    "the schedule, the bandwidth it is given, or a QoS profile, "
                    "not a block. The history covers "
                    f"{_fmt(recurrence.get('span_days'))} day(s)"
                    + (
                        f", from {_escape(recurrence.get('first_seen'))} to "
                        f"{_escape(recurrence.get('last_seen'))}"
                        if recurrence.get("first_seen")
                        else ""
                    )
                    + "."
                ),
                "named": [],
            }
        )

    # 4k - a passive unit. Not a cause: the fact without which the rest of the
    # capture cannot be read at all.
    ha = context.get("ha") or {}
    if ha.get("enabled") and ha.get("passive"):
        hypotheses.append(
            {
                "key": "passive_ha_unit",
                "title": "Captured on the passive unit",
                "state": "positive",
                "text": (
                    "<strong>This firewall was the "
                    f"{_escape(ha.get('local_state'))} member of an HA pair while "
                    "the capture ran.</strong> A passive unit forwards no "
                    "production traffic, so buffers filling on it are not "
                    "explained by the sessions it holds and every offender "
                    "ranking here will be empty by construction. Read the "
                    "utilization as a leak until proven otherwise, and collect "
                    "the same evidence on the active unit before concluding."
                ),
                "named": [],
            }
        )

    # Recent boot or upgrade: not a cause, a context that raises the
    # known-issue hypothesis - one corpus case started 14 hours after an
    # upgrade and its nightly trigger had been self-recovering before it.
    days_up = _first_number(context.get("uptime_days"))
    if days_up is not None and days_up < RECENT_BOOT_DAYS:
        hypotheses.append(
            {
                "key": "recent_boot",
                "title": "Recent boot or upgrade",
                "state": "positive",
                "text": (
                    f"<strong>The firewall had been up only "
                    f"{_escape(str(context.get('uptime')))} </strong>when this "
                    "incident was captured. An incident starting within days of "
                    "a boot raises the known-issue hypothesis: check the release "
                    "notes and known issues of PAN-OS "
                    + _escape(str(context.get("software_version") or "-"))
                    + " before treating the environment as the cause, and note "
                    "whether buffer utilization clears at each reboot and climbs "
                    "back - that history is itself the leak fingerprint."
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
            + (
                "</strong> would be a supported finding"
                if len(positives) == 1
                else "</strong> would be supported findings"
            )
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
        f"the alert {_fmt(context['alert_percent'])}% / activate "
        f"{_fmt(context['activate_percent'])}% thresholds configured on the firewall"
        if context["alert_source"] == "configuration"
        else "thresholds the configuration read could not establish, PBP's own "
        "mitigation contradicting the values it returned"
        if context["alert_source"] == "inconsistent"
        else f"the {_fmt(context['alert_percent'])}% alert threshold configured on the firewall"
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
                else "The PBP read failed in every batch, so what it learned is "
                "unknown; nothing is designated."
                if named["state"] == "failed"
                else "No offender was learned and none is designated."
            )
        )
        return sentences
    if named["state"] == "positive":
        sentences.append(
            "PBP designated: " + "; ".join(named["named"]) + "."
        )
    elif named["state"] == "failed":
        sentences.append(
            "Whether PBP designated anyone is unknown: its read failed in every "
            "batch, so this capture holds no PBP evidence and the read is worth "
            "repairing before the next incident."
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
    elif backlogs.get("node_unsupported"):
        sentences.append(
            "The ingress backlog command is not available on this platform, so "
            "the global counter delta carries that question."
        )
    elif backlogs["state"] == "failed":
        sentences.append(
            "The ingress backlog read failed in every batch — the firewall has "
            "the command but did not answer it — so that question is open and "
            "the read is worth repairing before the next incident."
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


#: The evidence section that proves each hypothesis, so a finding in the
#: layered report always links to the table it was read from.
EVIDENCE_ANCHORS = {
    "elephant": "large-sessions-title",
    "denied": "drop-counters-title",
    "storm": "session-table-title",
    "interfaces": "drop-counters-title",
    "aggregate": "cpu-tracking-title",
    "l2_storm": "drop-counters-title",
    "fragmentation": "drop-counters-title",
    "proxy_retransmit": "drop-counters-title",
    "held_resources": "pressure-title",
    "unprotected_flood": "attribution-title",
    "chassis_imbalance": "pressure-title",
    "session_collapse": "session-table-title",
    "block_collateral": "attribution-title",
    "recent_boot": "summary-title",
    "buffer_leak_history": "history-title",
    "scheduled_recurrence": "history-title",
    "unprotected_zone": "zones-title",
    "passive_ha_unit": "zones-title",
}

_FINDING_STEPS = ("pbp", "backlogs")


def collect_findings(diagnosis: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Flatten the investigation into what it confirmed, ruled out, or could not judge.

    The four-step walk is how the collector reasons; it is not how an operator
    reads under pressure. This returns the same conclusions as one ranked list
    of findings, so a report can lead with the handful that are supported and
    fold the rest away without losing them.

    Every finding carries two facts about its weight, so no consumer has to
    re-derive them: ``low_significance`` says step 1 found no shortage of
    buffers or descriptors, and ``ranking_derived`` says the finding is PBP's
    own ranking rather than an observation made independently of it. Under low
    pressure only the ranking-derived findings are "what PBP ranked"; calling
    an independent observation - a recent boot, an interface counter - by that
    name would be plainly false.
    """
    findings: dict[str, list[dict[str, Any]]] = {
        "confirmed": [],
        "ruled_out": [],
        "unavailable": [],
    }
    buckets = {
        "positive": findings["confirmed"],
        "negative": findings["ruled_out"],
        "unavailable": findings["unavailable"],
        # A step the collector could not read is still a step that could not
        # be judged: it belongs with the unavailable findings rather than
        # disappearing from the layered report.
        "failed": findings["unavailable"],
    }
    low_significance = any(
        bool(step.get("low_significance")) for step in diagnosis["steps"]
    )
    for step in diagnosis["steps"]:
        if step["key"] in _FINDING_STEPS and step["state"] in buckets:
            buckets[step["state"]].append(
                {
                    "key": step["key"],
                    "title": step["finding_title"],
                    "text": step["verdict"],
                    "named": list(step.get("named") or []),
                    "anchor": step["anchor"],
                    "origin": "step",
                    "ranking_derived": bool(step.get("ranking_derived")),
                    "low_significance": low_significance,
                    "reason": str(step.get("unavailable_reason") or ""),
                }
            )
        for hypothesis in step.get("hypotheses") or []:
            if hypothesis["state"] not in buckets:
                continue
            buckets[hypothesis["state"]].append(
                {
                    "key": hypothesis["key"],
                    "title": hypothesis["title"],
                    "text": hypothesis["text"],
                    "named": list(hypothesis.get("named") or []),
                    "anchor": EVIDENCE_ANCHORS.get(hypothesis["key"], step["anchor"]),
                    "origin": "hypothesis",
                    # A signature reads the counters, the pools, the session
                    # table or the uptime. None of them is PBP's ranking.
                    "ranking_derived": bool(hypothesis.get("ranking_derived")),
                    "low_significance": low_significance,
                    "reason": str(hypothesis.get("unavailable_reason") or ""),
                }
            )
    return findings


def render_diagnosis_context(diagnosis: dict[str, Any]) -> str:
    """The case chips: model, generation, PAN-OS, PBP state and its thresholds."""
    context = diagnosis["context"]
    chips = [
        f"model {context['model']}",
        context["generation"]["label"],
        f"PAN-OS {context['software_version']}",
        "PBP " + context["pbp_enabled"]
        + (f" · {', '.join(context['pbp_modes'])}" if context["pbp_modes"] else "")
        + (" · monitor only" if context["monitor_only"] else ""),
    ]
    if context["alert_source"] == "configuration":
        chips.append(
            f"configured alert {_fmt(context['alert_percent'])}% · activate "
            f"{_fmt(context['activate_percent'])}%"
            + (" (changed during the run)" if context["settings_changed_during_run"] else "")
        )
    elif context["alert_source"] == "inconsistent":
        chips.append(
            "configured thresholds contradicted by PBP · not the ones in force"
        )
    elif context["alert_percent"] is not None:
        chips.append(f"alert threshold {_fmt(context['alert_percent'])}% (from the firewall)")
    if context["latency_peak_ms"] is not None:
        chips.append(f"buffer latency peak {_fmt(context['latency_peak_ms'])} ms")
    if context["mitigating_from_percent"] is not None:
        chips.append(f"PBP mitigating from {_fmt(context['mitigating_from_percent'])}%")
    return '<p class="chart-legend diagnosis-context">' + "".join(
        f'<span class="key">{_escape(chip)}</span>' for chip in chips
    ) + "</p>"


def render_diagnosis_steps(diagnosis: dict[str, Any]) -> str:
    """The four-step walk, each step with its verdict, names and facts."""
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
    return f'<ol class="steps">{"".join(steps_html)}</ol>'


def render_diagnosis_conclusion(diagnosis: dict[str, Any]) -> str:
    """The sentences an operator carries into the TAC case."""
    conclusion_html = "".join(f"<p>{sentence}</p>" for sentence in diagnosis["conclusion"])
    return (
        '<div class="probable-cause"><h3 id="conclusion-title">Conclusion for the case</h3>'
        f"{conclusion_html}</div>"
    )


def render_diagnosis(diagnosis: dict[str, Any]) -> str:
    """Render the investigation as the report's opening block."""
    headline = diagnosis["headline"]
    return (
        f'<p class="headline"><strong>{_escape(headline["label"])}.</strong> '
        f'{headline["text"]}</p>'
        f"{render_diagnosis_context(diagnosis)}"
        f"{render_diagnosis_steps(diagnosis)}"
        f"{render_diagnosis_conclusion(diagnosis)}"
    )
