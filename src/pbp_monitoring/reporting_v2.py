#!/usr/bin/env python3
"""Generate the layered incident report from a PBP JSONL capture.

The v1 report in `reporting.py` presents its diagnosis, its evidence and its
appendix at the same weight. That was readable while the collector knew three
things about an incident; it is no longer, now that the diagnosis weighs
fourteen hypothesis families and step 4 renders a wall of bullets that mostly
say "no".

This renderer carries exactly the same content, from exactly the same builder,
in three strict layers:

1. the verdict, with the numbers that prove it and the conclusion to carry
   into a TAC case;
2. what explains it — only the supported findings, with everything ruled out
   folded behind a single line;
3. the evidence, then the raw appendix, folded.

Nothing is dropped, so the file stays enough on its own to open a case. What
changes is the order in which an operator meets it.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from . import __version__
from .diagnosis import (
    DEFAULT_ALERT_PERCENT,
    collect_findings,
    render_diagnosis_conclusion,
    render_diagnosis_context,
    render_diagnosis_steps,
)
from .reporting import (
    REPORT_STYLE,
    _appendix_sections,
    _build_report_parts,
    _escape,
    _evidence_sections,
    _format_number,
    _human_duration,
    _human_timestamp,
    _level,
    _part_heading,
    _read_jsonl,
    _render_section,
    resolve_report_destination,
    write_report_atomically,
)

#: The file name the collector writes beside the capture, and the Web UI serves.
REPORT_V2_FILENAME = "report-v2.html"

#: The layered report folds inside its second layer, not only at section
#: level, so its own control reaches those blocks too. It deliberately stops
#: there: opening every raw command response would print hundreds of pages.
REPORT_V2_SCRIPT = """(function(){
var folds=document.querySelectorAll("section:not(.glance)>details.section-fold,details.dismissed");
var nav=document.querySelector("nav.toc");
if(!folds.length||!nav){return;}
var button=document.createElement("button");
button.type="button";
button.className="fold-all";
button.textContent="Collapse all";
button.addEventListener("click",function(){
var collapse=false,i;
for(i=0;i<folds.length;i++){if(folds[i].open){collapse=true;break;}}
for(i=0;i<folds.length;i++){folds[i].open=!collapse;}
button.textContent=collapse?"Expand all":"Collapse all";
});
nav.appendChild(button);
function reveal(){
var id=window.location.hash.replace("#","");
if(!id){return;}
var heading=document.getElementById(id);
var element=heading;
while(element){
if(element.tagName==="DETAILS"){element.open=true;}
element=element.parentElement;
}
if(heading){heading.scrollIntoView();}
}
window.addEventListener("hashchange",reveal);
reveal();
})();"""

#: The Content-Security-Policy source expression the Web UI must allow for a
#: layered report page, alongside the v1 one and nothing else.
REPORT_V2_SCRIPT_CSP_HASH = "sha256-" + base64.b64encode(
    hashlib.sha256(REPORT_V2_SCRIPT.encode("utf-8")).digest()
).decode("ascii")

#: Layer styling. Everything else — tables, cards, charts, disclosures — comes
#: from the shared stylesheet, so a section rendered here looks exactly like
#: the same section in the v1 report.
REPORT_V2_STYLE = """
    .layer-lead { margin:0 0 18px; color:var(--muted); max-width:70ch; }
    section.verdict .section-body { padding-top:4px; }
    .proof { display:grid; gap:12px; grid-template-columns:repeat(auto-fit,minmax(165px,1fr)); margin:18px 0 22px; }
    .proof-item { padding:14px 16px; border:1px solid var(--line); border-radius:12px; background:var(--surface); }
    .proof-item span { display:block; color:var(--muted); font-size:12px; font-weight:700; letter-spacing:.04em; text-transform:uppercase; }
    .proof-item strong { display:block; margin-top:6px; font-size:26px; letter-spacing:-.02em; }
    .proof-item[data-level="warn"] { border-color:#fcd34d; background:#fffbeb; }
    .proof-item[data-level="warn"] strong { color:var(--warn); }
    .proof-item[data-level="bad"] { border-color:#fda29b; background:#fef3f2; }
    .proof-item[data-level="bad"] strong { color:var(--danger); }
    .proof-item[data-level="none"] strong { color:var(--muted); font-size:17px; font-weight:600; }
    .findings { margin:0; padding:0; list-style:none; display:grid; gap:14px; }
    .finding { padding:16px 18px; border:1px solid var(--line); border-left:4px solid var(--accent2); border-radius:12px; background:var(--surface); }
    .finding[data-level="warn"] { border-left-color:#d97706; }
    .finding[data-level="bad"] { border-left-color:var(--danger); }
    .finding-head { display:flex; align-items:baseline; gap:12px; flex-wrap:wrap; }
    .finding-head h3 { margin:0; font-size:16px; }
    .finding-rank { color:var(--muted); font-size:12px; font-weight:700; letter-spacing:.06em; }
    .finding-evidence { margin-left:auto; color:var(--accent); font-size:12px; font-weight:700; text-decoration:none; }
    .finding-evidence:hover { text-decoration:underline; }
    .finding>p { margin:8px 0 0; }
    .threshold-noise { padding:18px 20px; border:1px solid #fcd34d; border-left:4px solid #d97706; border-radius:12px; background:#fffbeb; }
    .threshold-noise p { margin:0 0 10px; max-width:78ch; }
    .threshold-noise p:last-child { margin-bottom:0; }
    .no-finding { margin:0; padding:16px 18px; border:1px dashed var(--line); border-radius:12px; background:var(--surface); color:var(--muted); }
    details.dismissed { margin-top:18px; border:1px solid var(--line); border-radius:12px; background:#eef2f7; }
    details.dismissed>summary { padding:11px 16px; cursor:pointer; font-weight:600; }
    details.dismissed>summary::marker { color:var(--muted); }
    details.dismissed .dismissed-body { padding:0 16px 14px; }
    details.dismissed ul.hypotheses { margin:0; }
    details.dismissed p.muted { margin:0 0 10px; }
    @media print { .proof-item,.finding { box-shadow:none; break-inside:avoid; } details.dismissed { background:#fff; } }
"""

_LEVEL_PILLS = {
    "bad": "critical",
    "warn": "elevated",
    "ok": "nominal",
    "none": "not collected",
}


def _proof_item(label: str, value: str, level: str) -> str:
    return (
        f'<div class="proof-item" data-level="{_escape(level)}">'
        f"<span>{_escape(label)}</span><strong>{_escape(value)}</strong></div>"
    )


def _render_proof(diagnosis: dict[str, Any], batch_count: int) -> str:
    """The handful of numbers that carry the verdict, before any table."""
    context = diagnosis["context"]
    pressure = next(
        (step for step in diagnosis["steps"] if step["key"] == "pressure"), {}
    )
    items = [
        _proof_item(
            "Packet buffers",
            f"{_format_number(pressure.get('buffer_peak'))}%"
            if pressure.get("buffer_peak") is not None
            else "Not collected",
            _level(pressure.get("buffer_peak")),
        ),
        _proof_item(
            "Packet descriptors",
            f"{_format_number(pressure.get('descriptor_peak'))}%"
            if pressure.get("descriptor_peak") is not None
            else "Not collected",
            _level(pressure.get("descriptor_peak")),
        ),
    ]
    if context.get("latency_peak_ms") is not None:
        items.append(
            _proof_item(
                "Buffer latency",
                f"{_format_number(context['latency_peak_ms'])} ms",
                "warn"
                if context.get("latency_alert_ms") is not None
                and context["latency_peak_ms"] >= context["latency_alert_ms"]
                else "ok",
            )
        )
    if (mitigating := context.get("mitigating_from_percent")) is not None:
        # Mitigating at a high level is PBP doing its job. Mitigating below the
        # PAN-OS alert default is the threshold-setting signal, and that is the
        # reading this tile has to make visible at a glance.
        items.append(
            _proof_item(
                "PBP mitigated from",
                f"{_format_number(mitigating)}%",
                "warn" if mitigating < DEFAULT_ALERT_PERCENT else "ok",
            )
        )
    items.append(
        _proof_item("Batches collected", _format_number(batch_count), "ok")
    )
    return f'<div class="proof">{"".join(items)}</div>'


def _render_finding(finding: dict[str, Any], rank: int, level: str) -> str:
    named_html = ""
    if finding["named"]:
        named_html = '<ol class="step-named">' + "".join(
            f"<li>{item}</li>" for item in finding["named"]
        ) + "</ol>"
    return (
        f'<li class="finding" data-level="{_escape(level)}">'
        '<div class="finding-head">'
        f'<span class="finding-rank">{_escape(rank)}</span>'
        f'<h3>{_escape(finding["title"])}</h3>'
        f'<a class="finding-evidence" href="#{_escape(finding["anchor"])}">evidence</a>'
        "</div>"
        f'<p>{finding["text"]}</p>{named_html}</li>'
    )


def _render_dismissed(
    findings: list[dict[str, Any]], state: str, summary: str, note: str
) -> str:
    """Fold everything the investigation rejected behind a single line.

    A ruled-out cause is not noise: it is what keeps a TAC engineer from
    re-testing it. It just must not compete with the findings that hold.
    """
    if not findings:
        return ""
    items = "".join(
        f'<li class="hypothesis hypothesis-{_escape(state)}">'
        f'<span class="hypothesis-mark" aria-hidden="true"></span>'
        f'<strong>{_escape(finding["title"])}</strong> — {finding["text"]}</li>'
        for finding in findings
    )
    return (
        f'<details class="dismissed"><summary>{_escape(summary)}</summary>'
        f'<div class="dismissed-body"><p class="muted">{_escape(note)}</p>'
        f'<ul class="hypotheses">{items}</ul></div></details>'
    )


def _threshold_noise_panel(diagnosis: dict[str, Any]) -> str:
    """State that the trigger is a setting, not an incident.

    When the firewall was never short of buffers or descriptors, PBP fired
    because its threshold sits below what this firewall carries at rest. Every
    entry PBP then ranked is the busiest ordinary traffic, and presenting any
    of it as a supported cause is the misreading this panel exists to prevent.
    """
    context = diagnosis["context"]
    pressure = next(
        (step for step in diagnosis["steps"] if step["key"] == "pressure"), {}
    )
    buffer_peak = pressure.get("buffer_peak")
    mitigating = context.get("mitigating_from_percent")

    sentences = [
        "<strong>No incident on this firewall.</strong> Packet buffers peaked at "
        + (f"{_format_number(buffer_peak)}%" if buffer_peak is not None else "a level below the PAN-OS alert default")
        + ", so the dataplane was never short of buffers or descriptors."
    ]
    if mitigating is not None:
        sentences.append(
            f"PBP was nevertheless mitigating from {_format_number(mitigating)}%, "
            "which means its activate threshold sits at or below what this "
            "firewall carries at rest."
        )
        configured_alert = context.get("configured_alert_percent")
        configured_activate = context.get("configured_activate_percent")
        syslog_alert = context.get("syslog_alert_percent")
        if configured_activate is not None and mitigating < configured_activate:
            # PBP cannot mitigate below its own activate threshold. When it did,
            # the settings read did not return the thresholds in force, and
            # saying so is more useful than quoting either number as fact.
            contradiction = (
                "The running configuration read at monitor start reports alert "
                f"{_format_number(configured_alert)}% and activate "
                f"{_format_number(configured_activate)}%. PBP cannot mitigate "
                "below its own activate threshold, so those are not the "
                "thresholds that were in force"
            )
            if syslog_alert is not None:
                contradiction += (
                    f"; the firewall's own congestion log named an alert "
                    f"threshold of {_format_number(syslog_alert)}%"
                )
            contradiction += (
                ". Read the packet-buffer-protection settings on the device "
                "before drawing any conclusion from this run."
            )
            sentences.append(contradiction)
        elif configured_activate is not None:
            sentences.append(
                "The running configuration reports alert "
                f"{_format_number(configured_alert)}% and activate "
                f"{_format_number(configured_activate)}%, far below the "
                "50% and 80% PAN-OS defaults."
            )
    sentences.append(
        "There is nothing to diagnose on the machine. What has to be reviewed is "
        "the packet-buffer-protection threshold configuration: at this setting "
        "PBP triggers on ordinary traffic, and every alert it raises is noise."
    )
    return '<div class="threshold-noise">' + "".join(
        f"<p>{sentence}</p>" for sentence in sentences
    ) + "</div>"


def _render_context_ranking(findings: list[dict[str, Any]]) -> str:
    """What PBP ranked, kept as context and named as ordinary traffic."""
    if not findings:
        return ""
    items = "".join(
        f'<li class="hypothesis hypothesis-unavailable">'
        f'<span class="hypothesis-mark" aria-hidden="true"></span>'
        f'<strong>{_escape(item["title"])}</strong> — {item["text"]}'
        + (
            '<ol class="step-named">'
            + "".join(f"<li>{named}</li>" for named in item["named"])
            + "</ol>"
            if item["named"]
            else ""
        )
        + "</li>"
        for item in findings
    )
    return (
        '<details class="dismissed"><summary>What PBP ranked — ordinary traffic, '
        "not a cause</summary>"
        '<div class="dismissed-body"><p class="muted">At this pressure level the '
        "ranking is the busiest ordinary traffic seen through a lowered "
        "threshold. It is kept because it is the firewall's own designation, and "
        "it must not be read as an attack.</p>"
        f'<ul class="hypotheses">{items}</ul></div></details>'
    )


def _render_cause_layer(diagnosis: dict[str, Any]) -> tuple[str, str, str]:
    """The second layer: what holds, then what does not, then the full walk.

    Returns its body, the pill for its heading, and the lead-in sentence, all
    three of which change when the run carries no real pressure.
    """
    findings = collect_findings(diagnosis)
    confirmed = findings["confirmed"]
    level = diagnosis["headline"]["level"]
    pressure = next(
        (step for step in diagnosis["steps"] if step["key"] == "pressure"), {}
    )
    low_significance = bool(pressure.get("low_significance"))

    if low_significance:
        body = _threshold_noise_panel(diagnosis) + _render_context_ranking(confirmed)
        pill = "no incident"
    elif confirmed:
        body = '<ol class="findings">' + "".join(
            _render_finding(finding, rank, level)
            for rank, finding in enumerate(confirmed, 1)
        ) + "</ol>"
        pill = f"{len(confirmed)} supported"
    else:
        body = (
            '<p class="no-finding">Nothing in this capture supports a cause. '
            "Read the ruled-out list below to see what was tested, then the "
            "evidence: when the pressure was real and no cause holds, a Tech "
            "Support File taken close to the incident is the next step.</p>"
        )
        pill = "no cause supported"

    ruled_out = _render_dismissed(
        findings["ruled_out"],
        "negative",
        f"{len(findings['ruled_out'])} other cause"
        f"{'s' if len(findings['ruled_out']) != 1 else ''} ruled out",
        "The capture holds the evidence to reject these. They are listed so "
        "they are not tested again.",
    )
    unavailable = _render_dismissed(
        findings["unavailable"],
        "unavailable",
        f"{len(findings['unavailable'])} cause"
        f"{'s' if len(findings['unavailable']) != 1 else ''} not evaluable",
        "The commands these need returned nothing, or were not collected. "
        "Neither confirmed nor excluded.",
    )
    walk = (
        '<details class="dismissed"><summary>The full four-step investigation</summary>'
        '<div class="dismissed-body"><p class="muted">The reasoning the findings '
        "above were drawn from, step by step, exactly as the v1 report states it."
        f"</p>{render_diagnosis_steps(diagnosis)}</div></details>"
    )
    # The conclusion restates every finding above. It closes this layer rather
    # than opening the report, so an operator meets each fact once.
    conclusion = (
        '<details class="dismissed conclusion"><summary>Conclusion for the case '
        "— the paragraph to carry into the TAC case</summary>"
        f'<div class="dismissed-body">{render_diagnosis_conclusion(diagnosis)}'
        "</div></details>"
    )
    intro = (
        "This firewall was not short of resources. The section states why PBP "
        "fired anyway, and what PBP ranked is kept below as context only."
        if low_significance
        else "Only what this capture supports, most decisive first. Everything "
        "the investigation rejected is folded below, with the step-by-step "
        "reasoning it came from."
    )
    return body + ruled_out + unavailable + walk + conclusion, pill, intro


def _render_html_v2(
    source: Path,
    records: list[tuple[int, dict[str, Any]]],
    warnings: list[str],
    source_hash: str,
) -> str:
    parts = _build_report_parts(source, records, warnings, source_hash)
    diagnosis = parts["diagnosis"]
    run_id = parts["run_id"]
    title = f"PBP Report v2 — {run_id}"
    generated_at = datetime.now(timezone.utc).isoformat()

    if diagnosis is not None:
        headline = diagnosis["headline"]
        verdict_body = (
            f'<p class="headline"><strong>{_escape(headline["label"])}.</strong> '
            f'{headline["text"]}</p>'
            + _render_proof(diagnosis, len(parts["cycles"]))
            + render_diagnosis_context(diagnosis)
        )
        verdict_level = headline["level"]
        verdict_pill = _LEVEL_PILLS.get(verdict_level, "")
        cause_body, cause_pill, cause_intro = _render_cause_layer(diagnosis)
    else:
        verdict_body = (
            '<p class="headline"><strong>No batch collected.</strong> '
            "This capture holds no collection batch, so there is nothing to "
            "diagnose. The appendix below carries the records that were "
            "written.</p>"
        )
        verdict_level, verdict_pill = "none", _LEVEL_PILLS["none"]
        cause_body, cause_pill, cause_intro = "", "", ""

    layers = [
        _render_section(
            "verdict-title",
            "Verdict",
            verdict_body,
            pill=verdict_pill,
            section_class="glance verdict",
            data_level=verdict_level,
        )
    ]
    if cause_body:
        layers.append(
            _render_section(
                "cause-title",
                "What explains it",
                cause_body,
                intro=cause_intro,
                pill=cause_pill,
                section_class="cause",
            )
        )
    layers.extend(
        [
            _part_heading(
                "The evidence",
                "One folded section per source of proof, each stating its "
                "one-line verdict without being opened. Expand all (top right) "
                "unfolds everything, including for printing.",
            ),
            _evidence_sections(parts),
            _part_heading(
                "Appendix — the complete capture",
                "The capture facts, the per-batch timeline, and every raw "
                "command response, for the TAC case.",
            ),
            _appendix_sections(parts),
        ]
    )
    layers_html = "".join(layers)

    nav_items = [("verdict-title", "Verdict")]
    if cause_body:
        nav_items.append(("cause-title", "Cause"))
    nav_items.extend(
        [
            ("pressure-title", "Pressure"),
            ("attribution-title", "Offenders"),
            ("ingress-title", "Backlog"),
            ("cpu-tracking-title", "CPU"),
            ("large-sessions-title", "Largest sessions"),
            ("drop-counters-title", "Drops"),
            ("session-table-title", "Session table"),
            ("summary-title", "Summary"),
            ("timeline-title", "Timeline"),
            ("cycles-title", "Batches"),
            ("events-title", "Events"),
        ]
    )
    if parts["pbp_threat_logs_html"]:
        nav_items.insert(3 if cause_body else 2, ("pbp-threat-logs-title", "Threat logs"))
    nav_html = '<nav class="toc" aria-label="Sections">' + "".join(
        f'<a href="#{anchor}">{label}</a>' for anchor, label in nav_items
    ) + "</nav>"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src '{REPORT_V2_SCRIPT_CSP_HASH}'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
  <title>{_escape(title)}</title>
  <style>
{REPORT_STYLE}{REPORT_V2_STYLE}  </style>
</head>
<body>
  <header>
    <h1>{_escape(title)}</h1>
    <p>Static report derived from the JSONL capture. The JSONL file remains the original evidence.</p>
    <div class="facts">
      <div class="fact"><span>Start</span><strong>{_escape(_human_timestamp(parts["started_at"]))}</strong></div>
      <div class="fact"><span>End</span><strong>{_escape(_human_timestamp(parts["ended_at"]))}</strong></div>
      <div class="fact"><span>Duration</span><strong>{_escape(_human_duration(parts["duration"]))}</strong></div>
      <div class="fact"><span>Stop reason</span><strong>{parts["stop_reason_html"]}</strong></div>
      <div class="fact"><span>Target</span><strong>{_escape(parts["target_name"])}</strong></div>
      <div class="fact"><span>Device</span><strong>{_escape(parts["device_name"])}</strong></div>
      <div class="fact"><span>Model</span><strong>{_escape(parts["device_model"])}</strong></div>
      <div class="fact"><span>PAN-OS</span><strong>{_escape(parts["software_version"])}</strong></div>
      <div class="fact"><span>Collector version</span><strong>{_escape(parts["collector_version"])}</strong></div>
      <div class="fact"><span>Source</span><strong>{_escape(parts["source_name"])}</strong></div>
    </div>
  </header>
  {nav_html}
  <main>
    {parts["warning_html"]}
    {layers_html}
  </main>
  <footer>
    Generated by PBP Monitoring v{_escape(__version__)} at {_escape(generated_at)} · JSONL SHA-256: <code>{_escape(source_hash)}</code> ·
    This report may contain sensitive IP addresses, ports, device names, and serial numbers.
  </footer>
  <script>{REPORT_V2_SCRIPT}</script>
</body>
</html>
"""


def generate_html_report_v2(jsonl_path: Path, html_path: Path | None = None) -> Path:
    """Generate an atomic, standalone layered report and return its final path."""
    source, destination = resolve_report_destination(jsonl_path, html_path, ".v2.html")
    records, warnings, source_hash = _read_jsonl(source)
    return write_report_atomically(
        destination, _render_html_v2(source, records, warnings, source_hash)
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate the layered HTML report from a PBP JSONL capture."
    )
    parser.add_argument("capture", type=Path, help="incident or API-check JSONL input file")
    parser.add_argument("-o", "--output", type=Path, help="optional HTML output path")
    args = parser.parse_args(argv)

    try:
        report = generate_html_report_v2(args.capture, args.output)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"error: {exc}\n")
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
