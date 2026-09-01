import unittest
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request

from pbp_monitoring.orchestrator import (
    PanOSAPIError,
    PanOSClient,
    PanOSResponse,
    RejectRedirectHandler,
    build_candidate_entities,
    derive_session_rates,
    extract_dataplane_pool_statistics,
    extract_dp_core_functions,
    extract_global_counters,
    extract_ingress_backlogs,
    extract_live_percentages,
    extract_resource_cpu_cores,
    extract_pbp_offenders,
    extract_session_info,
    extract_pbp_status,
    extract_session_ids,
    extract_session_summary,
    extract_system_info,
    extract_trigger_metadata,
    extract_log_job_status,
    extract_traffic_log_entries,
    extract_buffer_latency,
    extract_pbp_settings,
    extract_pbp_threat_log_entries,
    firewall_clock_query_time,
    pbp_threat_log_query,
)


class StubHTTPResponse:
    """Small urlopen response double; no network is used by these tests."""

    def __init__(self, payload: str, status: int = 200):
        self.payload = payload.encode("utf-8")
        self.status = status
        self.headers = {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def getcode(self):
        return self.status

    def read(self, limit: int = -1):
        return self.payload if limit is None or limit < 0 else self.payload[:limit]


def make_client(target_serial=None):
    cfg = SimpleNamespace(
        panos_url="https://firewall.invalid",
        api_key="fixture-key",
        target_serial=target_serial,
        tls_verify=True,
        request_timeout=3.0,
    )
    return PanOSClient(cfg)


class PanOSClientCollectionTests(unittest.TestCase):
    @patch("pbp_monitoring.orchestrator.build_opener")
    def test_success_preserves_exact_raw_response_and_op_compatibility(self, mocked_build_opener):
        raw = (
            '<?xml version="1.0" encoding="UTF-8"?>\r\n'
            '<response status="success" code="19">'
            '<result><value>ready</value></result>'
            "</response>\r\n"
        )
        mocked_build_opener.return_value.open.side_effect = [
            StubHTTPResponse(raw),
            StubHTTPResponse(raw),
        ]
        client = make_client()
        command = "<show><clock/></show>"

        response = client.op_response(command)

        self.assertIsInstance(response, PanOSResponse)
        self.assertEqual(response.raw_response, raw)
        self.assertEqual(
            response.result_xml,
            "<result><value>ready</value></result>",
        )
        self.assertEqual(client.op(command), response.result_xml)

    @patch("pbp_monitoring.orchestrator.build_opener")
    def test_log_query_enqueues_then_fetches_and_parses_the_job(self, mocked_build_opener):
        enqueue = (
            '<response status="success"><result>'
            "<msg><line>query job enqueued with jobid 271</line></msg>"
            "<job>271</job></result></response>"
        )
        result = (
            '<response status="success"><result>'
            "<job><status>FIN</status><id>271</id></job>"
            '<log><logs count="1"><entry logid="1">'
            "<receive_time>2026/08/29 10:00:05</receive_time>"
            "<src>203.0.113.7</src><dst>198.51.100.15</dst>"
            "<sport>54321</sport><dport>443</dport><proto>udp</proto>"
            "<app>not-applicable</app><rule>deny-flood</rule>"
            "<action>deny</action><from>outside</from><to>inside</to>"
            "<session_end_reason>policy-deny</session_end_reason>"
            "</entry></logs></log></result></response>"
        )
        mocked_build_opener.return_value.open.side_effect = [
            StubHTTPResponse(enqueue),
            StubHTTPResponse(result),
        ]
        client = make_client()

        job = client.log_query_job("traffic", "(addr.src in '203.0.113.7')", 20)
        response = client.log_query_result(job)

        self.assertEqual(job, "271")
        self.assertEqual(extract_log_job_status(response.result_xml), "FIN")
        entries = extract_traffic_log_entries(response.result_xml)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["destination_ip"], "198.51.100.15")
        self.assertEqual(entries[0]["destination_port"], "443")
        self.assertEqual(entries[0]["rule"], "deny-flood")
        self.assertEqual(entries[0]["action"], "deny")
        self.assertEqual(entries[0]["from_zone"], "outside")

    @patch("pbp_monitoring.orchestrator.build_opener")
    def test_a_doctype_in_the_response_is_refused(self, mocked_build_opener):
        raw = (
            '<!DOCTYPE bomb [<!ENTITY a "x">]>'
            '<response status="success"><result>&a;</result></response>'
        )
        mocked_build_opener.return_value.open.return_value = StubHTTPResponse(raw)

        with self.assertRaises(PanOSAPIError) as raised:
            make_client().op_response("<show><clock/></show>")

        self.assertIn("invalid XML", str(raised.exception))

    @patch("pbp_monitoring.orchestrator.build_opener")
    def test_an_oversized_response_is_refused_without_being_stored(self, mocked_build_opener):
        class OversizedResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                return False

            def read(self, limit: int = -1):
                return b"x" * (limit if limit and limit > 0 else 1)

        mocked_build_opener.return_value.open.return_value = OversizedResponse()

        with self.assertRaises(PanOSAPIError) as raised:
            make_client().op_response("<show><clock/></show>")

        self.assertIn("size limit", str(raised.exception))
        self.assertEqual(raised.exception.raw_response, "")

    @patch("pbp_monitoring.orchestrator.build_opener")
    def test_panos_error_preserves_exact_raw_response_on_exception(self, mocked_build_opener):
        raw = (
            '<response status="error" code="17">\n'
            "  <msg><line>Unknown command é</line></msg>\n"
            "</response>\n"
        )
        mocked_build_opener.return_value.open.return_value = StubHTTPResponse(raw)

        with self.assertRaises(PanOSAPIError) as raised:
            make_client().op_response("<show><unsupported/></show>")

        self.assertEqual(raised.exception.raw_response, raw)

    @patch("pbp_monitoring.orchestrator.build_opener")
    def test_invalid_xml_preserves_exact_raw_response_on_exception(self, mocked_build_opener):
        raw = "PAN-OS proxy error\r\n<response status=\"success\"><result>truncated"
        mocked_build_opener.return_value.open.return_value = StubHTTPResponse(raw)

        with self.assertRaises(PanOSAPIError) as raised:
            make_client().op_response("<show><clock/></show>")

        self.assertEqual(raised.exception.raw_response, raw)

    @patch("pbp_monitoring.orchestrator.build_opener")
    def test_api_key_is_only_a_header_and_op_target_are_in_post_body(self, mocked_build_opener):
        raw = '<response status="success"><result>ok</result></response>'
        mocked_build_opener.return_value.open.return_value = StubHTTPResponse(raw)
        command = "<show><system><info/></system></show>"

        make_client(target_serial="fixture-serial").op_response(command)

        request = mocked_build_opener.return_value.open.call_args.args[0]
        headers = {name.lower(): value for name, value in request.header_items()}
        body_text = request.data.decode("utf-8")
        body = parse_qs(body_text, keep_blank_values=True)

        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(urlsplit(request.full_url).query, "")
        self.assertEqual(body["type"], ["op"])
        self.assertEqual(body["cmd"], [command])
        self.assertEqual(body["target"], ["fixture-serial"])
        self.assertEqual(headers["x-pan-key"], "fixture-key")
        self.assertEqual(
            headers["content-type"],
            "application/x-www-form-urlencoded",
        )
        self.assertNotIn("key", body)
        self.assertNotIn("fixture-key", request.full_url)
        self.assertNotIn("fixture-key", body_text)

    @patch("pbp_monitoring.orchestrator.build_opener")
    def test_direct_mode_omits_target_from_post_body(self, mocked_build_opener):
        raw = '<response status="success"><result>ok</result></response>'
        mocked_build_opener.return_value.open.return_value = StubHTTPResponse(raw)

        make_client().op_response("<show><clock/></show>")

        request = mocked_build_opener.return_value.open.call_args.args[0]
        body = parse_qs(request.data.decode("utf-8"), keep_blank_values=True)
        self.assertNotIn("target", body)

    def test_authenticated_api_redirects_are_refused(self):
        handler = RejectRedirectHandler()
        request = Request("https://firewall.invalid/api/", data=b"type=op")
        request.add_unredirected_header("X-PAN-KEY", "fixture-key")

        with self.assertRaisesRegex(PanOSAPIError, "redirect refused"):
            handler.redirect_request(
                request,
                None,
                302,
                "Found",
                {},
                "http://other.invalid/",
            )


class CollectionParsingTests(unittest.TestCase):
    def test_pbp_offenders_preserve_session_ip_directions_and_drop_evidence(self):
        output = """
dp0
Session/IP Address | Zone | PCS | Percentage | State | Total | Dropped | Time till discard
38492 | trust | 4088 | 49 | Yes | 381171 | 121232 | 59
38492 | untrust | 4024 | 49 | Yes | 392557 | 125172 | 57
172.16.1.1 | trust | 31 | 0 | No | 721 | 0 | 60
"""

        offenders = extract_pbp_offenders(output)

        self.assertEqual(len(offenders), 3)
        self.assertEqual(offenders[0]["session_id"], 38492)
        self.assertTrue(offenders[0]["drop_state"])
        self.assertEqual(offenders[1]["zone"], "untrust")
        self.assertEqual(offenders[2]["entity_type"], "source_ip")
        self.assertEqual(offenders[2]["source_ip"], "172.16.1.1")

        entities = build_candidate_entities(offenders, [], [])
        self.assertEqual(entities[0]["session_id"], 38492)
        self.assertEqual(entities[0]["pbp_percentage_total"], 98.0)
        self.assertEqual(entities[0]["pbp_samples"], 8112)

        status = extract_pbp_status(
            "Packet buffer count based\nCongestion: 12431/17203 (72%)\n"
            "Drop probability: 74%. Percentage drop threshold: 48.",
            offenders,
        )
        self.assertEqual(status["mode"], "packet_buffer")
        self.assertTrue(status["active"])
        self.assertEqual(status["drop_probability_percentage"], 74.0)

    def test_pbp_offenders_parse_the_structured_xml_entry_table(self):
        output = """<result>
  <sw.comm.s1.dp0.packet-buffer-protection>
    <is-module-enabled>True</is-module-enabled>
    <is-monitor-only>False</is-monitor-only>
    <is-running>True</is-running>
    <use-buffer>1</use-buffer>
    <congestion>54000</congestion>
    <congestion-max>97280</congestion-max>
    <entries>
      <entry>
        <value>54048</value>
        <zone>untrust</zone>
        <pcs>622</pcs>
        <perc>7</perc>
        <drop-state>Yes</drop-state>
        <num-total>252</num-total>
        <num-dropped>9</num-dropped>
        <time-till-discard>60</time-till-discard>
        <heap-index>0</heap-index>
      </entry>
      <entry>
        <value>192.0.2.10</value>
        <zone>trust</zone>
        <pcs>416</pcs>
        <perc>5</perc>
        <drop-state>No</drop-state>
        <num-total>11105</num-total>
        <num-dropped>0</num-dropped>
        <time-till-discard>60</time-till-discard>
        <heap-index>1</heap-index>
      </entry>
    </entries>
  </sw.comm.s1.dp0.packet-buffer-protection>
</result>"""

        offenders = extract_pbp_offenders(output)

        self.assertEqual(len(offenders), 2)
        self.assertEqual(offenders[0]["entity_type"], "session")
        self.assertEqual(offenders[0]["session_id"], 54048)
        self.assertEqual(offenders[0]["dp"], "dp0")
        self.assertEqual(offenders[0]["zone"], "untrust")
        self.assertEqual(offenders[0]["samples"], 622)
        self.assertEqual(offenders[0]["percentage"], 7.0)
        self.assertTrue(offenders[0]["drop_state"])
        self.assertEqual(offenders[0]["packets_total"], 252)
        self.assertEqual(offenders[0]["packets_dropped"], 9)
        self.assertEqual(offenders[0]["time_till_discard_seconds"], 60)
        self.assertEqual(offenders[1]["entity_type"], "source_ip")
        self.assertEqual(offenders[1]["source_ip"], "192.0.2.10")
        self.assertFalse(offenders[1]["drop_state"])

        entities = build_candidate_entities(offenders, [], [])
        self.assertEqual(entities[0]["session_id"], 54048)
        self.assertEqual(entities[1]["source_ip"], "192.0.2.10")

        status = extract_pbp_status(output, offenders)
        self.assertTrue(status["active"])
        self.assertEqual(status["mode"], "packet_buffer")

    def test_pbp_offenders_ignore_a_structured_response_without_entries(self):
        output = """<result>
  <sw.comm.s1.dp0.packet-buffer-protection>
    <is-module-enabled>True</is-module-enabled>
    <is-running>False</is-running>
  </sw.comm.s1.dp0.packet-buffer-protection>
</result>"""

        self.assertEqual(extract_pbp_offenders(output), [])

    def test_session_info_reads_the_table_protocol_mix_and_rates_from_xml(self):
        output = """<result>
  <num-max>200000</num-max>
  <num-active>315</num-active>
  <num-tcp>204</num-tcp>
  <num-udp>111</num-udp>
  <num-icmp>0</num-icmp>
  <num-predict>0</num-predict>
  <num-installed>1383770</num-installed>
  <cps>2</cps>
  <pps>118</pps>
  <kbps>219</kbps>
  <dp>*.dp0</dp>
</result>"""

        parsed = extract_session_info(output)

        self.assertEqual(len(parsed["dataplanes"]), 1)
        dataplane = parsed["dataplanes"][0]
        self.assertEqual(dataplane["dp"], "*.dp0")
        self.assertEqual(dataplane["allocated"], 315)
        self.assertEqual(dataplane["supported"], 200000)
        self.assertEqual(dataplane["tcp"], 204)
        self.assertEqual(dataplane["udp"], 111)
        self.assertEqual(dataplane["created_since_bootup"], 1383770)
        self.assertEqual(dataplane["connection_rate_cps"], 2)
        self.assertEqual(dataplane["packet_rate_pps"], 118)
        self.assertEqual(dataplane["throughput_kbps"], 219)
        # PAN-OS returns no utilization field, so it is derived.
        self.assertEqual(dataplane["utilization_percentage"], 0.16)
        self.assertEqual(parsed["totals"]["allocated"], 315)

    def test_session_info_reads_the_cli_text_form_of_every_dataplane(self):
        output = """
target-dp:                                       *.dp0
Number of sessions supported:                    200000
Number of allocated sessions:                    421
Number of active TCP sessions:                   206
Number of active UDP sessions:                   215
Number of active ICMP sessions:                  0
Number of active predict sessions:               1
Session table utilization:                       0%
Number of sessions created since bootup:         1254101
Packet rate:                                     160/s
Throughput:                                      623 kbps
New connection establish rate:                   4 cps

target-dp:                                       *.dp1
Number of sessions supported:                    200000
Number of allocated sessions:                    79
Number of active TCP sessions:                   40
Number of active UDP sessions:                   39
Packet rate:                                     20/s
Throughput:                                      100 kbps
New connection establish rate:                   1 cps
"""

        parsed = extract_session_info(output)

        self.assertEqual(
            [dataplane["dp"] for dataplane in parsed["dataplanes"]],
            ["*.dp0", "*.dp1"],
        )
        self.assertEqual(parsed["dataplanes"][0]["allocated"], 421)
        self.assertEqual(parsed["dataplanes"][0]["predict"], 1)
        self.assertEqual(parsed["dataplanes"][1]["tcp"], 40)
        totals = parsed["totals"]
        self.assertEqual(totals["allocated"], 500)
        self.assertEqual(totals["supported"], 400000)
        self.assertEqual(totals["packet_rate_pps"], 180)
        self.assertEqual(totals["throughput_kbps"], 723)
        self.assertEqual(totals["connection_rate_cps"], 5)
        self.assertEqual(totals["utilization_percentage"], 0.12)

    def test_session_info_failure_yields_no_dataplane_instead_of_raising(self):
        parsed = extract_session_info("<response status=\"error\"><msg/></response>")

        self.assertEqual(parsed["dataplanes"], [])
        self.assertIsNone(parsed["totals"]["allocated"])

    def test_ingress_backlogs_retains_dp_groups_and_any_ip_protocol(self):
        output = """
-- SLOT: s1, DP: dp0 --
USAGE - ATOMIC: 88.5% TOTAL: 89.25%
TOP SESSIONS:
SESS-ID PCT GRP-ID COUNT
2022536315 88% flow_slowpath 3640 7 12
SESSION DETAILS
SESS-ID PROTO SZONE SRC SPORT DST DPORT IGR-IF EGR-IF APP
2022536315 89 trust 192.0.2.10 514 198.51.100.20 514 ethernet1/1 ethernet1/2 unknown
"""

        parsed = extract_ingress_backlogs(output)

        self.assertEqual(parsed["dataplanes"][0]["atomic_percentage"], 88.5)
        candidate = parsed["candidates"][0]
        self.assertEqual(candidate["session_id"], 2022536315)
        self.assertEqual(candidate["group_id"], "flow_slowpath")
        self.assertEqual(len(candidate["groups"]), 2)
        self.assertEqual(candidate["protocol"], 89)
        self.assertEqual(candidate["source_ip"], "192.0.2.10")
        self.assertEqual(candidate["application"], "unknown")

    def test_candidate_ranking_enriches_responsible_id_before_smaller_id(self):
        offenders = extract_pbp_offenders(
            "1 | trust | 1 | 0 | No | 1 | 0 | 60\n"
            "999 | trust | 7000 | 85 | Yes | 9000 | 1000 | 5"
        )

        entities = build_candidate_entities(offenders, [], [1, 999])

        self.assertEqual(
            [entity["session_id"] for entity in entities],
            [999, 1],
        )

    def test_session_snapshot_normalizes_tuple_and_diagnostic_fields(self):
        output = """
Session 35299
c2s flow:
 source: 192.0.2.10 [trust]
 dst: 198.51.100.20
 proto: 6
 sport: 52648 dport: 443
 state: ACTIVE type: FLOW
 src-user: alice
 dst-user: unknown
s2c flow:
 source: 198.51.100.20 [untrust]
 dst: 203.0.113.5
 proto: 6
 sport: 443 dport: 40000
 state: ACTIVE type: FLOW
start time: Thu Aug 27 14:00:00 2026
total byte count(c2s): 33844960
total byte count(s2c): 1200
layer7 packet count(c2s): 412712
application: ssl
rule: allow-web
ingress interface: ethernet1/1
egress interface: ethernet1/2
layer7 processing: completed
session tracker stage l7proc: app identified
"""

        summary = extract_session_summary(output)

        self.assertEqual(summary["session_id"], 35299)
        self.assertEqual(summary["c2s"]["source_ip"], "192.0.2.10")
        self.assertEqual(summary["c2s"]["destination_port"], 443)
        self.assertEqual(summary["s2c"]["destination_ip"], "203.0.113.5")
        self.assertEqual(summary["application"], "ssl")
        self.assertEqual(summary["total_bytes_c2s"], 33844960)
        self.assertEqual(summary["tracker_stages"]["l7proc"], "app identified")

    def test_session_rates_use_counter_deltas_and_reject_reused_sessions(self):
        previous_samples = {}
        baseline = {
            "42": {
                "session_id": 42,
                "available": True,
                "start_time": "Thu Aug 27 14:00:00 2026",
                "total_bytes_c2s": 1000,
                "total_bytes_s2c": 500,
            }
        }
        current = {
            "42": {
                **baseline["42"],
                "total_bytes_c2s": 4000,
                "total_bytes_s2c": 1500,
            }
        }

        first = derive_session_rates(baseline, previous_samples, 10.0)
        second = derive_session_rates(current, previous_samples, 15.0)
        reused = derive_session_rates(
            {
                "42": {
                    **current["42"],
                    "start_time": "Thu Aug 27 15:00:00 2026",
                }
            },
            previous_samples,
            20.0,
        )

        self.assertEqual(first["42"]["status"], "baseline")
        self.assertEqual(second["42"]["status"], "calculated")
        self.assertEqual(second["42"]["delta_bytes_total"], 4000)
        self.assertEqual(second["42"]["bits_per_second_total"], 6400.0)
        self.assertEqual(reused["42"]["status"], "session_reused")

    def test_structured_session_snapshot_and_ingress_candidate_are_supported(self):
        session_xml = """
<result><session><id>99</id><c2s>
  <source>192.0.2.10</source><source-zone>trust</source-zone>
  <destination>198.51.100.20</destination><protocol>132</protocol>
  <source-port>5000</source-port><destination-port>5001</destination-port>
  <state>ACTIVE</state><type>FLOW</type>
</c2s><application>sctp</application><rule>allow-sctp</rule>
</session></result>
""".strip()
        ingress_xml = """
<result><entry><SESS-ID>99</SESS-ID><PCT>76.5</PCT>
  <GRP-ID>flow_fastpath</GRP-ID><COUNT>900</COUNT>
  <PROTO>132</PROTO><SZONE>trust</SZONE><SRC>192.0.2.10</SRC>
  <SPORT>5000</SPORT><DST>198.51.100.20</DST><DPORT>5001</DPORT>
  <IGR-IF>ethernet1/1</IGR-IF><EGR-IF>ethernet1/2</EGR-IF><APP>sctp</APP>
</entry></result>
""".strip()

        summary = extract_session_summary(session_xml)
        candidate = extract_ingress_backlogs(ingress_xml)["candidates"][0]

        self.assertEqual(summary["session_id"], 99)
        self.assertEqual(summary["c2s"]["protocol"], 132)
        self.assertEqual(summary["application"], "sctp")
        self.assertEqual(candidate["percentage"], 76.5)
        self.assertEqual(candidate["source_port"], 5000)
        self.assertEqual(candidate["application"], "sctp")

    def test_bad_key_and_labelled_trigger_metadata_are_explicit(self):
        summary = extract_session_summary(
            "Session 2022536315\nBad Key: c2s: 'c2s'\nBad Key: s2c: 's2c'"
        )
        metadata = extract_trigger_metadata(
            "PBP Session Discarded threat-id=8508 session-id=42 "
            "src=192.0.2.1 dst=198.51.100.2"
        )

        self.assertEqual(summary["status"], "bad_key")
        self.assertFalse(summary["available"])
        self.assertEqual(metadata["trigger_type"], "pbp_session_discarded")
        self.assertEqual(metadata["threat_id"], 8508)
        self.assertEqual(metadata["session_id"], 42)
        self.assertEqual(metadata["source_ip"], "192.0.2.1")

    THREAT_CSV_LINE = (
        "PBP_SYSLOG_SOURCE=192.0.2.10 <14>Aug 29 10:00:00 lab-fw-01 "
        "1,2026/08/29 10:00:00,012345678901,THREAT,flood,2561,"
        "2026/08/29 10:00:00,203.0.113.7,198.51.100.15,0.0.0.0,0.0.0.0,"
        '"allow-outbound,legacy",,,not-applicable,vsys1,outside,inside,'
        "ethernet1/1,ethernet1/2,default,2026/08/29 10:00:00,123456,1,"
        '54321,443,0,0,0x0,udp,drop,"",PBP Packet Drop(8507),any,critical,'
        "client-to-server"
    )

    def test_positional_threat_csv_fields_expose_the_responsible_flow(self):
        metadata = extract_trigger_metadata(self.THREAT_CSV_LINE)

        self.assertEqual(metadata["trigger_type"], "pbp_packet_drop")
        self.assertEqual(metadata["threat_id"], 8507)
        self.assertEqual(metadata["device_serial"], "012345678901")
        self.assertEqual(metadata["syslog_source_ip"], "192.0.2.10")
        self.assertEqual(metadata["source_ip"], "203.0.113.7")
        self.assertEqual(metadata["destination_ip"], "198.51.100.15")
        self.assertEqual(metadata["source_port"], 54321)
        self.assertEqual(metadata["destination_port"], 443)
        self.assertEqual(metadata["session_id"], 123456)
        self.assertEqual(metadata["application"], "not-applicable")
        self.assertEqual(metadata["rule"], "allow-outbound,legacy")
        self.assertEqual(metadata["from_zone"], "outside")
        self.assertEqual(metadata["to_zone"], "inside")
        self.assertEqual(metadata["ingress_interface"], "ethernet1/1")
        self.assertEqual(metadata["protocol"], "udp")
        self.assertEqual(metadata["action"], "drop")

    def test_a_system_log_gets_no_positional_flow_fields(self):
        message = (
            "PBP_SYSLOG_SOURCE=192.0.2.10 <14>Aug 29 10:00:00 lab-fw-01 "
            "1,2026/08/29 10:00:00,012345678901,SYSTEM,general,,"
            "2026/08/29 10:00:00,,,general,,,,,informational,"
            "Packet buffer congestion is at 62 percent"
        )

        metadata = extract_trigger_metadata(message)

        self.assertEqual(metadata["trigger_type"], "packet_buffer_congestion")
        self.assertEqual(metadata["device_serial"], "012345678901")
        self.assertNotIn("source_ip", metadata)
        self.assertNotIn("session_id", metadata)

    def test_unroutable_placeholder_addresses_are_not_extracted(self):
        line = self.THREAT_CSV_LINE.replace("203.0.113.7", "0.0.0.0")

        metadata = extract_trigger_metadata(line)

        self.assertNotIn("source_ip", metadata)
        self.assertEqual(metadata["destination_ip"], "198.51.100.15")

    def test_native_panos_pbp_threat_name_exposes_threat_id(self):
        for name, expected in (
            ("PBP Packet Drop(8507)", 8507),
            ("PBP Session Discarded (8508)", 8508),
            ("PBP IP Blocked(8509)", 8509),
        ):
            with self.subTest(name=name):
                metadata = extract_trigger_metadata(name)
                self.assertEqual(metadata["threat_id"], expected)

    def test_flow_slowpath_id_is_extracted_but_ipv4_is_not(self):
        ingress = """
TOP SESSIONS:
SESS-ID         PCT     GRP-ID          COUNT
2022536315      88.5%   flow_slowpath   3640
"""
        pbp = """
51718          | vw-trust | 9  | 0 | No
172.16.1.1     | vw-trust | 31 | 0 | No
"""

        self.assertEqual(
            extract_session_ids(pbp, ingress),
            [51718, 2022536315],
        )

    def test_ingress_percentages_preserve_decimal_values(self):
        percentages = extract_live_percentages(
            "",
            "USAGE - ATOMIC: 88.5% TOTAL: 89.25%",
            "",
        )

        self.assertEqual(percentages["descriptor_atomic"], [88.5])
        self.assertEqual(percentages["descriptor_total"], [89.25])

    def test_dataplane_packet_buffer_pool_reports_usage_and_low_limit(self):
        output = """
Pow Atomic Memory Pools
[ 0] Work Queue Entries        :   284357/284672   0xd04be09f00
[ 1] Packet Buffers            :    93401/97280    0x8070bf3a40

        Low free buffer limit :    94208
"""

        parsed = extract_dataplane_pool_statistics(output)
        packet_buffers = parsed["packet_buffers"]
        percentages = extract_live_percentages("", "", "", output)

        self.assertTrue(parsed["parsed"])
        self.assertEqual(packet_buffers["available"], 93401)
        self.assertEqual(packet_buffers["used"], 3879)
        self.assertEqual(packet_buffers["used_percentage"], 3.987)
        self.assertEqual(packet_buffers["low_free_buffer_limit"], 94208)
        self.assertTrue(packet_buffers["below_low_free_buffer_limit"])
        self.assertEqual(
            percentages["dataplane_pool_packet_buffer_used"],
            [3.987],
        )

    def test_asic_pool_lines_parse_and_pki_pool_reports_the_worst_dataplane(self):
        # Anonymized PA-5250 shape: per-DP tables, hardware rows with an
        # address and interrupt column, software rows with an object size and
        # extra fraction columns, and no "Packet Buffers" pool at all.
        output = """
DP s1dp0:


Hardware Pools
[55] Timer Pool                :     4093/4096     0x800000080f158c00    0
[61] PKI POOL DFLT             :    12684/17203    0x800000072cb21000    0

Software Pools
Id   Name                      Length         Free/Total      HighWm/Populated  Used/Total  DataRange                  CacheSz
[10] software packet buffer 0  (    512):   205481/208000      15032/24570         6/51     0x8000000377800080-0x80000003779ffe80* 10725

Software Pool Segment Info
Id    SegSize      MaxSegs    NumActive  None       Default    Overflow   Unused     Depleted   Assigned   va_mask
[ 10] 2097152      51         6          45         6          0          0          0          0          0xffffffffffe00000

DP s1dp1:


Hardware Pools
[55] Timer Pool                :     4096/4096     0x800000080f158c00    0
[61] PKI POOL DFLT             :     2170/17203    0x800000072cb21000    0
"""

        parsed = extract_dataplane_pool_statistics(output)
        packet_buffers = parsed["packet_buffers"]
        percentages = extract_live_percentages("", "", "", output)

        self.assertTrue(parsed["parsed"])
        self.assertEqual(len(parsed["pools"]), 5)
        software = next(
            pool
            for pool in parsed["pools"]
            if pool["name"] == "software packet buffer 0"
        )
        self.assertEqual(software["dataplane"], "s1dp0")
        self.assertEqual(software["object_bytes"], 512)
        self.assertEqual(software["available"], 205481)
        self.assertEqual(software["total"], 208000)
        self.assertEqual(packet_buffers["name"], "PKI POOL DFLT")
        self.assertEqual(packet_buffers["dataplane"], "s1dp1")
        self.assertEqual(packet_buffers["available"], 2170)
        self.assertEqual(packet_buffers["used_percentage"], 87.386)
        self.assertIsNone(packet_buffers["low_free_buffer_limit"])
        self.assertIsNone(packet_buffers["below_low_free_buffer_limit"])
        self.assertEqual(
            percentages["dataplane_pool_packet_buffer_used"],
            [87.386],
        )

    def test_named_packet_buffers_pool_still_wins_over_pki_pool(self):
        output = """
Hardware Pools
[ 1] Packet Buffers            :    93401/97280    0x8070bf3a40
[61] PKI POOL DFLT             :     2170/17203    0x800000072cb21000    0
"""

        packet_buffers = extract_dataplane_pool_statistics(output)[
            "packet_buffers"
        ]

        self.assertEqual(packet_buffers["name"], "Packet Buffers")

    def test_global_counter_delta_normalizes_flow_rows(self):
        output = """
Global counters:
Elapsed time since last sampling: 3.675 seconds
name                                   value     rate severity  category  aspect    description
flow_np_pkt_rcv                           32        8 info      flow      offload   Packets received
flow_dos_pbp_block_host                    4        1 drop      flow      dos       Packets dropped by PBP
pkt_recv                                  43       11 info      packet    pktproc   Packets received
"""

        parsed = extract_global_counters(output)

        self.assertEqual(parsed["elapsed_seconds"], 3.675)
        self.assertEqual(len(parsed["counters"]), 3)
        self.assertEqual(
            [counter["name"] for counter in parsed["flow_counters"]],
            ["flow_np_pkt_rcv", "flow_dos_pbp_block_host"],
        )
        self.assertEqual(parsed["flow_counters"][1]["severity"], "drop")
        self.assertEqual(
            [counter["name"] for counter in parsed["significant_counters"]],
            ["flow_dos_pbp_block_host"],
        )

    def test_structured_global_counter_delta_uses_elapsed_milliseconds(self):
        output = """
<result><dp>dp0</dp><global><t>3675</t><counters><entry>
  <name>flow_dos_pbp_block_host</name><value>4</value><rate>1</rate>
  <severity>drop</severity><category>flow</category><aspect>dos</aspect>
  <desc>Packets dropped by PBP</desc><id>1131</id>
</entry></counters></global></result>
""".strip()

        parsed = extract_global_counters(output)

        self.assertTrue(parsed["parsed"])
        self.assertEqual(parsed["elapsed_seconds"], 3.675)
        self.assertEqual(len(parsed["flow_counters"]), 1)
        self.assertEqual(parsed["flow_counters"][0]["dataplane"], "dp0")
        self.assertEqual(parsed["flow_counters"][0]["id"], 1131)
        self.assertEqual(len(parsed["significant_counters"]), 1)

    def test_core_function_groups_are_read_from_statistics_xml(self):
        statistics = """
<result>
  <entry><dp>dp0</dp><entries>
    <entry><id>0</id><pid>1000</pid><modules>
      <member>pan_timer</member>
    </modules></entry>
    <entry><id>1</id><pid>1001</pid><modules>
      <member>flow_lookup</member><member>flow_fastpath</member>
      <member>flow_mgmt</member>
    </modules></entry>
  </entries></entry>
  <entry><dp>dp1</dp><entries>
    <entry><id>1</id><pid>2001</pid><modules>
      <member>flow_lookup</member><member>flow_fastpath</member>
    </modules></entry>
  </entries></entry>
</result>
""".strip()

        cores = extract_dp_core_functions(statistics)

        self.assertEqual(
            [(core["dataplane"], core["core_id"]) for core in cores],
            [("dp0", "0"), ("dp0", "1"), ("dp1", "1")],
        )
        self.assertEqual(cores[0]["functions"], ["pan_timer"])
        self.assertFalse(cores[0]["forwards_traffic"])
        self.assertTrue(cores[1]["forwards_traffic"])
        self.assertIn("flow_mgmt", cores[1]["functions"])

    def test_core_function_groups_fall_back_to_cli_task_lines(self):
        statistics = (
            "<result>"
            "task  0(pid:   4292) pan_timer\n"
            "task  1(pid:   4287) flow_lookup flow_fastpath flow_ctrl\n"
            "</result>"
        )

        cores = extract_dp_core_functions(statistics)

        self.assertEqual([core["core_id"] for core in cores], ["0", "1"])
        self.assertEqual(cores[0]["dataplane"], "dp0")
        self.assertEqual(cores[1]["functions"], ["flow_lookup", "flow_fastpath", "flow_ctrl"])
        self.assertTrue(cores[1]["forwards_traffic"])

    def test_unreadable_statistics_output_yields_no_core_functions(self):
        self.assertEqual(extract_dp_core_functions(""), [])
        self.assertEqual(extract_dp_core_functions("<result>not a task list</result>"), [])

    def test_resource_monitor_uses_latest_value_from_second_view(self):
        resource_monitor = """
Resource monitoring sampling data (per second):
CPU load (%) during last 5 seconds:
core 0 1 2
  * 12 81
Resource utilization (%) during last 5 seconds:
session:
  1  2  3  4  5
packet buffer:
 14 13 12 11 10
packet descriptor:
  7  6  5  4  3
packet descriptor (on-chip):
 91 90 89 88 87

Resource monitoring sampling data (per minute):
Resource utilization (%) during last 60 minutes:
packet buffer:
 99 98 97
packet descriptor:
 98 97 96
packet descriptor (on-chip):
 97 96 95
"""

        percentages = extract_live_percentages("", "", resource_monitor)

        self.assertEqual(percentages["resource_monitor_dp_cpu"], [81])
        self.assertEqual(percentages["resource_monitor_session"], [1])
        self.assertEqual(percentages["resource_monitor_packet_buffer"], [14])
        self.assertEqual(percentages["resource_monitor_packet_descriptor"], [7])
        self.assertEqual(
            percentages["resource_monitor_packet_descriptor_on_chip"],
            [91],
        )
        cores = extract_resource_cpu_cores(resource_monitor)
        self.assertEqual(
            [(core["core_id"], core["utilization"]) for core in cores],
            [(1, 12.0), (2, 81.0)],
        )
        self.assertEqual(cores[1]["window_peak"], 81.0)
        self.assertEqual(cores[1]["sample_count"], 1)

    def test_resource_monitor_xml_keeps_per_dataplane_attribution(self):
        resource_monitor = """
<response status="success"><result><resource-monitor><data-processors>
<s1dp0><second><resource-utilization>
  <entry><name>session</name><value>2,2,2</value></entry>
  <entry><name>packet buffer</name><value>7,7,6</value></entry>
  <entry><name>packet descriptor (on-chip)</name><value>9,8,8</value></entry>
</resource-utilization></second></s1dp0>
<s1dp1><second><resource-utilization>
  <entry><name>session</name><value>2,2,2</value></entry>
  <entry><name>packet buffer</name><value>87,87,87</value></entry>
  <entry><name>packet descriptor (on-chip)</name><value>92,91,90</value></entry>
</resource-utilization></second></s1dp1>
</data-processors></resource-monitor></result></response>
""".strip()

        percentages = extract_live_percentages("", "", resource_monitor)

        self.assertEqual(
            percentages["resource_monitor_packet_buffer"], [7.0, 87.0]
        )
        self.assertEqual(
            percentages["resource_monitor_dataplanes"],
            [
                {
                    "dataplane": "s1dp0",
                    "session": 2.0,
                    "packet_buffer": 7.0,
                    "packet_descriptor_on_chip": 9.0,
                },
                {
                    "dataplane": "s1dp1",
                    "session": 2.0,
                    "packet_buffer": 87.0,
                    "packet_descriptor_on_chip": 92.0,
                },
            ],
        )

    def test_resource_monitor_text_keeps_per_dataplane_attribution(self):
        resource_monitor = """
DP s1dp0:

Resource monitoring sampling data (per second):
Resource utilization (%) during last 5 seconds:
packet buffer:
  7  7  6
packet descriptor (on-chip):
  9  8  8

DP s1dp1:

Resource monitoring sampling data (per second):
Resource utilization (%) during last 5 seconds:
packet buffer:
 87 87 87
packet descriptor (on-chip):
 92 91 90
"""

        percentages = extract_live_percentages("", "", resource_monitor)

        self.assertEqual(
            percentages["resource_monitor_packet_buffer"], [7.0, 87.0]
        )
        self.assertEqual(
            percentages["resource_monitor_dataplanes"],
            [
                {
                    "dataplane": "s1dp0",
                    "packet_buffer": 7.0,
                    "packet_descriptor_on_chip": 9.0,
                },
                {
                    "dataplane": "s1dp1",
                    "packet_buffer": 87.0,
                    "packet_descriptor_on_chip": 92.0,
                },
            ],
        )

    def test_structured_panos_metrics_are_parsed(self):
        pbp = """
<response status="success"><result>
  <sw.comm.fixture.packet-buffer-protection>
    <congestion>25</congestion><congestion-max>100</congestion-max>
  </sw.comm.fixture.packet-buffer-protection>
</result></response>
""".strip()
        ingress = """
<response status="success"><result><entry>
  <SLOT>1</SLOT><DP>0</DP><ATOMIC>12.5</ATOMIC><TOTAL>13.75</TOTAL>
</entry></result></response>
""".strip()
        resource_monitor = """
<response status="success"><result><resource-monitor><data-processors><dp0>
  <second><cpu-load><entry><coreid>0</coreid><value>10,9,8</value></entry>
    <entry><coreid>3</coreid><value>81,80,79</value></entry></cpu-load><resource-utilization>
    <entry><name>session</name><value>4,3,2</value></entry>
    <entry><name>packet buffer</name><value>24,23,22</value></entry>
    <entry><name>packet descriptor</name><value>3,2,1</value></entry>
    <entry><name>packet descriptor (on-chip)</name><value>8,7,6</value></entry>
    <entry><name>sw tags descriptor</name><value>9,8,7</value></entry>
  </resource-utilization></second>
</dp0></data-processors></resource-monitor></result></response>
""".strip()

        percentages = extract_live_percentages(pbp, ingress, resource_monitor)
        pbp_status = extract_pbp_status(pbp)

        self.assertEqual(percentages["packet_buffer_congestion"], [25.0])
        self.assertEqual(pbp_status["congestion_percentage"], 25.0)
        self.assertEqual(percentages["descriptor_atomic"], [12.5])
        self.assertEqual(percentages["descriptor_total"], [13.75])
        self.assertEqual(percentages["resource_monitor_dp_cpu"], [81.0])
        cores = extract_resource_cpu_cores(resource_monitor)
        self.assertEqual(
            [(core["core_id"], core["utilization"]) for core in cores],
            [("0", 10.0), ("3", 81.0)],
        )
        self.assertEqual(cores[1]["maximum_series"], [81.0, 80.0, 79.0])
        self.assertEqual(cores[1]["window_peak"], 81.0)
        self.assertEqual(percentages["resource_monitor_session"], [4.0])
        self.assertEqual(percentages["resource_monitor_packet_buffer"], [24.0])
        self.assertEqual(percentages["resource_monitor_packet_descriptor"], [3.0])
        self.assertEqual(
            percentages["resource_monitor_packet_descriptor_on_chip"], [8.0]
        )
        self.assertEqual(
            percentages["resource_monitor_sw_tags_descriptor"], [9.0]
        )

    def test_structured_pbp_xml_reports_active_mitigation_and_mode(self):
        pbp = """
<response status="success"><result>
  <sw.comm.fixture.packet-buffer-protection>
    <is-module-enabled>True</is-module-enabled>
    <is-monitor-only>False</is-monitor-only>
    <congestion>4352</congestion>
    <congestion-max>97280</congestion-max>
    <max-tolerate>77824</max-tolerate>
    <use-latency>0</use-latency>
    <use-buffer>1</use-buffer>
    <is-mitigation-enabled>True</is-mitigation-enabled>
    <is-running>True</is-running>
  </sw.comm.fixture.packet-buffer-protection>
</result></response>
""".strip()

        status = extract_pbp_status(pbp)

        self.assertIs(status["active"], True)
        self.assertEqual(status["mode"], "packet_buffer")
        self.assertIs(status["enabled"], True)
        self.assertIs(status["monitor_only"], False)
        self.assertEqual(status["congestion_percentage"], 4.474)

    def test_structured_pbp_xml_separates_idle_mitigation_from_unknown(self):
        pbp = """
<response status="success"><result>
  <sw.comm.fixture.packet-buffer-protection>
    <is-module-enabled>True</is-module-enabled>
    <is-monitor-only>True</is-monitor-only>
    <congestion>0</congestion>
    <congestion-max>97280</congestion-max>
    <use-latency>0</use-latency>
    <use-buffer>1</use-buffer>
    <is-running>False</is-running>
  </sw.comm.fixture.packet-buffer-protection>
</result></response>
""".strip()

        status = extract_pbp_status(pbp)

        self.assertIs(status["active"], False)
        self.assertIs(status["monitor_only"], True)
        self.assertEqual(status["mode"], "packet_buffer")

    def test_one_dataplane_in_mitigation_marks_the_firewall_active(self):
        pbp = """
<response status="success"><result>
  <sw.comm.fixture.dp0.packet-buffer-protection>
    <is-module-enabled>True</is-module-enabled>
    <use-latency>1</use-latency>
    <use-buffer>0</use-buffer>
    <is-running>False</is-running>
  </sw.comm.fixture.dp0.packet-buffer-protection>
  <sw.comm.fixture.dp1.packet-buffer-protection>
    <is-module-enabled>True</is-module-enabled>
    <use-latency>1</use-latency>
    <use-buffer>0</use-buffer>
    <is-running>True</is-running>
  </sw.comm.fixture.dp1.packet-buffer-protection>
</result></response>
""".strip()

        status = extract_pbp_status(pbp)

        self.assertIs(status["active"], True)
        self.assertEqual(status["mode"], "latency")

    def test_text_only_pbp_output_keeps_unknown_activation_state(self):
        status = extract_pbp_status("Packet buffer protection is enabled\n")

        self.assertIsNone(status["active"])
        self.assertEqual(status["mode"], "unknown")

    def test_pa440_cpu_average_and_maximum_are_tracked_per_core(self):
        resource_monitor = """
<result><resource-monitor><data-processors><dp0><second>
  <cpu-load-average>
    <entry><coreid>0</coreid><value>4,3,2</value></entry>
    <entry><coreid>1</coreid><value>72,20,10</value></entry>
  </cpu-load-average>
  <cpu-load-maximum>
    <entry><coreid>0</coreid><value>9,8,7</value></entry>
    <entry><coreid>1</coreid><value>100,80,60</value></entry>
  </cpu-load-maximum>
</second></dp0></data-processors></resource-monitor></result>
""".strip()

        self.assertEqual(
            extract_resource_cpu_cores(resource_monitor),
            [
                {
                    "dataplane": "dp0",
                    "core_id": "0",
                    "average_series": [4.0, 3.0, 2.0],
                    "maximum_series": [9.0, 8.0, 7.0],
                    "average": 4.0,
                    "maximum": 9.0,
                    "utilization": 9.0,
                    "window_average": 3.0,
                    "window_peak": 9.0,
                    "seconds_at_or_above_90": 0,
                    "sample_count": 3,
                },
                {
                    "dataplane": "dp0",
                    "core_id": "1",
                    "average_series": [72.0, 20.0, 10.0],
                    "maximum_series": [100.0, 80.0, 60.0],
                    "average": 72.0,
                    "maximum": 100.0,
                    "utilization": 100.0,
                    "window_average": 34.0,
                    "window_peak": 100.0,
                    "seconds_at_or_above_90": 1,
                    "sample_count": 3,
                },
            ],
        )
        self.assertEqual(
            extract_live_percentages("", "", resource_monitor)[
                "resource_monitor_dp_cpu"
            ],
            [100.0],
        )

    def test_system_info_fields_are_normalized(self):
        system = """
<system>
  <hostname>fw-edge-a</hostname>
  <devicename>edge-a</devicename>
  <serial>fixture-serial</serial>
  <model>PA-VM</model>
  <sw-version>11.2.4</sw-version>
  <time>Thu Aug 27 14:03:02 2026</time>
  <uptime>0 days, 21:24:13</uptime>
</system>
""".strip()
        expected = {
            "hostname": "fw-edge-a",
            "device_name": "edge-a",
            "serial": "fixture-serial",
            "model": "PA-VM",
            "software_version": "11.2.4",
            "system_time": "Thu Aug 27 14:03:02 2026",
            "uptime": "0 days, 21:24:13",
        }
        samples = (
            f'<response status="success"><result>{system}</result></response>',
            f"<result>{system}</result>",
        )

        for sample in samples:
            with self.subTest(root=sample.split(">", 1)[0]):
                parsed = extract_system_info(sample)
                self.assertEqual(
                    {name: parsed[name] for name in expected},
                    expected,
                )
                self.assertNotIn("sw-version", parsed)


class PbpEvidenceParsingTests(unittest.TestCase):
    """Parsers for the configured thresholds, the latency and the threat logs."""

    def test_configured_thresholds_are_read_and_absent_ones_stay_none(self):
        settings = extract_pbp_settings(
            "<result><session>"
            "<packet-buffer-protection-enable>yes</packet-buffer-protection-enable>"
            "<packet-buffer-protection-alert>50</packet-buffer-protection-alert>"
            "<packet-buffer-protection-activate>80</packet-buffer-protection-activate>"
            "<packet-buffer-protection-latency-alert>50</packet-buffer-protection-latency-alert>"
            "<packet-buffer-protection-latency-activate>200</packet-buffer-protection-latency-activate>"
            "<packet-buffer-protection-latency-max-tolerate>500</packet-buffer-protection-latency-max-tolerate>"
            "<packet-buffer-protection-latency-block-countdown>500</packet-buffer-protection-latency-block-countdown>"
            "<dhcp-bcast-session-on>yes</dhcp-bcast-session-on>"
            "</session></result>"
        )

        self.assertEqual(settings["status"], "parsed")
        self.assertTrue(settings["enabled"])
        self.assertEqual(settings["alert_percent"], 50.0)
        self.assertEqual(settings["activate_percent"], 80.0)
        self.assertEqual(settings["latency_activate_ms"], 200.0)
        self.assertEqual(settings["latency_max_tolerate_ms"], 500.0)
        # A threshold left at its default is absent from the running config.
        partial = extract_pbp_settings("<result><session><packet-buffer-protection-enable>no</packet-buffer-protection-enable></session></result>")
        self.assertFalse(partial["enabled"])
        self.assertIsNone(partial["alert_percent"])
        self.assertEqual(extract_pbp_settings("not xml")["status"], "unparsed")
        self.assertEqual(extract_pbp_settings("<result/>")["status"], "unparsed")

    def test_buffer_latency_report_is_read_per_dataplane(self):
        latency = extract_buffer_latency(
            "<result><sw.comm.s1.dp0.packet-buffer-latency-report>"
            "<buffer-latency-enabled>True</buffer-latency-enabled>"
            "<latest>104</latest>"
            "<last-max><member>110</member><member>105</member></last-max>"
            "<last-avg><member>108</member><member>44</member></last-avg>"
            "</sw.comm.s1.dp0.packet-buffer-latency-report>"
            "<sw.comm.s1.dp1.packet-buffer-latency-report>"
            "<buffer-latency-enabled>True</buffer-latency-enabled>"
            "<latest>2</latest><last-max><member>3</member></last-max>"
            "<last-avg><member>1</member></last-avg>"
            "</sw.comm.s1.dp1.packet-buffer-latency-report></result>"
        )

        self.assertEqual(latency["status"], "parsed")
        self.assertEqual([dp["dataplane"] for dp in latency["dataplanes"]], ["s1.dp0", "s1.dp1"])
        self.assertEqual(latency["dataplanes"][0]["last_max_ms"], [110.0, 105.0])
        self.assertEqual(latency["latest_ms"], 104.0)
        self.assertEqual(latency["peak_ms"], 110.0)
        self.assertEqual(
            extract_buffer_latency("<result>Buffer latency measurement is disabled.</result>")["status"],
            "disabled",
        )
        self.assertEqual(extract_buffer_latency("<result/>")["status"], "unparsed")

    def test_pbp_threat_log_entries_keep_the_id_and_the_designated_source(self):
        entries = extract_pbp_threat_log_entries(
            "<result><job><status>FIN</status></job><log><logs count=\"1\">"
            "<entry logid=\"1\"><receive_time>2026/08/30 12:15:26</receive_time>"
            "<src>203.0.113.7</src><dst>0.0.0.0</dst><sport>0</sport><dport>0</dport>"
            "<proto>tcp</proto><app>not-applicable</app><from>LAN</from>"
            "<action>drop</action><sessionid>0</sessionid><repeatcnt>1</repeatcnt>"
            "<threatid>PBP Packet Drop</threatid><tid>8507</tid>"
            "<threat_name>PBP Packet Drop</threat_name></entry></logs></log></result>"
        )

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["threat_id"], 8507)
        self.assertEqual(entries[0]["threat_name"], "PBP Packet Drop")
        self.assertEqual(entries[0]["source_ip"], "203.0.113.7")
        self.assertEqual(entries[0]["from_zone"], "LAN")
        self.assertEqual(entries[0]["action"], "drop")
        self.assertEqual(extract_pbp_threat_log_entries("not xml"), [])

    def test_the_threat_query_window_follows_the_firewall_clock(self):
        self.assertEqual(
            firewall_clock_query_time("Sun Aug 30 12:05:20 CEST 2026"),
            "2026/08/30 12:04:20",
        )
        self.assertEqual(
            firewall_clock_query_time("Thu Aug 27 10:00:00 UTC 2026", margin_seconds=0),
            "2026/08/27 10:00:00",
        )
        self.assertIsNone(firewall_clock_query_time("garbage"))
        self.assertIsNone(firewall_clock_query_time(None))
        self.assertEqual(
            pbp_threat_log_query("2026/08/30 12:04:20"),
            "((threatid eq 8507) or (threatid eq 8508) or (threatid eq 8509))"
            " and (receive_time geq '2026/08/30 12:04:20')",
        )
        self.assertEqual(
            pbp_threat_log_query(None),
            "((threatid eq 8507) or (threatid eq 8508) or (threatid eq 8509))",
        )


if __name__ == "__main__":
    unittest.main()
