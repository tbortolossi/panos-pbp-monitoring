import unittest
from unittest.mock import patch

from pbp_monitoring import orchestrator

from pbp_monitoring.orchestrator import (
    ARP_ENTRIES_OMITTED_MARKER,
    TRIGGER_REGEX,
    _kv_lines,
    read_arp_response,
    annotate_large_sessions,
    extract_application_statistics,
    extract_arp_table_header,
    extract_chassis_status,
    extract_congestion_log_entries,
    extract_global_counters_raw,
    extract_ha_state,
    extract_inflight_monitoring,
    extract_interface_counter_table,
    extract_interface_status,
    extract_large_sessions,
    extract_pow_performance,
    extract_resource_monitor_history,
    extract_session_distribution,
    extract_zone_protection,
    extract_live_percentages,
    extract_session_ids,
    large_session_command,
    parse_panos_time,
    summarize_large_sessions,
    trim_arp_entries,
)


class ParsingTests(unittest.TestCase):
    def test_ingress_and_pbp_session_ids(self):
        ingress = """
TOP SESSIONS:SESS-ID PCT GRP-ID COUNT
38492 72% 1 156
SESSION DETAILS SESS-ID PROTO SZONE SRC SPORT DST DPORT
38492 6 trust 10.0.0.1 12345 10.0.0.2 443
"""
        pbp = """
38492 | trust | 4088 | 49 | Yes
172.16.1.1 | trust | 31 | 0 | No
"""
        self.assertEqual(extract_session_ids(ingress, pbp), [38492])

    def test_percentages(self):
        pbp = "Congestion: 12431/17203 (72%)"
        ingress = "USAGE - ATOMIC: 92% TOTAL: 93%"
        self.assertEqual(
            extract_live_percentages(pbp, ingress),
            {
                "packet_buffer_congestion": [72],
                "descriptor_atomic": [92],
                "descriptor_total": [93],
            },
        )

    def test_default_system_and_threat_triggers(self):
        for message in (
            "Packet buffer congestion is 50000/86016 (58%)",
            "PBP Packet Drop(8507)",
            "PBP Session Discarded(8508)",
            "PBP IP Blocked(8509)",
        ):
            self.assertIsNotNone(TRIGGER_REGEX.search(message))


if __name__ == "__main__":
    unittest.main()


class LargeSessionTests(unittest.TestCase):
    """An elephant session is found by volume and age, never by a traffic log."""

    RESULT = (
        "<result>"
        "<entry><source>198.51.100.20</source><dst>203.0.113.30</dst>"
        "<sport>44321</sport><dport>443</dport><proto>6</proto>"
        "<from>LAN</from><to>INTERNET</to>"
        "<start-time>Thu Aug 27 09:00:00 2026</start-time><state>ACTIVE</state>"
        "<total-byte-count>4500000000</total-byte-count><idx>5258</idx>"
        "<application>ssl</application>"
        "<ingress>ethernet1/1</ingress><egress>ethernet1/2</egress></entry>"
        "<entry><source>198.51.100.21</source><dst>203.0.113.31</dst>"
        "<sport>51002</sport><dport>873</dport><proto>6</proto>"
        "<from>LAN</from><to>INTERNET</to>"
        "<start-time>Thu Aug 27 08:00:00 2026</start-time><state>ACTIVE</state>"
        "<total-byte-count>9000000000</total-byte-count><idx>5259</idx>"
        "<application>rsync</application>"
        "<ingress>ethernet1/1</ingress><egress>ethernet1/2</egress></entry>"
        "</result>"
    )
    CLOCK = "Thu Aug 27 10:00:00 CEST 2026"

    def test_both_thresholds_are_sent_to_the_firewall(self):
        self.assertEqual(
            large_session_command(1048576, 600),
            "<show><session><all><filter><min-kb>1048576</min-kb>"
            "<min-age>600</min-age></filter></all></session></show>",
        )

    def test_an_age_of_zero_leaves_the_filter_out_of_the_command(self):
        self.assertEqual(
            large_session_command(1048576, 0),
            "<show><session><all><filter><min-kb>1048576</min-kb>"
            "</filter></all></session></show>",
        )

    def test_sessions_are_ranked_by_cumulative_volume(self):
        parsed = extract_large_sessions(self.RESULT)

        self.assertEqual(parsed["status"], "collected")
        self.assertEqual(parsed["session_count"], 2)
        self.assertFalse(parsed["truncated"])
        self.assertEqual(
            [session["session_id"] for session in parsed["sessions"]], [5259, 5258]
        )
        self.assertEqual(parsed["sessions"][0]["application"], "rsync")
        self.assertEqual(parsed["sessions"][0]["ingress_interface"], "ethernet1/1")

    def test_more_sessions_than_the_cap_are_reported_as_truncated(self):
        parsed = extract_large_sessions(self.RESULT, limit=1)

        self.assertTrue(parsed["truncated"])
        self.assertEqual(parsed["session_count"], 2)
        self.assertEqual(len(parsed["sessions"]), 1)

    def test_unparsable_output_yields_no_session_instead_of_raising(self):
        parsed = extract_large_sessions("not xml at all")

        self.assertEqual(parsed["status"], "parse_failed")
        self.assertEqual(parsed["sessions"], [])

    def test_session_age_is_measured_against_the_firewall_clock(self):
        sessions = extract_large_sessions(self.RESULT)["sessions"]

        annotated = annotate_large_sessions(
            sessions, {}, 100.0, parse_panos_time(self.CLOCK)
        )

        by_id = {session["session_id"]: session for session in annotated}
        self.assertEqual(by_id[5258]["duration_seconds"], 3600.0)
        self.assertEqual(by_id[5259]["duration_seconds"], 7200.0)
        # 4.5 GB spread over one hour is ten megabits per second.
        self.assertEqual(by_id[5258]["average_bits_per_second"], 10_000_000.0)
        self.assertEqual(by_id[5258]["rate_status"], "baseline")

    def test_a_session_started_after_the_clock_reports_no_age(self):
        sessions = extract_large_sessions(self.RESULT)["sessions"]

        annotated = annotate_large_sessions(
            sessions, {}, 100.0, parse_panos_time("Thu Aug 27 07:00:00 CEST 2026")
        )

        self.assertTrue(
            all(session["duration_seconds"] is None for session in annotated)
        )

    def test_two_batches_derive_the_current_bandwidth(self):
        samples: dict = {}
        device_time = parse_panos_time(self.CLOCK)
        annotate_large_sessions(
            extract_large_sessions(self.RESULT)["sessions"], samples, 100.0, device_time
        )
        later = self.RESULT.replace(
            "<total-byte-count>4500000000</total-byte-count>",
            "<total-byte-count>4506250000</total-byte-count>",
        )

        annotated = annotate_large_sessions(
            extract_large_sessions(later)["sessions"], samples, 105.0, device_time
        )

        session = next(item for item in annotated if item["session_id"] == 5258)
        self.assertEqual(session["rate_status"], "calculated")
        self.assertEqual(session["delta_bytes"], 6_250_000)
        self.assertEqual(session["sample_interval_seconds"], 5.0)
        # 6.25 MB in five seconds is ten megabits per second.
        self.assertEqual(session["bits_per_second"], 10_000_000.0)

    def test_a_recycled_session_index_never_inherits_a_bandwidth(self):
        samples: dict = {}
        device_time = parse_panos_time(self.CLOCK)
        annotate_large_sessions(
            extract_large_sessions(self.RESULT)["sessions"], samples, 100.0, device_time
        )
        reused = self.RESULT.replace(
            "<start-time>Thu Aug 27 09:00:00 2026</start-time>",
            "<start-time>Thu Aug 27 09:30:00 2026</start-time>",
        )

        annotated = annotate_large_sessions(
            extract_large_sessions(reused)["sessions"], samples, 105.0, device_time
        )

        session = next(item for item in annotated if item["session_id"] == 5258)
        self.assertEqual(session["rate_status"], "session_reused")
        self.assertNotIn("bits_per_second", session)

    def test_a_session_that_left_the_listing_stops_being_sampled(self):
        samples: dict = {}
        device_time = parse_panos_time(self.CLOCK)
        annotate_large_sessions(
            extract_large_sessions(self.RESULT)["sessions"], samples, 100.0, device_time
        )
        self.assertEqual(sorted(samples), ["5258", "5259"])

        single = extract_large_sessions(self.RESULT)["sessions"][:1]
        annotate_large_sessions(single, samples, 105.0, device_time)

        self.assertEqual(sorted(samples), ["5259"])

    def test_a_failed_command_does_not_discard_the_batch(self):
        summary = summarize_large_sessions(
            {"ok": False, "result": "", "error": "timeout"},
            1048576,
            {},
            100.0,
            self.CLOCK,
            600,
        )

        self.assertEqual(summary["status"], "lookup_failed")
        self.assertEqual(summary["sessions"], [])
        self.assertEqual(summary["min_age_seconds"], 600)

    def test_a_zero_threshold_reports_the_collection_as_disabled(self):
        summary = summarize_large_sessions(None, 0, {}, 100.0, self.CLOCK, 600)

        self.assertEqual(summary["status"], "disabled")
        self.assertEqual(summary["sessions"], [])


class TsfCorpusEvidenceParsingTests(unittest.TestCase):
    """The once-per-incident reads the TSF corpus showed were missing.

    Every fixture is the anonymized shape the lab PA-440 (PAN-OS 12.2.2)
    returned when the operational XML was validated read-only.
    """

    RAW_COUNTERS = (
        "<result><dp>dp0</dp><global><t>174633</t><counters>"
        "<entry><name>pkt_recv</name><value>498397976</value><rate>218</rate>"
        "<severity>info</severity><category>packet</category>"
        "<aspect>pktproc</aspect><desc>Packets received</desc><id>17</id></entry>"
        "<entry><name>flow_dos_pbp_block_host</name><value>14</value>"
        "<rate>0</rate><severity>drop</severity><category>flow</category>"
        "<aspect>dos</aspect><desc>PBP blocked hosts</desc><id>801</id></entry>"
        "<entry><name>never_moved</name><value>0</value><rate>0</rate>"
        "<severity>info</severity><category>packet</category>"
        "<aspect>pktproc</aspect><desc>Idle</desc><id>900</id></entry>"
        "</counters></global></result>"
    )

    def test_a_counter_too_slow_for_a_delta_window_survives_the_raw_read(self):
        parsed = extract_global_counters_raw(self.RAW_COUNTERS)

        self.assertTrue(parsed["parsed"])
        # Fourteen block-host events since boot at a rate of zero: no delta
        # window would ever have shown it, and it is the whole finding.
        self.assertEqual(parsed["counters"]["flow_dos_pbp_block_host"]["value"], 14)
        self.assertEqual(parsed["counters"]["pkt_recv"]["rate"], 218)
        self.assertEqual(parsed["dataplanes"], ["dp0"])
        self.assertEqual(parsed["counter_count"], 3)

    def test_a_counter_that_never_moved_is_not_persisted(self):
        parsed = extract_global_counters_raw(self.RAW_COUNTERS)

        self.assertNotIn("never_moved", parsed["counters"])

    def test_an_unparsable_counter_read_is_reported_not_raised(self):
        self.assertEqual(
            extract_global_counters_raw("not xml at all")["counters"], {}
        )

    HISTORY = (
        "<result><resource-monitor><data-processors><dp0>"
        "<hour><cpu-load-maximum>"
        "<entry><coreid>1</coreid><value>79,38,48,6</value></entry>"
        "</cpu-load-maximum><resource-utilization>"
        "<entry><name>packet buffer (average)</name>"
        "<value>62,58,40,12</value></entry>"
        "<entry><name>packet buffer (maximum)</name>"
        "<value>88,71,44,14</value></entry>"
        "</resource-utilization></hour>"
        "<week><resource-utilization>"
        "<entry><name>packet buffer (maximum)</name>"
        "<value>88,60,20</value></entry>"
        "</resource-utilization></week>"
        "</dp0></data-processors></resource-monitor></result>"
    )

    def test_the_history_keeps_the_newest_first_series_of_each_window(self):
        parsed = extract_resource_monitor_history(self.HISTORY)

        self.assertTrue(parsed["parsed"])
        windows = {window["window"]: window for window in parsed["windows"]}
        self.assertEqual(sorted(windows), ["hour", "week"])
        hour = windows["hour"]["metrics"]["packet_buffer"]
        self.assertEqual(hour["maximum_series"], [88.0, 71.0, 44.0, 14.0])
        self.assertEqual(hour["maximum"]["latest"], 88.0)
        self.assertEqual(hour["maximum"]["oldest"], 14.0)
        self.assertEqual(hour["maximum"]["peak"], 88.0)
        self.assertEqual(hour["average"]["latest"], 62.0)
        self.assertEqual(windows["hour"]["cpu"]["maximum_peak"], 79.0)

    def test_a_text_only_history_is_reported_as_unparsed_not_guessed(self):
        parsed = extract_resource_monitor_history(
            "<result>Resource monitoring sampling data (per hour)</result>"
        )

        self.assertFalse(parsed["parsed"])
        self.assertEqual(parsed["windows"], [])

    ZONE_PROTECTION = (
        "<result><entry><dp>dp0</dp><entries>"
        "<entry><zone>INTERNET</zone><vsys>vsys1</vsys>"
        "<profile>Default_Zone_Protection</profile>"
        "<tcp-syn-cookie>False</tcp-syn-cookie><tcp>False</tcp><udp>False</udp>"
        "<icmp>False</icmp><ip>False</ip><icmp6>False</icmp6>"
        "<sctp_init>False</sctp_init><pbp-drop>3984</pbp-drop>"
        "<pbp-block-host>2</pbp-block-host></entry>"
        "<entry><zone>LAN</zone><vsys>vsys1</vsys><profile>lan-zp</profile>"
        "<tcp-syn-cookie>True</tcp-syn-cookie><tcp>True</tcp><udp>False</udp>"
        "<icmp>False</icmp><ip>False</ip><icmp6>False</icmp6>"
        "<sctp_init>False</sctp_init><pbp-drop>0</pbp-drop></entry>"
        "</entries></entry></result>"
    )

    def test_a_zone_with_every_flood_type_off_reads_as_unprotected(self):
        parsed = extract_zone_protection(self.ZONE_PROTECTION)

        self.assertTrue(parsed["parsed"])
        internet = parsed["zones"][0]
        self.assertEqual(internet["zone"], "INTERNET")
        self.assertIs(internet["flood_protection_enabled"], False)
        self.assertEqual(internet["pbp_drop"], 3984)
        self.assertEqual(internet["pbp_counters"]["pbp_block_host"], 2)
        self.assertEqual(internet["profile"], "Default_Zone_Protection")

    def test_a_zone_with_one_flood_type_on_reads_as_protected(self):
        parsed = extract_zone_protection(self.ZONE_PROTECTION)
        lan = next(zone for zone in parsed["zones"] if zone["zone"] == "LAN")

        self.assertIs(lan["flood_protection_enabled"], True)

    def test_a_chassis_sums_the_same_zone_across_its_dataplanes(self):
        two_planes = self.ZONE_PROTECTION.replace(
            "</entries></entry></result>",
            "</entries></entry>"
            "<entry><dp>s1dp1</dp><entries>"
            "<entry><zone>INTERNET</zone><vsys>vsys1</vsys>"
            "<profile>Default_Zone_Protection</profile>"
            "<tcp>True</tcp><pbp-drop>16</pbp-drop></entry>"
            "</entries></entry></result>",
        )

        parsed = extract_zone_protection(two_planes)
        internet = next(
            zone for zone in parsed["zones"] if zone["zone"] == "INTERNET"
        )

        self.assertEqual(internet["pbp_drop"], 4000)
        self.assertEqual(internet["dataplanes"], ["dp0", "s1dp1"])
        # Protected on one plane is protected: the flags are OR-ed so an
        # unprotected verdict can never be pronounced on a covered zone.
        self.assertIs(internet["flood_protection_enabled"], True)

    def test_a_standalone_firewall_reports_ha_as_disabled(self):
        parsed = extract_ha_state(
            "<result><enabled>no</enabled><group><local-info>"
            "<ha1-encrypt-imported>no</ha1-encrypt-imported>"
            "</local-info></group></result>"
        )

        self.assertTrue(parsed["parsed"])
        self.assertIs(parsed["enabled"], False)
        self.assertIsNone(parsed["passive"])

    def test_a_passive_unit_is_named_and_its_peer_identity_is_not_kept(self):
        parsed = extract_ha_state(
            "<result><enabled>yes</enabled><group>"
            "<local-info><state>passive</state><state-duration>42</state-duration>"
            "<mode>Active-Passive</mode><priority>100</priority></local-info>"
            "<peer-info><state>active</state><conn-status>up</conn-status>"
            "<serial>012345678901</serial></peer-info>"
            "<running-sync>synchronized</running-sync></group></result>"
        )

        self.assertIs(parsed["enabled"], True)
        self.assertIs(parsed["passive"], True)
        self.assertEqual(parsed["local_state_duration_seconds"], 42)
        self.assertEqual(parsed["peer_state"], "active")
        self.assertEqual(parsed["running_sync"], "synchronized")
        self.assertNotIn("peer_serial", parsed)

    def test_a_disabled_on_box_ingress_collection_is_read_with_its_settings(self):
        parsed = extract_inflight_monitoring(
            "<result>cfg.session.erspan: False\n"
            "cfg.session.inflight_monitoring: False\n"
            "cfg.session.ingress_backlogs_duration: 3\n"
            "cfg.session.ingress_backlogs_threshold: 80\n"
            "cfg.session.ingress_backlogs_trigger: False\n</result>"
        )

        self.assertTrue(parsed["parsed"])
        self.assertIs(parsed["enabled"], False)
        self.assertEqual(parsed["duration_seconds"], 3)
        self.assertEqual(parsed["threshold_percent"], 80)
        self.assertIs(parsed["trigger_pending"], False)

    def test_an_enabled_on_box_ingress_collection_is_read_as_enabled(self):
        parsed = extract_inflight_monitoring(
            "cfg.session.inflight_monitoring: True\n"
            "cfg.session.ingress_backlogs_duration: 5\n"
            "cfg.session.ingress_backlogs_threshold: 60\n"
            "cfg.session.ingress_backlogs_trigger: True\n"
        )

        self.assertIs(parsed["enabled"], True)
        self.assertEqual(parsed["duration_seconds"], 5)
        self.assertEqual(parsed["threshold_percent"], 60)
        self.assertIs(parsed["trigger_pending"], True)

    def test_no_matches_leaves_the_on_box_collection_state_unknown(self):
        parsed = extract_inflight_monitoring("<result>NO_MATCHES</result>")

        self.assertFalse(parsed["parsed"])
        self.assertIsNone(parsed["enabled"])
        self.assertIsNone(parsed["duration_seconds"])
        self.assertIsNone(parsed["threshold_percent"])
        self.assertIsNone(parsed["trigger_pending"])

    def test_a_release_without_the_on_box_nodes_is_still_monitored(self):
        # An empty answer, a failed command stored as an empty string and a
        # release that exposes only some of the nodes must each parse into a
        # partial state rather than raise: the incident goes on being
        # monitored either way.
        for output in ("", "<result></result>", "not xml at all"):
            with self.subTest(output=output):
                parsed = extract_inflight_monitoring(output)

                self.assertFalse(parsed["parsed"])
                self.assertIsNone(parsed["enabled"])
        partial = extract_inflight_monitoring(
            "<result>cfg.session.inflight_monitoring: True</result>"
        )

        self.assertIs(partial["enabled"], True)
        self.assertIsNone(partial["threshold_percent"])

    def test_the_on_box_collection_state_carries_nothing_identifying(self):
        # The whole point of reading `cfg.session.*` is four flags and
        # numbers; the surrounding nodes of a real firewall must not be kept,
        # so an anonymized export cannot leak through this field.
        parsed = extract_inflight_monitoring(
            "<result>cfg.session.erspan: False\n"
            "cfg.session.inflight_monitoring: False\n"
            "cfg.session.hostname: customer-edge-fw\n"
            "cfg.session.mgmt-ip: 203.0.113.7\n</result>"
        )

        self.assertEqual(
            set(parsed),
            {
                "parsed",
                "status",
                "enabled",
                "duration_seconds",
                "threshold_percent",
                "trigger_pending",
            },
        )
        self.assertEqual(parsed["status"], "read")
        for name, value in parsed.items():
            if name == "status":
                continue
            self.assertIsInstance(value, (bool, int, type(None)))

    def test_a_hexadecimal_state_value_is_read_as_the_number_it_is(self):
        # `show system state` prints some nodes in hexadecimal. Reading only
        # the decimal form would leave the value None, and every renderer
        # would then substitute the PAN-OS default and present it as the
        # firewall's own setting.
        parsed = extract_inflight_monitoring(
            "<result>cfg.session.inflight_monitoring: True\n"
            "cfg.session.ingress_backlogs_threshold: 0x3c\n"
            "cfg.session.ingress_backlogs_duration: 0x5\n</result>"
        )

        self.assertEqual(parsed["threshold_percent"], 60)
        self.assertEqual(parsed["duration_seconds"], 5)

    def test_a_release_without_the_feature_is_told_from_a_failed_read(self):
        # NO_MATCHES is an answer: the release has no such setting, so the
        # tech support file is known to hold no pan_ingress_backlogs.log. An
        # empty body is a read that did not happen and settles nothing.
        absent = extract_inflight_monitoring("<result>NO_MATCHES</result>")
        unrelated = extract_inflight_monitoring(
            "<result>cfg.session.erspan: False</result>"
        )
        not_collected = extract_inflight_monitoring("")

        self.assertEqual(absent["status"], "absent")
        self.assertEqual(unrelated["status"], "absent")
        self.assertEqual(not_collected["status"], "not_collected")
        for parsed in (absent, unrelated, not_collected):
            self.assertIsNone(parsed["enabled"])

    def test_the_whole_interface_counter_table_is_parsed_per_port(self):
        parsed = extract_interface_counter_table(
            "<result><hw>"
            "<entry><name>ethernet1/1</name><port>"
            "<rx-broadcast>645165</rx-broadcast><rx-discards>3</rx-discards>"
            "</port></entry>"
            "<entry><name>ae1</name><port>"
            "<rx-multicast>7</rx-multicast></port></entry>"
            "</hw></result>"
        )

        self.assertEqual(sorted(parsed), ["ae1", "ethernet1/1"])
        self.assertEqual(parsed["ethernet1/1"]["counters"]["rx_broadcast"], 645165)
        self.assertEqual(parsed["ae1"]["counters"]["rx_multicast"], 7)

    def test_the_interface_map_keeps_the_zone_and_drops_the_mac(self):
        parsed = extract_interface_status(
            "<result><hw>"
            "<entry><name>ethernet1/1</name><mac>00:53:00:00:00:01</mac>"
            "<speed>1000</speed><state>up</state></entry>"
            "</hw><ifnet>"
            "<entry><name>ethernet1/1</name><zone>INTERNET</zone><vsys>1</vsys>"
            "<tag>0</tag><ip>198.51.100.1/24</ip></entry>"
            "<entry><name>ethernet1/2</name><zone>LAN</zone><ip>N/A</ip></entry>"
            "</ifnet></result>"
        )

        self.assertEqual(parsed["ethernet1/1"]["zone"], "INTERNET")
        self.assertEqual(parsed["ethernet1/1"]["speed"], "1000")
        self.assertEqual(parsed["ethernet1/1"]["state"], "up")
        self.assertNotIn("mac", parsed["ethernet1/1"])
        # `N/A` is PAN-OS saying nothing, not an address.
        self.assertNotIn("ip", parsed["ethernet1/2"])

    def test_a_congestion_log_line_yields_its_occupancy_and_threshold(self):
        entries = extract_congestion_log_entries(
            "<result><job><status>FIN</status></job><log><logs>"
            "<entry><time_generated>2026/08/30 03:00:34</time_generated>"
            "<receive_time>2026/08/30 03:00:34</receive_time>"
            "<severity>informational</severity>"
            "<opaque>Packet buffer congestion (utilization) is 4170/97280 (72%)"
            "(alert threshold is 50%).</opaque></entry>"
            "<entry><opaque>Some other system message</opaque></entry>"
            "</logs></log></result>"
        )

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["used"], 4170)
        self.assertEqual(entries[0]["total"], 97280)
        self.assertEqual(entries[0]["percent"], 72.0)
        self.assertEqual(entries[0]["alert_threshold_percent"], 50.0)
        self.assertEqual(entries[0]["measure"], "utilization")
        self.assertEqual(entries[0]["time_generated"], "2026/08/30 03:00:34")




# The Tier 2 device reads, shaped as the lab firewalls and the anonymized TAC
# tech support files answer them. Every address and MAC below is
# documentation-range; the chassis and dataplane names are the hardware's own.
ARP_TABLE_RESULT = """<result>
  <dp>dp0</dp>
  <timeout>1800</timeout>
  <total>2</total>
  <entries>
    <entry>
      <interface>ethernet1/1</interface>
      <ip>192.0.2.10</ip>
      <mac>00:53:00:11:22:33</mac>
      <port>ethernet1/1</port>
      <status>  c  </status>
      <ttl>1670</ttl>
    </entry>
    <entry>
      <interface>ethernet1/2</interface>
      <ip>198.51.100.7</ip>
      <mac>00:53:00:44:55:66</mac>
      <port>ethernet1/2</port>
      <status>  c  </status>
      <ttl>90</ttl>
    </entry>
  </entries>
  <max>3000</max>
</result>"""

#: Two dataplanes, the first holding no entry at all. Each block is a replica
#: of the same table, so the occupancy is the fullest block's and never their
#: sum, and an empty `<entries/>` must not swallow the block behind it.
ARP_TABLE_MULTI_DP_RESULT = """<result>
  <dataplane>
    <dp>s1dp0</dp>
    <timeout>1800</timeout>
    <total>0</total>
    <entries/>
    <max>128000</max>
  </dataplane>
  <dataplane>
    <dp>s1dp1</dp>
    <timeout>1800</timeout>
    <total>120000</total>
    <entries>
      <entry><ip>192.0.2.10</ip><mac>00:53:00:11:22:33</mac></entry>
    </entries>
    <max>128000</max>
  </dataplane>
</result>"""

APPLICATION_STATISTICS_RESULT = """<result>Vsys: 1
Number of apps: 4
App (report-as) sessions   packets    bytes        app changed threats
--------------- ---------- ---------- ------------ ----------- -------
undecided       0          0          0            0           2
ssl             500        239658     247864083    0           124
active-directory-base 25    9948       6525908      35          0
web-browsing    120        4501       9930221      12          3
--------------- ---------- ---------- ------------ ----------- -------
Total           645        254107     264320212    47          129
</result>"""

SESSION_DISTRIBUTION_RESULT = """<result>
DP         Active               Dispatched           Dispatched/sec
--------------------------------------------------------------------------------
s1dp0      264453               89997427             1189
s1dp1      212443               90063088             1190
</result>"""

#: A PA-5260 has four dataplanes and no slots: its rows are `dp0` to `dp3`.
SESSION_DISTRIBUTION_SLOTLESS_RESULT = """<result>
DP         Active               Dispatched           Dispatched/sec
--------------------------------------------------------------------------------
dp0        200000               89997427             1189
dp1        0                    90063088             1190
</result>"""

CHASSIS_STATUS_RESULT = """<result>
Slot  Component        Card Status         Config Status Disabled
1     PA-7000-100G-NPC-A Up                  Success
2     PA-7000-DPC-A    Powered Off         Config Failed
3     empty
6     PA-7080-SMC-B    Up                  Success

================================================================================
Chassis autocommit ready : True
Inserted slots           : 1 2 6
Powered slots            : 1 2 6
Traffic enabled slots    : 1
</result>"""

POW_PERFORMANCE_RESULT = """<result>
DP s1dp0:

group                                 max-us   avg-us        count     total-us
flow_fastpath                          14478     74.2      7665961    569011460
flow_slowpath                            222     82.2       656571     53976194

func                                  max-us   avg-us        count     total-us
pbp_buf_latency                          670      2.4       161525       393629
pkt_rx_tx_latency                      43119    125.0      4688049    586312319

pbp_buf_latency (func)
col    avg-ticks   avg-us        count     total-us
 11         3457        2       113315       244850
 20      1073522      670            1          670

mi_proxy (func)
col    avg-ticks   avg-us        count     total-us
 13        15446        9         2131        20572

DP s1dp1:

func                                  max-us   avg-us        count     total-us
pbp_buf_latency                           22      2.8       161221       456326
</result>"""


class KeyValueLineTests(unittest.TestCase):
    """One reader for the labelled values half the text commands answer with."""

    def test_separators_and_spacing_are_not_read_as_labels(self):
        text = (
            "Slot  Component\n"
            "--------------------------------------------------\n"
            "================================================\n"
            "\n"
            "Traffic enabled slots    : 1 2\n"
            "Chassis autocommit ready : True\n"
            "TCP: 90 secs, UDP: 60 secs\n"
        )

        self.assertEqual(
            list(_kv_lines(text)),
            [
                ("traffic enabled slots", "1 2"),
                ("chassis autocommit ready", "True"),
                ("tcp", "90 secs, UDP: 60 secs"),
            ],
        )


class ArpTableHeaderTests(unittest.TestCase):
    """`show arp all` is read for its header and never for its table."""

    def test_the_header_gives_the_occupancy_of_the_table(self):
        parsed = extract_arp_table_header(ARP_TABLE_RESULT)

        self.assertTrue(parsed["parsed"])
        self.assertEqual(parsed["entries"], 2)
        self.assertEqual(parsed["maximum_entries"], 3000)
        self.assertEqual(parsed["timeout_seconds"], 1800)
        self.assertEqual(parsed["utilization_percent"], 0.1)
        self.assertEqual(parsed["dataplane"], "dp0")

    def test_the_occupancy_of_a_chassis_is_the_fullest_dataplane_not_the_sum(self):
        # Each block is a replica of the same table. Adding them would report
        # 120000 of 256000 entries on a firewall whose table is 94% full.
        parsed = extract_arp_table_header(ARP_TABLE_MULTI_DP_RESULT)

        self.assertEqual(parsed["entries"], 120000)
        self.assertEqual(parsed["maximum_entries"], 128000)
        self.assertEqual(parsed["utilization_percent"], 93.8)
        self.assertEqual(parsed["dataplane"], "s1dp1")
        self.assertEqual([row["dataplane"] for row in parsed["dataplanes"]], ["s1dp0", "s1dp1"])

    def test_the_stored_answer_keeps_the_header_and_drops_every_address(self):
        stored = trim_arp_entries(
            {
                "ok": True,
                "result": ARP_TABLE_RESULT,
                "raw_response": f"<response status='success'>{ARP_TABLE_RESULT}</response>",
            }
        )

        for value in (stored["result"], stored["raw_response"]):
            self.assertNotIn("192.0.2.10", value)
            self.assertNotIn("00:53:00:11:22:33", value)
            self.assertIn("<total>2</total>", value)
            self.assertIn("removed by the collector", value)
        # A replayed capture must parse to what the live read parsed, so the
        # trimming may never cost the header the parser reads.
        self.assertEqual(
            extract_arp_table_header(stored["result"]),
            extract_arp_table_header(ARP_TABLE_RESULT),
        )

    def test_an_empty_entries_element_does_not_swallow_the_next_block(self):
        stored = trim_arp_entries({"result": ARP_TABLE_MULTI_DP_RESULT})

        self.assertEqual(
            extract_arp_table_header(stored["result"]),
            extract_arp_table_header(ARP_TABLE_MULTI_DP_RESULT),
        )
        self.assertNotIn("192.0.2.10", stored["result"])

    def test_an_empty_or_rejected_answer_is_not_an_empty_table(self):
        for output in ("", "<result />"):
            parsed = extract_arp_table_header(output)
            self.assertFalse(parsed["parsed"])
            self.assertIsNone(parsed["entries"])


class ArpStreamingReadTests(unittest.TestCase):
    """The table is dropped as it arrives, not after it has been read."""

    class _Body:
        def __init__(self, payload: bytes, chunk: int = 64):
            self._payload = payload
            self._chunk = chunk
            self.largest_read = 0

        def read(self, size: int) -> bytes:
            self.largest_read = max(self.largest_read, size)
            head, self._payload = self._payload[:size], self._payload[size:]
            return head

    def _envelope(self, entries: int) -> bytes:
        rows = "".join(
            "<entry><interface>ethernet1/1</interface>"
            f"<ip>192.0.2.{index % 250}</ip>"
            "<mac>00:53:00:11:22:33</mac><ttl>1670</ttl></entry>"
            for index in range(entries)
        )
        return (
            '<response status="success"><result><dp>dp0</dp>'
            f"<timeout>1800</timeout><total>{entries}</total>"
            f"<entries>{rows}</entries><max>128000</max>"
            "</result></response>"
        ).encode("utf-8")

    def test_the_header_survives_and_no_address_is_ever_held(self):
        body = self._Body(self._envelope(500), chunk=61)

        text = read_arp_response(body)

        self.assertIn("<total>500</total>", text)
        self.assertIn("<max>128000</max>", text)
        self.assertIn(ARP_ENTRIES_OMITTED_MARKER, text)
        self.assertNotIn("192.0.2.", text)
        self.assertNotIn("00:53:00:11:22:33", text)
        # A tag split across two chunks is still a tag.
        self.assertEqual(extract_arp_table_header(text)["entries"], 500)

    def test_a_table_larger_than_the_transfer_cap_is_refused(self):
        class _Endless:
            def read(self, size: int) -> bytes:
                return b"<entry>x</entry>" * (size // 16)

        with patch.object(orchestrator, "ARP_TRANSFER_LIMIT_BYTES", 64 * 1024):
            with self.assertRaises(ValueError):
                read_arp_response(_Endless())


class ApplicationStatisticsTests(unittest.TestCase):
    def test_the_table_is_ranked_and_bounded(self):
        parsed = extract_application_statistics(APPLICATION_STATISTICS_RESULT)

        self.assertTrue(parsed["parsed"])
        self.assertEqual(parsed["reported_application_count"], 4)
        self.assertEqual(parsed["totals"]["bytes"], 264320212)
        self.assertEqual(parsed["top_by_bytes"][0]["application"], "ssl")
        # An application name wider than its column keeps its counters.
        names = [entry["application"] for entry in parsed["top_by_bytes"]]
        self.assertIn("active-directory-base", names)
        # `Total` is the table's own summary line, never an application, and
        # an application that carried nothing is not ranked as if it had.
        self.assertNotIn("Total", names)
        self.assertNotIn("undecided", names)

    def test_an_empty_answer_reports_nothing_collected(self):
        parsed = extract_application_statistics("<result />")

        self.assertFalse(parsed["parsed"])
        self.assertEqual(parsed["top_by_bytes"], [])


class SessionDistributionTests(unittest.TestCase):
    def test_the_per_dataplane_counts_and_the_imbalance(self):
        parsed = extract_session_distribution(SESSION_DISTRIBUTION_RESULT)

        self.assertTrue(parsed["parsed"])
        self.assertEqual(parsed["dataplane_count"], 2)
        self.assertEqual(parsed["busiest"], "s1dp0")
        self.assertEqual(parsed["busiest_active"], 264453)
        self.assertEqual(parsed["median_active"], 212443)
        self.assertEqual(parsed["imbalance_ratio"], 1.24)
        self.assertEqual(parsed["dataplanes"][1]["dispatched_per_second"], 1190)

    def test_a_platform_without_slots_names_its_dataplanes_dp0_and_dp1(self):
        # A PA-5260 and a PA-5450 have several dataplanes and no chassis: a
        # pattern requiring the slot prefix reads nothing at all on them.
        parsed = extract_session_distribution(SESSION_DISTRIBUTION_SLOTLESS_RESULT)

        self.assertEqual([row["dataplane"] for row in parsed["dataplanes"]], ["dp0", "dp1"])
        self.assertEqual(parsed["busiest"], "dp0")
        # Idle peers: the ratio does not exist, and the median is what says so.
        self.assertEqual(parsed["median_active"], 0)
        self.assertIsNone(parsed["imbalance_ratio"])

    def test_a_single_dataplane_answer_carries_no_distribution(self):
        # A PA-VM answers the command with an empty result, a PA-440 refuses
        # the node: neither is a table, and neither may read as one.
        for output in ("<result />", ""):
            parsed = extract_session_distribution(output)
            self.assertFalse(parsed["parsed"])
            self.assertEqual(parsed["dataplanes"], [])


class ChassisStatusTests(unittest.TestCase):
    def test_a_multi_word_status_is_one_status(self):
        parsed = extract_chassis_status(CHASSIS_STATUS_RESULT)

        self.assertTrue(parsed["parsed"])
        slots = {slot["slot"]: slot for slot in parsed["slots"]}
        self.assertEqual(slots[1]["component"], "PA-7000-100G-NPC-A")
        self.assertEqual(slots[1]["card_status"], "Up")
        # Split on whitespace, `Powered Off  Config Failed` reads as
        # `Powered` / `Off`, which is a status no firewall ever printed.
        self.assertEqual(slots[2]["card_status"], "Powered Off")
        self.assertEqual(slots[2]["config_status"], "Config Failed")
        self.assertIsNone(slots[3]["component"])
        self.assertEqual(parsed["traffic_enabled_slots"], [1])

    def test_a_platform_without_a_chassis_parses_to_nothing(self):
        parsed = extract_chassis_status("<result />")

        self.assertFalse(parsed["parsed"])
        self.assertEqual(parsed["slots"], [])


class PowPerformanceTests(unittest.TestCase):
    def test_the_named_rows_and_the_buffer_wait_histogram(self):
        parsed = extract_pow_performance(POW_PERFORMANCE_RESULT)

        self.assertTrue(parsed["parsed"])
        self.assertEqual(
            [entry["dataplane"] for entry in parsed["dataplanes"]],
            ["s1dp0", "s1dp1"],
        )
        first = parsed["dataplanes"][0]
        self.assertEqual(first["functions"]["pbp_buf_latency"]["max_us"], 670)
        self.assertEqual(first["functions"]["flow_slowpath"]["avg_us"], 82.2)
        # Only the packet-buffer histogram is kept, and its buckets are the
        # measurement, not the bucket numbers PAN-OS indexes them by.
        self.assertEqual(
            first["latency_histogram"],
            [{"avg_us": 2.0, "count": 113315}, {"avg_us": 670.0, "count": 1}],
        )
        self.assertEqual(parsed["peak_pbp_buffer_latency_us"], 670)
        self.assertEqual(parsed["peak_pbp_buffer_latency_dataplane"], "s1dp0")

    def test_a_release_that_returns_nothing_parses_to_nothing(self):
        for output in ("", "<result />"):
            parsed = extract_pow_performance(output)
            self.assertFalse(parsed["parsed"])
            self.assertIsNone(parsed["peak_pbp_buffer_latency_us"])
