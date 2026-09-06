import unittest

from pbp_monitoring.orchestrator import (
    TRIGGER_REGEX,
    annotate_large_sessions,
    extract_congestion_log_entries,
    extract_global_counters_raw,
    extract_ha_state,
    extract_interface_counter_table,
    extract_interface_status,
    extract_large_sessions,
    extract_resource_monitor_history,
    extract_zone_protection,
    extract_live_percentages,
    extract_session_ids,
    large_session_command,
    parse_panos_time,
    summarize_large_sessions,
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
