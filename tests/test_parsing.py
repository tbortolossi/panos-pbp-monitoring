import unittest

from pbp_monitoring.orchestrator import (
    TRIGGER_REGEX,
    annotate_large_sessions,
    extract_large_sessions,
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
