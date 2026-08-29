import unittest

from pbp_monitoring.orchestrator import (
    TRIGGER_REGEX,
    extract_live_percentages,
    extract_session_ids,
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
