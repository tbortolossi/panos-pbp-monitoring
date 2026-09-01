"""The documentation screenshots must never be able to carry real data.

These tests exercise the generator without a browser: they build the fictitious
deployment, serve it, and inspect the HTML that would be handed to Chromium.
Rendering itself is not tested, because a headless browser is neither available
nor deterministic across the distributions CI runs on.
"""

import re
import tempfile
import unittest
from pathlib import Path

from pbp_monitoring import __version__
from tests.support import start_fast_password_hashing, stop_fast_password_hashing
from tools.generate_demo_stack import (
    DEMO_RUN_ID,
    DEMO_SERIAL,
    DEMO_TARGET,
    _frozen_clock,
    _render_pages,
    _without_csp,
    chromium_binary,
    demo_incident_records,
    demo_syslog_records,
    generate,
)


def setUpModule():
    start_fast_password_hashing()


def tearDownModule():
    stop_fast_password_hashing()


# Anything outside the documentation ranges of RFC 5737 is a candidate for real
# infrastructure. `0.0.0.0` is the unset address PAN-OS writes into a THREAT log
# for the NAT fields, and the version string is not an address at all.
DOCUMENTATION_NETWORKS = ("192.0.2.", "198.51.100.", "203.0.113.")
ADDRESS = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ALLOWED_LITERALS = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}


def _addresses(text: str) -> set[str]:
    return {
        found
        for found in ADDRESS.findall(text)
        if found not in ALLOWED_LITERALS
        and all(part.isdigit() and int(part) < 256 for part in found.split("."))
    }


class DemoDataTests(unittest.TestCase):
    """The invented capture has to stay invented."""

    def test_every_address_in_the_capture_is_a_documentation_address(self):
        text = repr(demo_incident_records()) + repr(demo_syslog_records())

        for address in _addresses(text):
            self.assertTrue(
                address.startswith(DOCUMENTATION_NETWORKS),
                f"{address} is outside the RFC 5737 documentation ranges",
            )

    def test_the_capture_opens_with_an_identity_and_closes_with_a_stop(self):
        records = demo_incident_records()

        self.assertEqual(records[0]["event"], "monitor_started")
        self.assertEqual(records[0]["device"]["model"], "PA-440")
        self.assertEqual(records[-1]["event"], "monitor_stopped")
        self.assertEqual(records[-1]["reason"], "resources_recovered")

    def test_the_capture_reports_the_running_collector_version(self):
        versions = {
            record["collector_version"]
            for record in demo_incident_records()
            if "collector_version" in record
        }

        self.assertEqual(versions, {__version__})

    def test_an_unregistered_sender_is_journalled_without_its_payload(self):
        suppressed = [
            record for record in demo_syslog_records() if record.get("suppressed")
        ]

        self.assertEqual(len(suppressed), 1)
        self.assertNotIn("message", suppressed[0])
        self.assertEqual(suppressed[0]["target_names"], [])


class DemoPageTests(unittest.TestCase):
    """The pages handed to the browser are the ones the collector really serves."""

    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as temporary:
            with _frozen_clock():
                cls.pages = dict(_render_pages(Path(temporary)))

    def test_every_served_page_is_captured(self):
        self.assertEqual(
            set(self.pages),
            {
                "admin-setup",
                "admin-sign-in",
                "dashboard",
                "admin-configuration",
                "admin-firewall-form",
                "incident-report",
                "incident-report-v2",
                "text-exports",
            },
        )

    def test_no_page_carries_an_address_outside_the_documentation_ranges(self):
        for name, html in self.pages.items():
            for address in _addresses(html):
                self.assertTrue(
                    address.startswith(DOCUMENTATION_NETWORKS),
                    f"page {name} exposes {address}",
                )

    def test_the_dashboard_shows_the_completed_incident(self):
        dashboard = self.pages["dashboard"]

        self.assertIn(DEMO_TARGET, dashboard)
        self.assertIn(DEMO_RUN_ID, dashboard)
        self.assertIn("Completed", dashboard)
        self.assertIn("84", dashboard)

    def test_the_report_states_the_firewall_identity(self):
        for name in ("incident-report", "incident-report-v2"):
            with self.subTest(page=name):
                report = self.pages[name]

                self.assertNotIn("Unidentified", report)
                self.assertIn("PA-440", report)
                self.assertIn("11.1.4-h7", report)

    def test_the_demonstration_exercises_the_pbp_settings_read(self):
        """A real run reads the thresholds; the demo has to show them."""
        for name in ("incident-report", "incident-report-v2"):
            with self.subTest(page=name):
                report = self.pages[name]

                self.assertIn("configured alert 50% · activate 80%", report)
                self.assertIn("PBP enabled", report)
                # An 84% peak against an 80% activate threshold is PBP doing
                # its job, so the report must not call it threshold noise.
                self.assertNotIn('<div class="threshold-noise">', report)

    def test_the_layered_report_opens_on_its_verdict(self):
        report = self.pages["incident-report-v2"]

        self.assertLess(
            report.index('id="verdict-title"'), report.index('id="cause-title"')
        )
        self.assertLess(
            report.index('id="cause-title"'), report.index('id="pressure-title"')
        )

    def test_the_configuration_page_lists_the_demonstration_firewall(self):
        configuration = self.pages["admin-configuration"]

        self.assertIn(DEMO_TARGET, configuration)
        self.assertIn(DEMO_SERIAL, configuration)
        self.assertIn("Add a firewall", configuration)

    def test_the_first_run_pages_precede_any_administrator_session(self):
        self.assertIn("setup", self.pages["admin-setup"].lower())
        self.assertIn("sign in", self.pages["admin-sign-in"].lower())

    def test_no_page_leaks_the_demonstration_password_or_api_key(self):
        for name, html in self.pages.items():
            self.assertNotIn("demonstration-password", html, name)
            self.assertNotIn("demo-api-key", html, name)

    def test_pages_are_stable_across_runs_so_images_can_be_committed(self):
        with tempfile.TemporaryDirectory() as temporary:
            with _frozen_clock():
                again = dict(_render_pages(Path(temporary)))

        # Only the per-session CSRF tokens differ, and they live in hidden
        # inputs that no screenshot can show.
        token = re.compile(r'name="csrf" value="[^"]+"')
        for name, html in self.pages.items():
            self.assertEqual(
                token.sub('name="csrf"', html),
                token.sub('name="csrf"', again[name]),
                f"page {name} is not reproducible",
            )


class MeasurementTests(unittest.TestCase):
    """The height probe has to survive the report's own script lockdown."""

    def test_the_report_content_security_policy_is_dropped_for_measuring_only(self):
        report = _render_report_once()

        self.assertIn("Content-Security-Policy", report)
        self.assertNotIn("Content-Security-Policy", _without_csp(report))

    def test_an_unknown_browser_name_resolves_to_nothing(self):
        self.assertIsNone(chromium_binary("no-such-browser-binary"))


class CheckModeTests(unittest.TestCase):
    """`--check` is what CI runs, so it must never need a browser."""

    def test_check_mode_builds_every_page_and_writes_no_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "images"

            status = generate(output, binary=None, check_only=True)

            self.assertEqual(status, 0)
            self.assertFalse(output.exists())

    def test_a_missing_browser_is_reported_instead_of_raising(self):
        with tempfile.TemporaryDirectory() as temporary:
            status = generate(
                Path(temporary) / "images", binary=None, check_only=False
            )

            self.assertEqual(status, 2)


def _render_report_once() -> str:
    with tempfile.TemporaryDirectory() as temporary:
        with _frozen_clock():
            return dict(_render_pages(Path(temporary)))["incident-report"]


if __name__ == "__main__":
    unittest.main()
