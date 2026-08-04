"""Focused unit tests for the external HIP DNS availability monitor."""

from __future__ import annotations

import importlib.util
import os
import struct
import sys
import unittest
from unittest import mock


MODULE_PATH = os.path.join(os.path.dirname(__file__), "check_hip_dns.py")
SPEC = importlib.util.spec_from_file_location("check_hip_dns", MODULE_PATH)
assert SPEC and SPEC.loader
MONITOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MONITOR
SPEC.loader.exec_module(MONITOR)

ISSUE_MODULE_PATH = os.path.join(os.path.dirname(__file__), "update_dns_monitor_issue.py")
ISSUE_SPEC = importlib.util.spec_from_file_location("update_dns_monitor_issue", ISSUE_MODULE_PATH)
assert ISSUE_SPEC and ISSUE_SPEC.loader
ISSUES = importlib.util.module_from_spec(ISSUE_SPEC)
sys.modules[ISSUE_SPEC.name] = ISSUES
ISSUE_SPEC.loader.exec_module(ISSUES)


class HipDnsMonitorTests(unittest.TestCase):
    """Verify bounded query encoding and DNSSEC response classification."""

    def test_query_contains_one_recursive_a_question(self) -> None:
        query = MONITOR.encode_dns_query("example.com")
        transaction_id, flags, questions, answers, authority, additional = struct.unpack("!HHHHHH", query[:12])

        self.assertEqual(transaction_id, 0)
        self.assertEqual(flags, 0x0120)
        self.assertEqual((questions, answers, authority, additional), (1, 0, 0, 0))
        self.assertLessEqual(len(query), 4096)

    def test_secure_response_requires_noerror_and_ad(self) -> None:
        message = struct.pack("!HHHHHH", 0, 0x81A0, 1, 1, 0, 0)
        response = MONITOR.parse_dns_response(message)

        MONITOR.require_secure_answer(response)
        self.assertTrue(response.is_authentic_data)
        self.assertEqual(response.response_code, 0)

    def test_bogus_response_requires_servfail_without_ad(self) -> None:
        message = struct.pack("!HHHHHH", 0, 0x8182, 1, 0, 0, 0)
        response = MONITOR.parse_dns_response(message)

        MONITOR.require_bogus_failure(response)
        self.assertFalse(response.is_authentic_data)
        self.assertEqual(response.response_code, 2)

    def test_response_with_wrong_transaction_id_fails(self) -> None:
        message = struct.pack("!HHHHHH", 7, 0x81A0, 1, 1, 0, 0)

        with self.assertRaises(MONITOR.MonitorFailure):
            MONITOR.parse_dns_response(message)

    def test_workflow_has_bounded_permissions_and_incident_lifecycle(self) -> None:
        workflow_path = os.path.join(os.path.dirname(__file__), "..", "..", ".github", "workflows", "dns-availability.yml")
        with open(workflow_path, encoding="utf-8") as workflow_file:
            workflow = workflow_file.read()

        self.assertIn("contents: read", workflow)
        self.assertIn("issues: write", workflow)
        self.assertIn('cron: "17,47 * * * *"', workflow)
        self.assertIn("continue-on-error: true", workflow)
        self.assertIn("id: dns_monitor", workflow)
        self.assertNotIn("steps.dns-monitor", workflow)
        self.assertIn("--status failed", workflow)
        self.assertIn("--status passed", workflow)
        self.assertNotIn("secrets.", workflow)

    def test_incident_body_is_bounded_and_escaped(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "GITHUB_SERVER_URL": "https://github.com",
                "GITHUB_REPOSITORY": "daCodez/HIP",
                "GITHUB_RUN_ID": "123",
            },
        ):
            body = ISSUES.build_failure_body("<token>" + ("x" * 7000))

        self.assertIn("https://github.com/daCodez/HIP/actions/runs/123", body)
        self.assertIn("&lt;token&gt;", body)
        self.assertNotIn("<token>", body)
        self.assertLess(len(body), 6500)

    def test_existing_incident_is_reused(self) -> None:
        response = [
            {"title": ISSUES.ISSUE_TITLE, "number": 27},
            {"title": ISSUES.ISSUE_TITLE, "number": 28, "pull_request": {}},
        ]
        with mock.patch.object(ISSUES, "_github_request", return_value=response):
            self.assertEqual(ISSUES._find_open_incident(), 27)


if __name__ == "__main__":
    unittest.main()
