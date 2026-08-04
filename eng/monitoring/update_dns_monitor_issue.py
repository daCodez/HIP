#!/usr/bin/env python3
"""Open one GitHub DNS incident issue and close it after recovery."""

from __future__ import annotations

import argparse
import html
import json
import os
import sys
import urllib.request
from typing import Optional


ISSUE_TITLE = "[monitoring] HIP DNS availability incident"


def _github_request(method: str, path: str, payload: Optional[dict[str, object]] = None) -> object:
    token = os.environ.get("GITHUB_TOKEN")
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not token or not repository:
        raise RuntimeError("GitHub monitor environment is incomplete.")

    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}{path}",
        data=body,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "HIP-DNS-Availability-Monitor/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        response_body = response.read()
    return json.loads(response_body) if response_body else {}


def _find_open_incident() -> Optional[int]:
    issues = _github_request("GET", "/issues?state=open&per_page=100")
    if not isinstance(issues, list):
        raise RuntimeError("GitHub issue listing returned an unexpected response.")
    for issue in issues:
        if isinstance(issue, dict) and issue.get("title") == ISSUE_TITLE and "pull_request" not in issue:
            number = issue.get("number")
            if isinstance(number, int):
                return number
    return None


def _run_url() -> str:
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    return f"{server}/{repository}/actions/runs/{run_id}"


def build_failure_body(report: str) -> str:
    """Create a bounded, escaped incident body with no workflow token or environment dump."""
    bounded_report = html.escape(report[:6000])
    return (
        "The external HIP DNS monitor detected an availability or validation failure.\n\n"
        f"Workflow run: {_run_url()}\n\n"
        "The issue remains open while failures continue and closes automatically after a successful check.\n\n"
        f"<details><summary>Bounded monitor report</summary><pre>{bounded_report}</pre></details>"
    )


def main() -> int:
    """Create, retain, or close the single HIP DNS availability incident."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--status", choices=("passed", "failed"), required=True)
    parser.add_argument("--report", required=True)
    arguments = parser.parse_args()

    with open(arguments.report, encoding="utf-8") as report_file:
        report = report_file.read()
    incident_number = _find_open_incident()

    if arguments.status == "failed" and incident_number is None:
        created = _github_request(
            "POST",
            "/issues",
            {"title": ISSUE_TITLE, "body": build_failure_body(report)},
        )
        print(f"Opened HIP DNS incident issue #{created.get('number', 'unknown')}.")
    elif arguments.status == "failed":
        print(f"HIP DNS incident issue #{incident_number} remains open.")
    elif incident_number is not None:
        _github_request(
            "POST",
            f"/issues/{incident_number}/comments",
            {"body": f"The external HIP DNS monitor recovered. Workflow run: {_run_url()}"},
        )
        _github_request("PATCH", f"/issues/{incident_number}", {"state": "closed"})
        print(f"Closed recovered HIP DNS incident issue #{incident_number}.")
    else:
        print("HIP DNS is healthy and no incident issue is open.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
