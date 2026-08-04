#!/usr/bin/env python3
"""Externally verify HIP encrypted DNS without collecting user query data."""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import ssl
import struct
import sys
import time
import urllib.request
from dataclasses import asdict, dataclass
from typing import Callable, Optional


SECURE_TEST_DOMAIN = "cloudflare.com"
BOGUS_TEST_DOMAIN = "dnssec-failed.org"
EXPECTED_STATUS_TEXT = "HIP encrypted DNS endpoint"


class MonitorFailure(RuntimeError):
    """Raised when a monitored DNS contract is unavailable or invalid."""


@dataclass(frozen=True)
class DnsResponseHeader:
    """Minimal privacy-safe DNS response fields needed by the monitor."""

    transaction_id: int
    response_code: int
    is_response: bool
    is_truncated: bool
    is_authentic_data: bool


@dataclass(frozen=True)
class CheckResult:
    """One bounded availability result without raw DNS payloads or credentials."""

    name: str
    status: str
    duration_ms: int
    detail: str


def encode_dns_query(domain: str, transaction_id: int = 0) -> bytes:
    """Encode one recursive IN A query with a bounded public test name."""
    labels = domain.rstrip(".").split(".")
    if not labels or any(not label or len(label.encode("ascii")) > 63 for label in labels):
        raise ValueError("DNS test domain is invalid.")

    question = bytearray()
    for label in labels:
        encoded = label.encode("ascii")
        question.append(len(encoded))
        question.extend(encoded)
    question.append(0)
    question.extend(struct.pack("!HH", 1, 1))
    # Request recursion and signal that this client understands the authenticated-data bit.
    return struct.pack("!HHHHHH", transaction_id, 0x0120, 1, 0, 0, 0) + bytes(question)


def parse_dns_response(message: bytes, expected_transaction_id: int = 0) -> DnsResponseHeader:
    """Parse and validate the fixed DNS header returned by an encrypted transport."""
    if len(message) < 12:
        raise MonitorFailure("DNS response was shorter than its fixed header.")

    transaction_id, flags, question_count, _, _, _ = struct.unpack("!HHHHHH", message[:12])
    response = DnsResponseHeader(
        transaction_id=transaction_id,
        response_code=flags & 0x000F,
        is_response=bool(flags & 0x8000),
        is_truncated=bool(flags & 0x0200),
        is_authentic_data=bool(flags & 0x0020),
    )
    if response.transaction_id != expected_transaction_id:
        raise MonitorFailure("DNS response transaction identifier did not match.")
    if not response.is_response or question_count != 1:
        raise MonitorFailure("DNS response did not contain the expected single question.")
    if response.is_truncated:
        raise MonitorFailure("Encrypted DNS response was unexpectedly truncated.")
    return response


def require_secure_answer(response: DnsResponseHeader) -> None:
    """Require a successful DNSSEC-authenticated answer."""
    if response.response_code != 0 or not response.is_authentic_data:
        raise MonitorFailure("Secure test domain was not returned as DNSSEC authenticated.")


def require_bogus_failure(response: DnsResponseHeader) -> None:
    """Require a known-bogus DNSSEC domain to fail closed with SERVFAIL."""
    if response.response_code != 2 or response.is_authentic_data:
        raise MonitorFailure("Known-bogus DNSSEC domain did not fail closed.")


def _https_dns_request(host: str, query: bytes, method: str, timeout_seconds: float) -> bytes:
    url = f"https://{host}/dns-query"
    headers = {
        "Accept": "application/dns-message",
        "User-Agent": "HIP-DNS-Availability-Monitor/1.0",
    }
    data: Optional[bytes] = None
    if method == "GET":
        encoded = base64.urlsafe_b64encode(query).decode("ascii").rstrip("=")
        url = f"{url}?dns={encoded}"
    elif method == "POST":
        data = query
        headers["Content-Type"] = "application/dns-message"
    else:
        raise ValueError("DoH method must be GET or POST.")

    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        if response.status != 200:
            raise MonitorFailure(f"DoH {method} returned HTTP {response.status}.")
        content_type = response.headers.get_content_type()
        if content_type != "application/dns-message":
            raise MonitorFailure(f"DoH {method} returned unexpected media type {content_type}.")
        return response.read(65536)


def _read_exact(stream: ssl.SSLSocket, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        chunk = stream.recv(length - len(output))
        if not chunk:
            raise MonitorFailure("DNS-over-TLS connection closed before the response completed.")
        output.extend(chunk)
    return bytes(output)


def _dot_request(host: str, query: bytes, timeout_seconds: float, minimum_certificate_days: int) -> bytes:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((host, 853), timeout=timeout_seconds) as connection:
        with context.wrap_socket(connection, server_hostname=host) as secure_connection:
            certificate = secure_connection.getpeercert()
            expiry_text = certificate.get("notAfter")
            if not expiry_text:
                raise MonitorFailure("DNS-over-TLS certificate did not expose an expiry date.")
            remaining_days = (ssl.cert_time_to_seconds(expiry_text) - time.time()) / 86400
            if remaining_days < minimum_certificate_days:
                raise MonitorFailure(
                    f"DNS-over-TLS certificate expires in fewer than {minimum_certificate_days} days."
                )

            secure_connection.sendall(struct.pack("!H", len(query)) + query)
            response_length = struct.unpack("!H", _read_exact(secure_connection, 2))[0]
            if response_length < 12:
                raise MonitorFailure("DNS-over-TLS response length was invalid.")
            return _read_exact(secure_connection, response_length)


def _check_status_page(host: str, timeout_seconds: float) -> str:
    request = urllib.request.Request(
        f"https://{host}/",
        headers={"User-Agent": "HIP-DNS-Availability-Monitor/1.0"},
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        body = response.read(1024).decode("utf-8", errors="replace")
        if response.status != 200 or EXPECTED_STATUS_TEXT not in body:
            raise MonitorFailure("Encrypted DNS status endpoint was unavailable or unexpected.")
    return "HTTPS status endpoint returned the expected service marker."


def _check_plain_dns_closed(host: str, timeout_seconds: float) -> str:
    try:
        with socket.create_connection((host, 53), timeout=min(timeout_seconds, 3.0)):
            raise MonitorFailure("Public TCP port 53 unexpectedly accepted a connection.")
    except MonitorFailure:
        raise
    except OSError:
        return "Public TCP port 53 remains closed."


def _run_check(name: str, operation: Callable[[], str]) -> CheckResult:
    started = time.monotonic()
    try:
        detail = operation()
        status = "pass"
    except Exception as exception:  # noqa: BLE001 - monitor must report every independent check.
        detail = str(exception) or exception.__class__.__name__
        status = "fail"
    duration_ms = round((time.monotonic() - started) * 1000)
    return CheckResult(name, status, duration_ms, detail)


def run_monitor(host: str, timeout_seconds: float, minimum_certificate_days: int) -> list[CheckResult]:
    """Run fixed public probes for availability, DNSSEC behavior, and transport safety."""
    secure_query = encode_dns_query(SECURE_TEST_DOMAIN)
    bogus_query = encode_dns_query(BOGUS_TEST_DOMAIN)

    def check_doh_get() -> str:
        require_secure_answer(parse_dns_response(_https_dns_request(host, secure_query, "GET", timeout_seconds)))
        return "DoH GET returned a DNSSEC-authenticated answer."

    def check_doh_post() -> str:
        require_secure_answer(parse_dns_response(_https_dns_request(host, secure_query, "POST", timeout_seconds)))
        return "DoH POST returned a DNSSEC-authenticated answer."

    def check_doh_bogus() -> str:
        require_bogus_failure(parse_dns_response(_https_dns_request(host, bogus_query, "GET", timeout_seconds)))
        return "DoH rejected the known-bogus DNSSEC domain."

    def check_dot_secure() -> str:
        require_secure_answer(
            parse_dns_response(_dot_request(host, secure_query, timeout_seconds, minimum_certificate_days))
        )
        return "DoT certificate and DNSSEC-authenticated answer are valid."

    def check_dot_bogus() -> str:
        require_bogus_failure(
            parse_dns_response(_dot_request(host, bogus_query, timeout_seconds, minimum_certificate_days))
        )
        return "DoT rejected the known-bogus DNSSEC domain."

    return [
        _run_check("status-page", lambda: _check_status_page(host, timeout_seconds)),
        _run_check("doh-get-secure", check_doh_get),
        _run_check("doh-post-secure", check_doh_post),
        _run_check("doh-bogus-fails-closed", check_doh_bogus),
        _run_check("dot-secure-and-certificate", check_dot_secure),
        _run_check("dot-bogus-fails-closed", check_dot_bogus),
        _run_check("plain-tcp-53-closed", lambda: _check_plain_dns_closed(host, timeout_seconds)),
    ]


def main() -> int:
    """Run the external HIP DNS monitor and print a bounded JSON report."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=os.environ.get("HIP_DNS_HOST", "dns.guardwithhip.com"))
    parser.add_argument("--timeout-seconds", type=float, default=8.0)
    parser.add_argument("--minimum-certificate-days", type=int, default=14)
    arguments = parser.parse_args()

    results = run_monitor(arguments.host, arguments.timeout_seconds, arguments.minimum_certificate_days)
    report = {
        "service": arguments.host,
        "status": "pass" if all(result.status == "pass" for result in results) else "fail",
        "checkedAtUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "checks": [asdict(result) for result in results],
    }
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
