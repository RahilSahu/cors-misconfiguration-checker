#!/usr/bin/env python3
"""CORS misconfiguration checker.

Cross-Origin Resource Sharing mistakes are a staple of web security
assessments: an API that reflects any Origin while also allowing
credentials is readable by every website a logged-in user visits.

This tool probes a target URL with a battery of Origin headers and
classifies the responses:

- Origin reflection with credentials (critical)
- Wildcard origin with credentials (critical, browsers block it but it
  signals a broken configuration)
- Origin reflection without credentials (high when sensitive data is
  returned)
- Trusting the null origin with credentials (high, sandbox and file
  contexts send Origin: null)
- Trusting subdomains or prefix or suffix lookalike origins
- Preflight handling for a cross-origin request with custom headers

Zero dependencies: Python 3.9+ standard library only. Only test
applications you own or are authorised to test.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlparse

USER_AGENT = "cors-check/1.0 (+https://github.com/RahilSahu/cors-misconfiguration-checker)"

ATTACKER = "https://evil-attacker.example"


@dataclass
class Finding:
    test: str
    origin_sent: str
    severity: str  # critical, high, medium, info
    detail: str
    acao: str | None = None
    acac: str | None = None


@dataclass
class Report:
    url: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def worst(self) -> str:
        order = {"critical": 3, "high": 2, "medium": 1, "info": 0}
        if not self.findings:
            return "none"
        return max((f.severity for f in self.findings), key=lambda s: order[s])


def classify(url: str, origin_sent: str, acao: str | None, acac: str | None,
             test: str = "origin probe") -> Finding | None:
    """Classify one response. Pure function, unit tested offline.

    Returns None when the response does not trust the sent origin.
    """
    if acao is None:
        return None
    credentials = (acac or "").strip().lower() == "true"
    acao_clean = acao.strip()

    if origin_sent == "null" and acao_clean == "null":
        severity = "high" if credentials else "medium"
        return Finding(test, origin_sent, severity,
                       "Server trusts the null origin. Sandboxed iframes, redirects and local files "
                       "all produce Origin: null, so this is attacker-controllable.",
                       acao, acac)

    if acao_clean == "*":
        if credentials:
            return Finding(test, origin_sent, "critical",
                           "Wildcard Access-Control-Allow-Origin with credentials allowed. "
                           "Browsers refuse this combination, which signals the CORS policy "
                           "was never reviewed.", acao, acac)
        return Finding(test, origin_sent, "info",
                       "Wildcard origin without credentials. Fine for public data, wrong for "
                       "anything user-specific.", acao, acac)

    if acao_clean == origin_sent:
        if credentials:
            return Finding(test, origin_sent, "critical",
                           "Server reflects an arbitrary Origin AND allows credentials. Any "
                           "website can read this user's authenticated responses from this API.",
                           acao, acac)
        return Finding(test, origin_sent, "high",
                       "Server reflects an arbitrary Origin. Any website can read unauthenticated "
                       "responses, and the same code path often also enables credentials elsewhere.",
                       acao, acac)

    parsed_target = urlparse(url)
    origin_host = urlparse(origin_sent).hostname or ""
    target_host = parsed_target.hostname or ""
    if origin_host and target_host and origin_host != target_host and origin_host.endswith(target_host):
        return Finding(test, origin_sent, "high" if credentials else "medium",
                       f"Server trusts an origin that ends with the target host ({origin_host}). "
                       "An attacker who controls such a subdomain or lookalike can pass the check.",
                       acao, acac)
    return None


def probe_origins(url: str) -> list[tuple[str, str]]:
    """Origins to try, relative to the target host."""
    host = urlparse(url).hostname or "example.com"
    scheme = urlparse(url).scheme or "https"
    return [
        ("Arbitrary origin reflection", ATTACKER),
        ("Null origin", "null"),
        ("Same site over plain HTTP", f"http://{host}"),
        ("Subdomain of target", f"{scheme}://evil.{host}"),
        ("Target as subdomain of attacker", f"{scheme}://{host}.evil-attacker.example"),
        ("Prefix lookalike", f"{scheme}://{host}evil.example"),
        ("Suffix lookalike", f"{scheme}://evil{host}"),
        ("Underscore subdomain", f"{scheme}://sub_domain.{host}"),
    ]


def fetch_cors(url: str, origin: str, method: str = "GET", extra_headers: dict | None = None,
               timeout: float = 15.0) -> tuple[str | None, str | None, int | None]:
    headers = {"User-Agent": USER_AGENT, "Origin": origin}
    if extra_headers:
        headers.update(extra_headers)
    request = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return (response.headers.get("Access-Control-Allow-Origin"),
                    response.headers.get("Access-Control-Allow-Credentials"),
                    response.status)
    except urllib.error.HTTPError as exc:
        return (exc.headers.get("Access-Control-Allow-Origin") if exc.headers else None,
                exc.headers.get("Access-Control-Allow-Credentials") if exc.headers else None,
                exc.code)
    except (urllib.error.URLError, TimeoutError, ValueError):
        return None, None, None


def run_checks(url: str, timeout: float = 15.0) -> Report:
    if "://" not in url:
        url = "https://" + url
    report = Report(url=url)
    for test_name, origin in probe_origins(url):
        acao, acac, _status = fetch_cors(url, origin, timeout=timeout)
        finding = classify(url, origin, acao, acac, test=test_name)
        if finding:
            report.findings.append(finding)

    # Preflight: does the server approve a cross-origin request carrying
    # a custom header and credentials from the attacker origin?
    acao, acac, _ = fetch_cors(
        url, ATTACKER, method="OPTIONS",
        extra_headers={
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-Custom-Header, Authorization",
        }, timeout=timeout)
    preflight = classify(url, ATTACKER, acao, acac, test="Preflight with custom headers")
    if preflight:
        preflight.detail += " The preflight check also approves custom headers cross-origin."
        if all(f.test != preflight.test for f in report.findings):
            report.findings.append(preflight)
    return report


def print_report(report: Report) -> None:
    print(f"\nURL: {report.url}")
    if not report.findings:
        print("No CORS trust problems found for the origins tested.\n")
        return
    for f in report.findings:
        print(f"\n[{f.severity.upper()}] {f.test}")
        print(f"  Origin sent: {f.origin_sent}")
        print(f"  ACAO: {f.acao}  ACAC: {f.acac}")
        print(f"  {f.detail}")
    print(f"\nWorst severity: {report.worst}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check a URL for CORS misconfigurations.")
    parser.add_argument("url", help="URL to test, e.g. https://api.example.com/me")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args(argv)

    report = run_checks(args.url, timeout=args.timeout)
    if args.json:
        print(json.dumps({"url": report.url, "worst_severity": report.worst,
                          "findings": [vars(f) for f in report.findings]}, indent=2))
    else:
        print_report(report)
    return 1 if report.worst in ("critical", "high") else 0


if __name__ == "__main__":
    raise SystemExit(main())
