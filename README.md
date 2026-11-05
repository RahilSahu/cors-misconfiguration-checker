# CORS Misconfiguration Checker

A zero-dependency Python tool that probes a URL with a battery of
hostile Origin headers and tells you, in plain language, whether the
CORS policy can be abused.

CORS mistakes are one of the most common findings in web and API
assessments. The dangerous pattern is simple: the server reflects any
Origin it receives and also sends
`Access-Control-Allow-Credentials: true`. At that point every website
a logged-in user visits can read that user's authenticated API
responses.

## What it tests

- Arbitrary origin reflection, with and without credentials
- Wildcard `Access-Control-Allow-Origin: *` combined with credentials
- Trusting the `null` origin (sent by sandboxed iframes, redirects and
  local files, so fully attacker controllable)
- Trusting subdomains of the target
- Prefix and suffix lookalike hosts, for example
  `api.example.com.evil.com` or `evilapi.example.com`
- A preflight request carrying custom headers from an attacker origin

## Usage

```bash
python3 cors_check.py https://api.example.com/me
python3 cors_check.py https://api.example.com/me --json
```

Example output:

```text
[CRITICAL] Arbitrary origin reflection
  Origin sent: https://evil-attacker.example
  ACAO: https://evil-attacker.example  ACAC: true
  Server reflects an arbitrary Origin AND allows credentials. Any
  website can read this user's authenticated responses from this API.
```

Exit code is 1 when a critical or high finding is present.

## How to fix a finding

- Allowlist exact origins, never reflect the Origin header back
- Never combine a reflected or wildcard origin with credentials
- Do not trust `null`, subdomains, or string suffix matches
- Keep the allowlist in configuration, reviewed like firewall rules

## Requirements

Python 3.9 or newer. No packages to install.

## Tests

The classification logic is unit tested offline:

```bash
python3 -m unittest discover -s tests
```

## Responsible use

Only test applications you own or are authorised to test.

## License

MIT, see LICENSE.
