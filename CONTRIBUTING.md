# Contributing to WHX Sentinel

Thanks for your interest! This is a small, local-only Windows tool; contributions are
welcome as long as they keep the “runs on your machine, no telemetry” promise.

## Before you start

- Read `SECURITY.md` and the capability boundaries in `README.md`.
- This project is **not** an antivirus or a commercial EDR; rule bypasses and false
  positives are reported as normal issues, not vulnerabilities.
- Windows 10/11 64-bit and Python 3.10+ (3.12 tested) are required for full testing.

## Development setup

```bat
python -m pip install -r requirements.txt
python sentinel.py --version
python sentinel.py --once
python sentinel.py --open
```

Run the smoke suite before every pull request:

```bat
python tests/smoke_test.py
```

All cases must pass (`PASS n · FAIL 0`). `SKIP` is acceptable only when an optional
asset (e.g. Node.js for `node --check`) is missing locally.

## Pull requests

- Keep changes focused; one topic per PR.
- Do not commit `data/`, `*.db`, logs, tokens or screenshots containing real usernames
  or LAN IPs.
- New detection rules: add a positive and a negative case to `tests/smoke_test.py`.
- New API endpoints: validate input lengths, require the control token for writes, and
  keep the `Host` validation middleware untouched.
- Update `CHANGELOG.md` and, when relevant, both `README.md` and `README.en.md`.

## Reporting security issues

Please **do not** open a public issue for vulnerabilities. Use GitHub Security
Advisories (“Report a vulnerability”) — see `SECURITY.md` for scope and the disclosure
timeline.
