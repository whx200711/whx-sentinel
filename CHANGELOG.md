# Changelog

All notable changes to WHX Sentinel are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-11-11

First public release: a local-only Windows host visibility agent with a browser
dashboard. Everything runs on the user's machine; no telemetry, no cloud.

### Added

- 8 sensors: process, network, Defender/firewall, Security event log, autorun,
  startup folder, scheduled tasks, services, file integrity (canary files) and
  exposure checks.
- FastAPI dashboard on `127.0.0.1:8765` with event timeline, event details,
  allow-list management, settings drawer, JSON export and recent-actions log.
- Manual response actions: acknowledge/ignore event, block remote IP, kill process,
  Defender quick scan/update, stop agent — all behind the control token.
- Optional AI triage through a **local** Ollama instance (off by default).
- Windows autostart helpers (`install/*.bat`) and an install/uninstall flow.
- Smoke test suite (`tests/smoke_test.py`) covering rules, database, config,
  API and front-end assets, plus a GitHub Actions workflow.

### Security

- **DNS rebinding fix (H-1):** every HTTP endpoint now validates the `Host` header
  and only accepts `127.0.0.1` / `localhost` / `[::1]`; a `Cross-Origin-Resource-Policy:
  same-origin` header is sent as well.
- **Documented local-process boundary (H-2):** README / README.en / SECURITY now state
  that the control token protects browser cross-origin requests only, not local
  processes, and that the agent assumes a single-user workstation.
- **Ollama URL validation (M-1):** `ollama_url` is parsed with `urlsplit` and restricted
  to loopback hosts, no userinfo, and port 11434 — this closes the
  `http://127.0.0.1@evil.tld` style bypass that could exfiltrate event metadata.
- **Non-blocking response actions (M-2):** dashboard actions (including AI triage) run in
  a thread pool so the event loop is no longer blocked for up to 150 seconds.
- **Random internal probe marker (M-3):** the fixed `WHX_SENTINEL_INTERNAL` allow-list
  string was removed; each install generates `internal_marker` and only that value is
  used to skip the agent's own PowerShell subprocesses.
- **Request body limit:** write endpoints reject bodies over 1 MB with `413`.
- **Kill-process guard:** PID 0/4 and the agent's own PID are rejected before touching
  the process table.
- **Safer defaults:** AI triage is off by default; the exposure panel no longer shows a
  contradictory “hardened” badge for risky states.

### Notes

- Windows-only; requires Python 3.10+ (tested on 3.12).
- Uses public/loopback data only; no network egress, no remote management.

[1.0.0]: https://github.com/whx200711/whx-sentinel/releases/tag/v1.0.0
