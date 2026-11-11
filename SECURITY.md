# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | ✅ |
| < 1.0 | ❌ |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Preferred channel: GitHub **Security Advisories** — open the repository's *Security*
tab and choose **Report a vulnerability**. That starts a private thread visible only
to you and the maintainer.

If advisories are unavailable, open a normal issue that contains **no details**,
just asking for a private channel.

Please include:

- affected version (`python sentinel.py --version`) and Windows version
- a minimal reproduction (steps, request, or code path)
- impact assessment (what an attacker gains, required privileges)
- whether the issue is reachable by a browser page, an unprivileged local process,
  or only by an administrator

## Scope

**In scope** — vulnerabilities in the agent itself:

- local HTTP API: authentication/authorization bypass, token leakage, CSRF,
  DNS rebinding, path traversal in static file serving, request validation, DoS
- command construction: injection into PowerShell probes, response actions, AI calls
- dashboard: DOM XSS / HTML injection from event data, CSP bypass, clickjacking
- privilege boundaries: standard-mode users reaching elevated-only actions
- data handling: unintended network egress, sensitive data written outside `data/`,
  token or command lines leaking into logs/export

**Out of scope** — expected behavior or documented limitations:

- evading the detection rules (this is not an antivirus; rule bypass is expected and
  is a regular feature request, not a vulnerability)
- attacks that require pre-existing administrator/SYSTEM rights — admin malware can
  always stop the agent (documented: no tamper protection)
- vulnerabilities in Windows, PowerShell, Defender or Ollama themselves
- false positives / false negatives in detection rules (open a normal issue)
- anything requiring physical access or a compromised same-user account
  (the same-user boundary is explicitly *not* a security boundary of this project)

## Threat model (short)

The agent runs as the current user (optionally elevated) and serves a dashboard on
`127.0.0.1`. Considered threats:

1. a malicious web page in the local browser trying to reach the dashboard
   (CSRF / DNS rebinding)
2. an unprivileged process of another user on a multi-user machine
3. untrusted data (process command lines, event fields, remote IPs) rendered in the
   dashboard
4. untrusted input reaching PowerShell or response actions

Mitigations: loopback-only binding, **`Host` header validation on every endpoint**
(blocks DNS-rebinding pages from reading events/settings), control token on every
write API, constant-time comparison, strict CSP, text-only rendering, allow-listing,
manual confirmation for all response actions, and refusal to kill critical system
processes (PID 0/4 included).

### Local-process boundary (important)

The control token is **not** a local-process security boundary. `/api/token` only
checks that the request came from loopback and that the `Host` header is a loopback
name; it does not verify the Windows user identity. Any process or user on the same
machine can read `data/config.json` (or call `/api/token`) and then:

- disable AI triage or the canary sensor,
- add up to 200 `suppress_rules` allow-list entries to silence alerts,
- stop the agent via `/api/admin/shutdown`.

The agent therefore assumes a **single-user workstation**. On shared or multi-user
machines, treat other local users as trusted. The internal probe marker used to
ignore the agent's own PowerShell subprocesses is randomly generated per install
(`internal_marker` in `config.json`) and is not exposed by the settings API.

## Disclosure timeline

| Step | Target |
| --- | --- |
| Acknowledge report | within 72 hours |
| Initial triage / severity | within 7 days |
| Fix or mitigation | 30 days for High/Critical, 90 days for others |
| Public disclosure | coordinated, after a fix is released |

Credit will be given in the release notes unless you ask to stay anonymous.

## Hardening notes for users

- Run **standard mode** for daily use; use elevated mode only when you need the
  Security event log or Defender/firewall actions.
- Keep the dashboard on `127.0.0.1` — never expose port 8765 to the LAN or internet.
- Do not commit or share `data/config.json` (it contains your control token).
- Keep Windows Defender enabled; this agent does not replace it.
