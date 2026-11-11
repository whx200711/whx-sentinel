# Publishing WHX Sentinel

This is the maintainer checklist for getting the local `v1.0.0` tree onto GitHub.
The code and tests are already finished; only the steps that need a GitHub account
(credentials, repository settings, release) remain.

## 0. Prerequisites

- A GitHub account that owns the target repository (`whx200711` in the current setup).
- Git configured with a credential that can push (PAT or Git Credential Manager).
- Network access to `github.com` (the China-mainland network on the dev machine can
  reach the web UI but not `git push`; push from a machine/VPN where it works, or use
  a GitHub release upload through the web UI).

## 1. Create a private repository

On GitHub: **New repository** → owner `whx200711` → name `whx-sentinel` → **Private** →
do **not** add README / .gitignore / license (this tree already has them).

Then, from this folder:

```bat
git add -A
git commit -m "WHX Sentinel v1.0.0: local host visibility agent"
git branch -M main
git remote add origin https://github.com/whx200711/whx-sentinel.git
git push -u origin main
```

## 2. Let CI go green

The workflow at `.github/workflows/ci.yml` runs on `windows-latest` with Python 3.12:

- `python -m compileall -q .`
- `python sentinel.py --version`
- `python tests/smoke_test.py` → must end with `PASS n · FAIL 0`

Wait for the green check before tagging.

## 3. Tag and release

```bat
git tag -a v1.0.0 -m "WHX Sentinel v1.0.0"
git push origin v1.0.0
```

On GitHub: **Releases → Draft a new release** → choose tag `v1.0.0` → title
`WHX Sentinel v1.0.0` → copy the `## [1.0.0]` section from `CHANGELOG.md` → publish.

**Do not attach** `data/`, `*.db`, logs, or the original screenshots — the release is
the source tree only (users run it with Python; do not ship a PyInstaller exe: it
triggers SmartScreen/antivirus false positives).

## 4. Repository settings (before making it public)

- Description: `Local-only Windows host visibility agent — processes, network, persistence, event log and canary files. No telemetry.`
- Topics: `windows`, `security`, `python`, `fastapi`, `privacy`, `monitoring`, `host-based`, `triage`
- Enable **Security advisories** (Security tab → Advisories) so `SECURITY.md` links work.
- Enable **Private vulnerability reporting** if available.
- Keep the repo private until the CI run and release look right.

## 5. Go public

Switch visibility to public, then post according to the launch plan (V2EX, 少数派,
知乎, 安全客, FreeBuf, 先知, Show HN). For every announcement:

- link the repository and the screenshot in `docs/screenshot-dashboard.png`;
- state clearly that it is a local visibility tool, **not** an antivirus/EDR;
- never discuss unfixed vulnerabilities in public issues (use Security Advisories).

## 6. Post-release self-check (30 seconds)

```powershell
# PII / secrets
Select-String -Path (Get-ChildItem . -Recurse -File -Include *.py,*.js,*.md,*.json,*.yml,*.bat) `
  -Pattern 'C:\\Users\\|王浩轩|@(qq|gmail|outlook)\.com|sk-[A-Za-z0-9]{16,}|ghp_'
# sensitive data must not be tracked
git ls-files | Select-String 'data/|\.db$|\.log$'
# smoke
python tests\smoke_test.py
```
