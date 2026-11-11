"""WHX 哨兵 · 自启动项 / 计划任务 / 服务传感器。

采集并基线化这些持久化位置（全部只读）：

- 注册表：HKCU/HKLM（含 WOW6432Node）的 Run / RunOnce / RunServices，
  以及 Winlogon 的 Shell / Userinit；
- 启动目录：用户与公共「启动」文件夹里的文件（大小 + mtime 指纹）；
- 计划任务：Get-ScheduledTask（失败回退 schtasks /query CSV）；
- 系统服务：Get-CimInstance Win32_Service（失败回退 psutil.win_service_iter）。

基线 diff 语义（ctx.baselines["autorun"]）：
- 某个类别第一次被成功采集时只保存基线，不产生「新增」告警（避免装完刚启动满屏告警）；
- 之后新增 → match_autorun / match_startup_file / match_scheduled_task / match_service；
- 内容变化 → match_autorun(changed=True)；计划任务/服务没有「通用变更」规则，
  只对可疑命令继续跑规则匹配（见交付报告里的接口缺口说明）；
- 所有条目（含首次运行）都会跑可疑命令匹配；
- 采集失败的类别保留旧基线，避免临时失败导致下次整批误报。

写 ctx.shared["autorun"] = {count, baseline_ts, capabilities, ...}。
"""

from __future__ import annotations

import csv
import io
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any

import rules
import winutil
from sensors.base import Sensor

logger = logging.getLogger("whx.sentinel.sensor.autorun")

MAX_FINDINGS_PER_CYCLE = 40
COMMAND_LIMIT = 1200

# (root_name, hive_label, registry_path, location_label)
REG_LOCATIONS = (
    ("HKEY_CURRENT_USER", "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", "Run"),
    ("HKEY_CURRENT_USER", "HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce"),
    ("HKEY_CURRENT_USER", "HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunServices", "RunServices"),
    ("HKEY_LOCAL_MACHINE", "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Run"),
    ("HKEY_LOCAL_MACHINE", "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce"),
    ("HKEY_LOCAL_MACHINE", "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices", "RunServices"),
    ("HKEY_LOCAL_MACHINE", "HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "Run(Wow6432Node)"),
    ("HKEY_LOCAL_MACHINE", "HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce(Wow6432Node)"),
)
WINLOGON_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
WINLOGON_VALUES = ("Shell", "Userinit")

TASKS_SERVICES_PS = r"""
$r = [pscustomobject]@{
  tasks_ok = $false; tasks_error = ''; tasks = @()
  services_ok = $false; services_error = ''; services = @()
}
try {
  $r.tasks = @(Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
    $acts = @($_.Actions | ForEach-Object { ("{0} {1}" -f "$($_.Execute)", "$($_.Arguments)").Trim() })
    [pscustomobject]@{
      name = "$($_.TaskName)"
      path = "$($_.TaskPath)"
      state = "$($_.State)"
      command = ($acts -join ' ; ')
    }
  })
  $r.tasks_ok = $true
} catch { $r.tasks_error = "$($_.FullyQualifiedErrorId)" }
try {
  $r.services = @(Get-CimInstance Win32_Service -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{
      name = "$($_.Name)"
      display = "$($_.DisplayName)"
      command = "$($_.PathName)"
      state = "$($_.State)"
      start_mode = "$($_.StartMode)"
    }
  })
  $r.services_ok = $true
} catch { $r.services_error = "$($_.FullyQualifiedErrorId)" }
$r
"""

_DENIED_HINTS = ("unauthorized", "accessdenied", "access is denied", "0x80041003", "拒绝访问")


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------
def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return [value]


def _text(value: Any, limit: int = COMMAND_LIMIT) -> str:
    return str(value or "").strip()[:limit]


def _reg_values(root_name: str, path: str) -> list[tuple[str, Any]]:
    """枚举一个注册表键下的所有值；键不存在/无权限返回 []。"""

    if not winutil.IS_WINDOWS:
        return []
    try:
        import winreg

        root = getattr(winreg, root_name, None)
        if root is None:
            return []
        values: list[tuple[str, Any]] = []
        with winreg.OpenKey(root, path) as key:
            try:
                count = winreg.QueryInfoKey(key)[1]
            except OSError:
                return values
            for index in range(count):
                try:
                    name, value, _kind = winreg.EnumValue(key, index)
                except OSError:
                    break
                values.append((name, value))
        return values
    except OSError:
        return []


def _is_denied(error_text: str) -> bool:
    text = str(error_text or "").lower()
    return any(hint in text for hint in _DENIED_HINTS)


def _decode_console(data: bytes) -> str:
    """命令行工具输出按 Windows ANSI 代码页解码（schtasks 的中文表头）。"""

    if not data:
        return ""
    for encoding in ("mbcs", "utf-8", "gbk", "latin-1"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", "replace")


def _parse_schtasks_csv(text: str) -> list[dict[str, str]] | None:
    """解析 schtasks /query /fo CSV /v 的输出；表头无法识别时返回 None。"""

    try:
        rows = list(csv.reader(io.StringIO(text)))
    except csv.Error:
        return None
    if len(rows) < 2:
        return None
    header = [cell.strip() for cell in rows[0]]
    lowered = [cell.lower() for cell in header]

    def find_column(*needles: str) -> int | None:
        for index, cell in enumerate(lowered):
            if any(needle in cell for needle in needles):
                return index
        for index, cell in enumerate(header):
            if any(needle in cell for needle in needles):
                return index
        return None

    name_index = find_column("taskname", "任务名", "任务名称")
    command_index = find_column("task to run", "要运行的任务", "运行的任务")
    if name_index is None or command_index is None:
        return None

    tasks: list[dict[str, str]] = []
    for row in rows[1:]:
        if len(row) <= max(name_index, command_index):
            continue
        name = _text(row[name_index], 300)
        if not name or name.lower() in {"taskname", "任务名"}:
            continue
        tasks.append({"name": name, "command": _text(row[command_index])})
    return tasks


# ---------------------------------------------------------------------------
# 传感器
# ---------------------------------------------------------------------------
class AutorunSensor(Sensor):
    id = "autorun"
    name = "自启动项"
    description = "基线化注册表自启动、启动目录、计划任务与服务，发现新增/变更的持久化项"
    interval_key = "autorun_interval_s"
    default_interval = 300.0
    initial_delay = 8.0
    requires_admin = False

    # ------------------------------------------------------------------ 采集
    def collect(self) -> list:
        try:
            return self._collect()
        except Exception:  # noqa: BLE001 - 传感器绝不向采集线程抛异常
            logger.exception("自启动项传感器采集异常")
            self.capability = "degraded"
            return []

    def _collect(self) -> list:
        if not winutil.IS_WINDOWS:
            self.capability = "unavailable"
            return []

        now = time.time()
        entries: list[dict[str, Any]] = []
        capabilities: dict[str, str] = {}
        probed_categories: set[str] = set()

        # ---- 注册表自启动 ----------------------------------------------------
        try:
            registry_entries = self._collect_registry()
            entries.extend(registry_entries)
            capabilities["registry"] = "ok"
            probed_categories.add("registry")
        except Exception:  # noqa: BLE001
            logger.exception("注册表自启动项采集失败")
            capabilities["registry"] = "error"

        # ---- 启动目录 --------------------------------------------------------
        try:
            startup_entries = self._collect_startup_files()
            entries.extend(startup_entries)
            capabilities["startup_dirs"] = "ok"
            probed_categories.add("startup")
        except Exception:  # noqa: BLE001
            logger.exception("启动目录采集失败")
            capabilities["startup_dirs"] = "error"

        # ---- 计划任务 / 服务（一次 PowerShell 探针） --------------------------
        env = self._probe_tasks_services()
        tasks_entries, tasks_capability, tasks_category = self._collect_tasks(env)
        services_entries, services_capability, services_category = self._collect_services(env)
        capabilities["tasks"] = tasks_capability
        capabilities["services"] = services_capability
        if tasks_entries is not None and tasks_category:
            entries.extend(tasks_entries)
            probed_categories.add(tasks_category)
        if services_entries is not None and services_category:
            entries.extend(services_entries)
            probed_categories.add(services_category)

        # ---- 基线 diff + 规则匹配 --------------------------------------------
        findings, baseline_ts = self._diff_and_match(entries, probed_categories, now)

        # ---- 状态发布 --------------------------------------------------------
        by_kind: dict[str, int] = {}
        for entry in entries:
            kind = str(entry.get("kind") or "unknown")
            by_kind[kind] = by_kind.get(kind, 0) + 1
        if (
            capabilities.get("registry") == "ok"
            and capabilities.get("startup_dirs") == "ok"
            and capabilities.get("tasks") == "ok"
            and capabilities.get("services") == "ok"
        ):
            self.capability = "ok"
        elif capabilities.get("registry") == "ok" or capabilities.get("startup_dirs") == "ok":
            self.capability = "degraded"
        else:
            self.capability = "unavailable"

        self.ctx.shared["autorun"] = {
            "count": len(entries),
            "baseline_ts": baseline_ts,
            "capabilities": capabilities,
            "by_kind": by_kind,
            "checked_at": now,
            "baseline_entries": len(self._baseline_entries_snapshot()),
        }
        if findings:
            self.ctx.shared["autorun"]["last_alert_ts"] = now
        return findings

    # ------------------------------------------------------------------ 注册表
    def _collect_registry(self) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for root_name, hive, reg_path, label in REG_LOCATIONS:
            for value_name, value in _reg_values(root_name, reg_path):
                command = _text(value)
                if not command:
                    continue
                name = str(value_name or "").strip()
                entries.append(
                    {
                        "key": f"run:{hive}:{label}:{name.lower()}",
                        "category": "registry",
                        "kind": "registry",
                        "name": name,
                        "location": f"{hive}\\{reg_path}",
                        "command": command,
                        "fingerprint": {"command": command},
                    }
                )

        for value_name in WINLOGON_VALUES:
            value = winutil.registry_value("HKEY_LOCAL_MACHINE", WINLOGON_KEY, value_name)
            command = _text(value)
            if not command:
                continue
            entries.append(
                {
                    "key": f"winlogon:{value_name.lower()}",
                    "category": "registry",
                    "kind": "winlogon",
                    "name": value_name,
                    "location": f"HKLM\\{WINLOGON_KEY}",
                    "command": command,
                    "fingerprint": {"command": command},
                }
            )
        return entries

    # ------------------------------------------------------------------ 启动目录
    def _startup_dirs(self) -> list[Path]:
        dirs: list[Path] = []
        appdata = os.environ.get("APPDATA")
        if appdata:
            dirs.append(Path(appdata) / "Microsoft/Windows/Start Menu/Programs/Startup")
        programdata = os.environ.get("PROGRAMDATA") or os.environ.get("ALLUSERSPROFILE")
        if programdata:
            dirs.append(Path(programdata) / "Microsoft/Windows/Start Menu/Programs/Startup")
        return dirs

    def _collect_startup_files(self) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        existing = 0
        readable = 0
        for directory in self._startup_dirs():
            if not directory.is_dir():
                continue
            existing += 1
            try:
                children = list(directory.iterdir())
            except OSError:
                continue
            readable += 1
            for child in children:
                try:
                    if not child.is_file():
                        continue
                    stat = child.stat()
                except OSError:
                    continue
                entries.append(
                    {
                        "key": f"startup:{str(child).lower()}",
                        "category": "startup",
                        "kind": "startup_file",
                        "name": child.name,
                        "location": str(directory),
                        "path": str(child),
                        "command": str(child),
                        "fingerprint": {"size": int(stat.st_size), "mtime": int(stat.st_mtime)},
                    }
                )
        if existing and not readable:
            raise OSError("启动目录不可读")
        return entries

    # ------------------------------------------------------------------ 任务/服务
    def _probe_tasks_services(self) -> dict[str, Any]:
        try:
            env = self.ctx.probe_json(TASKS_SERVICES_PS, timeout=60.0)
        except Exception as exc:  # noqa: BLE001 - 权限不足/沙箱属预期
            logger.debug("计划任务/服务探针失败：%s", exc)
            return {}
        return env if isinstance(env, dict) else {}

    def _collect_tasks(
        self, env: dict[str, Any]
    ) -> tuple[list[dict[str, Any]] | None, str, str]:
        tasks = env.get("tasks")
        if bool(env.get("tasks_ok")):
            entries: list[dict[str, Any]] = []
            for item in _as_list(tasks):
                if not isinstance(item, dict):
                    continue
                name = _text(item.get("name"), 300)
                if not name:
                    continue
                path = _text(item.get("path"), 300)
                command = _text(item.get("command"))
                entries.append(
                    {
                        "key": f"task:{(path + name).lower()}",
                        "category": "tasks:ps",
                        "kind": "scheduled_task",
                        "name": name,
                        "location": path or "\\",
                        "command": command,
                        "execute": command,
                        "arguments": "",
                        "fingerprint": {"command": command},
                    }
                )
            return entries, "ok", "tasks:ps"

        # 回退：schtasks /query /fo CSV /v（原生命令，直接子进程读取输出）
        fallback = self._tasks_from_schtasks()
        if fallback is None:
            return None, "unavailable", ""
        error = str(env.get("tasks_error") or "")
        logger.debug("Get-ScheduledTask 不可用（%s），已回退 schtasks", error[:120])
        entries = []
        for item in fallback:
            name = _text(item.get("name"), 300)
            command = _text(item.get("command"))
            if not name:
                continue
            entries.append(
                {
                    "key": f"task:{name.lower()}",
                    "category": "tasks:schtasks",
                    "kind": "scheduled_task",
                    "name": name,
                    "location": "schtasks",
                    "command": command,
                    "execute": command,
                    "arguments": "",
                    "fingerprint": {"command": command},
                }
            )
        if not entries:
            return None, "unavailable", ""
        return entries, "fallback:schtasks", "tasks:schtasks"

    def _tasks_from_schtasks(self) -> list[dict[str, str]] | None:
        try:
            completed = subprocess.run(
                ["schtasks.exe", "/query", "/fo", "CSV", "/v"],
                capture_output=True,
                timeout=60,
                creationflags=getattr(winutil, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            logger.debug("schtasks 回退失败：%s", exc)
            return None
        if completed.returncode != 0:
            return None
        return _parse_schtasks_csv(_decode_console(completed.stdout))

    def _collect_services(
        self, env: dict[str, Any]
    ) -> tuple[list[dict[str, Any]] | None, str, str]:
        if bool(env.get("services_ok")):
            entries: list[dict[str, Any]] = []
            for item in _as_list(env.get("services")):
                if not isinstance(item, dict):
                    continue
                name = _text(item.get("name"), 200)
                if not name:
                    continue
                command = _text(item.get("command"))
                entries.append(
                    {
                        "key": f"service:{name.lower()}",
                        "category": "services:ps",
                        "kind": "service",
                        "name": name,
                        "location": "Windows 服务",
                        "command": command,
                        "display_name": _text(item.get("display"), 300),
                        "state": _text(item.get("state"), 80),
                        "start_mode": _text(item.get("start_mode"), 80),
                        "fingerprint": {"command": command},
                    }
                )
            return entries, "ok", "services:ps"

        # 回退：psutil 枚举服务（标准用户可用）
        fallback = self._services_from_psutil()
        if fallback is None:
            return None, "unavailable", ""
        error = str(env.get("services_error") or "")
        logger.debug("Win32_Service 不可用（%s），已回退 psutil", error[:120])
        entries = []
        for item in fallback:
            name = _text(item.get("name"), 200)
            if not name:
                continue
            entries.append(
                {
                    "key": f"service:{name.lower()}",
                    "category": "services:psutil",
                    "kind": "service",
                    "name": name,
                    "location": "Windows 服务",
                    "command": _text(item.get("command")),
                    "display_name": _text(item.get("display"), 300),
                    "state": _text(item.get("state"), 80),
                    "start_mode": _text(item.get("start_mode"), 80),
                    "fingerprint": {"command": _text(item.get("command"))},
                }
            )
        if not entries:
            return None, "unavailable", ""
        return entries, "fallback:psutil", "services:psutil"

    def _services_from_psutil(self) -> list[dict[str, Any]] | None:
        try:
            import psutil
        except ImportError:
            return None
        services: list[dict[str, Any]] = []
        try:
            iterator = psutil.win_service_iter()
        except (psutil.Error, OSError):
            return None
        for service in iterator:
            try:
                info = service.as_dict()
            except (psutil.Error, OSError):
                continue
            name = str(info.get("name") or "").strip()
            if not name:
                continue
            services.append(
                {
                    "name": name,
                    "display": str(info.get("display_name") or ""),
                    "command": str(info.get("binpath") or ""),
                    "state": str(info.get("status") or ""),
                    "start_mode": str(info.get("start_type") or ""),
                }
            )
        return services

    # ------------------------------------------------------------------ 基线
    def _baseline_entries_snapshot(self) -> dict[str, Any]:
        stored = self.ctx.baselines.get("autorun")
        if isinstance(stored, dict) and isinstance(stored.get("entries"), dict):
            return stored["entries"]
        return {}

    def _diff_and_match(
        self, entries: list[dict[str, Any]], probed_categories: set[str], now: float
    ) -> tuple[list, float]:
        stored = self.ctx.baselines.get("autorun")
        baseline_entries: dict[str, Any] = {}
        done_categories: set[str] = set()
        baseline_ts = now
        if isinstance(stored, dict):
            if isinstance(stored.get("entries"), dict):
                baseline_entries = dict(stored["entries"])
            if isinstance(stored.get("categories_done"), list):
                done_categories = {str(item) for item in stored["categories_done"]}
            if isinstance(stored.get("ts"), (int, float)):
                baseline_ts = float(stored["ts"])

        findings: list = []
        new_baseline: dict[str, Any] = {}
        for entry in entries:
            key = str(entry.get("key") or "")
            category = str(entry.get("category") or "")
            if not key:
                continue
            fingerprint = entry.get("fingerprint") or {"command": entry.get("command") or ""}
            previous = baseline_entries.get(key)
            category_known = category in done_categories
            is_new = category_known and previous is None
            changed = (
                category_known
                and isinstance(previous, dict)
                and previous.get("fingerprint") != fingerprint
            )
            try:
                hits = self._match_entry(entry, is_new, changed)
            except Exception:  # noqa: BLE001 - 单条持久化项异常不影响其它项
                logger.exception("自启动项规则匹配异常：%s", key)
                hits = []
            for hit in hits:
                if len(findings) >= MAX_FINDINGS_PER_CYCLE:
                    break
                findings.append(
                    hit.finding(
                        sensor=self.id,
                        subject=self._subject(entry),
                        metadata=self._metadata(entry, is_new, changed),
                        dedupe_key=f"autorun:{hit.rule_id}:{key}",
                    )
                )
            new_baseline[key] = {"category": category, "fingerprint": fingerprint}

        # 采集失败的类别保留旧基线，避免临时不可读导致下次整批「新增」告警
        for key, value in baseline_entries.items():
            category = value.get("category") if isinstance(value, dict) else None
            if category not in probed_categories:
                new_baseline.setdefault(key, value)

        new_done = done_categories | probed_categories
        if new_baseline != baseline_entries or new_done != done_categories:
            self.ctx.baselines.set(
                "autorun",
                {
                    "ts": baseline_ts,
                    "entries": new_baseline,
                    "categories_done": sorted(new_done),
                },
            )
        return findings, baseline_ts

    @staticmethod
    def _match_entry(entry: dict[str, Any], is_new: bool, changed: bool) -> list:
        kind = str(entry.get("kind") or "")
        if kind in {"registry", "winlogon"}:
            payload = {
                "name": entry.get("name") or "",
                "location": entry.get("location") or "",
                "command": entry.get("command") or "",
                "kind": kind,
            }
            return rules.match_autorun(payload, is_new=is_new, changed=changed)
        if kind == "startup_file":
            hits: list = []
            path = str(entry.get("path") or "")
            if is_new:
                hits.extend(rules.match_startup_file(path, True))
            if changed:
                hits.extend(rules.match_fileguard("startup_changed", path))
            return hits
        if kind == "scheduled_task":
            return rules.match_scheduled_task(
                str(entry.get("name") or ""),
                str(entry.get("execute") or ""),
                str(entry.get("arguments") or ""),
                is_new=is_new,
                changed=changed,
            )
        if kind == "service":
            return rules.match_service(
                str(entry.get("name") or ""),
                str(entry.get("command") or ""),
                is_new=is_new,
                changed=changed,
            )
        return []

    @staticmethod
    def _subject(entry: dict[str, Any]) -> str:
        kind = str(entry.get("kind") or "")
        name = str(entry.get("name") or "?")
        location = str(entry.get("location") or "")
        if kind == "startup_file":
            return str(entry.get("path") or name)
        if kind == "scheduled_task":
            return f"计划任务 {location}{name}" if location not in {"", "\\", "schtasks"} else f"计划任务 {name}"
        if kind == "service":
            return f"服务 {name}"
        return f"{name} @ {location}" if location else name

    @staticmethod
    def _metadata(entry: dict[str, Any], is_new: bool, changed: bool) -> dict[str, Any]:
        metadata: dict[str, Any] = {
            "kind": str(entry.get("kind") or ""),
            "name": str(entry.get("name") or ""),
            "location": str(entry.get("location") or ""),
            "baseline_state": "new" if is_new else ("changed" if changed else "baseline"),
        }
        for field in ("command", "path", "execute", "arguments", "display_name", "state", "start_mode"):
            value = entry.get(field)
            if value:
                metadata[field] = str(value)[:COMMAND_LIMIT]
        return metadata
