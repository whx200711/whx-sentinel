"""WHX 哨兵 · 应用核心。

负责：加载配置、初始化日志/数据库/传感器/分析管线、维护状态快照、
提供设置与白名单修改、以及开机自启注册（HKCU Run）。
"""

from __future__ import annotations

import ctypes
import importlib
import json
import logging
import logging.handlers
import os
import shutil
import sys
import threading
import time
from pathlib import Path
from typing import Any

import ai
import config
import respond
import rules_data
import winutil
from analyst import Analyst
from db import Database
from events import SEVERITIES
from sensors.base import BaselineStore, Sensor, SensorContext

logger = logging.getLogger("whx.sentinel.core")

RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
AUTOSTART_VALUE = "WHX Sentinel"

# 传感器类名不固定，按模块内 Sensor 子类自动发现，方便独立开发/替换
SENSOR_MODULES = (
    "sensors.defender",
    "sensors.eventlog",
    "sensors.process",
    "sensors.network",
    "sensors.autorun",
    "sensors.fileguard",
    "sensors.exposure",
)

PUBLIC_SETTINGS_KEYS = (
    "ai_enabled",
    "ai_model",
    "toast_enabled",
    "toast_min_severity",
    "auto_quick_scan_on_malware",
    "auto_block_high_remote",
    "retention_days",
    "max_events",
    "canary_enabled",
)

INTERVAL_SETTING_TO_ATTR = {
    "process_interval_s": "process",
    "network_interval_s": "network",
    "autorun_interval_s": "autorun",
    "eventlog_interval_s": "eventlog",
    "defender_interval_s": "defender",
    "fileguard_interval_s": "fileguard",
    "exposure_interval_s": "exposure",
}


class _MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def _memory_mb() -> dict[str, int]:
    try:
        status = _MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))
        return {
            "total": int(status.ullTotalPhys // (1024 * 1024)),
            "available": int(status.ullAvailPhys // (1024 * 1024)),
        }
    except Exception:  # noqa: BLE001 - 仅展示用
        return {"total": 0, "available": 0}


def discover_sensors(ctx: SensorContext) -> list[Sensor]:
    sensors: list[Sensor] = []
    for module_name in SENSOR_MODULES:
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:  # noqa: BLE001 - 单个传感器缺失不应导致整体不可用
            logger.warning("传感器模块 %s 加载失败：%s", module_name, exc)
            continue
        instances: list[Sensor] = []
        for attr in dir(module):
            if attr.startswith("_"):
                continue
            candidate = getattr(module, attr)
            if (
                isinstance(candidate, type)
                and issubclass(candidate, Sensor)
                and candidate is not Sensor
                and candidate.__module__ == module.__name__
            ):
                try:
                    instances.append(candidate(ctx))
                except Exception:  # noqa: BLE001
                    logger.exception("传感器 %s.%s 初始化失败", module_name, attr)
        if not instances:
            logger.warning("传感器模块 %s 中没有找到 Sensor 子类", module_name)
        sensors.extend(instances)
    sensors.sort(key=lambda item: item.initial_delay)
    return sensors


class SentinelCore:
    def __init__(self, data_dir: str | Path | None = None, port: int | None = None):
        if data_dir:
            config.configure(data_dir)
        config.ensure_dirs()
        self.cfg: dict[str, Any] = config.load_config()
        if port:
            self.cfg["port"] = int(port)
        winutil.set_internal_marker(str(self.cfg.get("internal_marker") or ""))
        self.data_dir = config.DATA_DIR
        self.started_at = time.time()
        self._setup_logging()

        self.db = Database(config.DB_PATH)
        self.baselines = BaselineStore(config.BASELINE_PATH)
        self.ctx = SensorContext(
            self.cfg, self.db, self.data_dir, self.ingest, self.baselines
        )
        self.analyst = Analyst(self)
        self.sensors = discover_sensors(self.ctx)
        self.uvicorn_server: Any = None
        self._stop = threading.Event()
        self._maintenance_thread: threading.Thread | None = None
        self._started = False
        self._last_prune = 0.0
        logger.info(
            "哨兵初始化：版本 %s | 数据目录 %s | 管理员权限 %s | 传感器 %s 个",
            config.VERSION,
            self.data_dir,
            self.ctx.is_admin,
            len(self.sensors),
        )
        for sensor in self.sensors:
            logger.info("  - 传感器 %-10s %s", sensor.id, sensor.name)

    # ------------------------------------------------------------------ 日志
    def _setup_logging(self) -> None:
        root = logging.getLogger("whx.sentinel")
        root.setLevel(logging.INFO)
        root.propagate = False
        if root.handlers:
            return
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S"
        )
        handler: logging.Handler | None = None
        try:
            handler = logging.handlers.RotatingFileHandler(
                config.LOG_DIR / "sentinel.log",
                maxBytes=2_000_000,
                backupCount=3,
                encoding="utf-8",
            )
            handler.setFormatter(formatter)
            root.addHandler(handler)
        except OSError:
            handler = None
        if sys.stdout is not None:
            console = logging.StreamHandler(sys.stdout)
            console.setFormatter(formatter)
            root.addHandler(console)
        # uvicorn 在 pythonw 下没有 stderr，把它的日志也收进文件
        system_root = logging.getLogger()
        system_root.setLevel(logging.INFO)
        if handler is not None and handler not in system_root.handlers:
            system_root.addHandler(handler)
        for noisy in ("httpx", "httpcore", "uvicorn", "uvicorn.error", "uvicorn.access", "asyncio"):
            logging.getLogger(noisy).setLevel(logging.WARNING)

    # ------------------------------------------------------------------ 生命周期
    def start(self) -> None:
        if self._started:
            return
        self.db.init()
        self.analyst.start()
        for sensor in self.sensors:
            sensor.start()
        self._maintenance_thread = threading.Thread(
            target=self._maintenance_loop, name="sentinel-maintenance", daemon=True
        )
        self._maintenance_thread.start()
        self._started = True
        logger.info("哨兵已启动：http://127.0.0.1:%s/", self.cfg["port"])

    def stop(self) -> None:
        if not self._started:
            return
        logger.info("哨兵正在停止…")
        self._stop.set()
        for sensor in self.sensors:
            sensor.stop()
        self.analyst.stop()
        self._started = False
        try:
            self.db.close()
        except Exception:  # noqa: BLE001
            pass
        logger.info("哨兵已停止")

    def request_shutdown(self) -> None:
        """Ask the uvicorn server (or the process) to exit gracefully."""

        server = self.uvicorn_server
        if server is not None:
            try:
                server.should_exit = True
                return
            except Exception:  # noqa: BLE001
                pass
        self._stop.set()

    def _maintenance_loop(self) -> None:
        while not self._stop.wait(30):
            try:
                now = time.time()
                if now - self._last_prune > 3600:
                    self._last_prune = now
                    self.db.prune(
                        int(self.cfg.get("retention_days") or 30),
                        int(self.cfg.get("max_events") or 20000),
                    )
            except Exception:  # noqa: BLE001
                logger.exception("维护任务失败")

    # ------------------------------------------------------------------ 入口
    def ingest(self, findings: list) -> None:
        self.analyst.ingest(findings)

    # ------------------------------------------------------------------ 状态
    def public_settings(self) -> dict[str, Any]:
        settings = {key: self.cfg.get(key) for key in PUBLIC_SETTINGS_KEYS}
        allowlist = dict(self.cfg.get("allowlist") or {})
        marker = str(self.cfg.get("internal_marker") or "")
        markers = [item for item in (allowlist.get("cmdline_contains") or []) if item != marker]
        allowlist["cmdline_contains"] = markers
        settings["allowlist"] = allowlist
        settings["ollama_url"] = self.cfg.get("ollama_url")
        return settings

    def _fallback_host(self) -> dict[str, Any]:
        memory = _memory_mb()
        try:
            disk = shutil.disk_usage("C:\\")
            disk_free = round(disk.free / (1024 ** 3), 1)
        except OSError:
            disk_free = None
        os_info = winutil.windows_version()
        return {
            "os": os_info.get("name", "Windows"),
            "os_build": os_info.get("build", ""),
            "uptime_s": round(winutil.machine_uptime_s()),
            "ram_total_mb": memory["total"],
            "ram_available_mb": memory["available"],
            "disk_free_gb": disk_free,
            "cpu_count": os.cpu_count() or 0,
            "user": winutil.username(),
            "hostname": winutil.hostname(),
            "elevated": self.ctx.is_admin,
        }

    def status(self) -> dict[str, Any]:
        shared = self.ctx.shared
        host = shared.get("host") or self._fallback_host()
        defender = shared.get("defender") or {
            "available": False,
            "source": "not-collected",
            "checked_at": 0.0,
        }
        firewall_raw = defender.get("firewall") or {"available": False}
        firewall = dict(firewall_raw) if isinstance(firewall_raw, dict) else {"available": False}
        if firewall.get("available"):
            profiles = [firewall.get(key) for key in ("domain", "private", "public")]
            known = [item for item in profiles if isinstance(item, bool)]
            firewall["enabled"] = all(known) if known else None
        else:
            firewall["enabled"] = None
        exposure = shared.get("exposure") or {"checks": [], "checked_at": 0.0}
        stats = self.db.stats(24)
        analyst = self.analyst.status()
        stats["ai"] = {
            "done": stats.get("ai_done", 0),
            "pending": analyst.get("queue", 0),
            "engine": (analyst.get("last_ai") or {}).get("engine") or "",
            "model": self.cfg.get("ai_model"),
            "available": analyst.get("available", False),
        }
        return {
            "app": config.APP_ID,
            "version": config.VERSION,
            "uptime_s": round(time.time() - self.started_at),
            "elevated": bool(self.ctx.is_admin),
            "host": host,
            "sensors": [sensor.snapshot() for sensor in self.sensors],
            "stats": stats,
            "defender": defender,
            "firewall": firewall,
            "exposure": exposure,
            "settings": self.public_settings(),
            "db": {
                "path": str(config.DB_PATH),
                "size_mb": self.db.size_mb(),
                "events": self.db.count(),
            },
            "autostart": self.autostart_state(),
            "ai": {
                "enabled": bool(self.cfg.get("ai_enabled")),
                "model": self.cfg.get("ai_model"),
                "available": analyst.get("available", False),
                "queue": analyst.get("queue", 0),
            },
            "network": shared.get("network") or {},
            "autorun": shared.get("autorun") or {},
            "process": {
                "count": shared.get("process_count"),
                "scan_ts": shared.get("process_scan_ts"),
            },
            "last_toast": analyst.get("last_toast"),
            "checked_at": time.time(),
        }

    # ------------------------------------------------------------------ 设置
    BOOL_SETTINGS = {
        "ai_enabled",
        "toast_enabled",
        "auto_quick_scan_on_malware",
        "auto_block_high_remote",
        "canary_enabled",
    }
    INT_SETTINGS = {
        "retention_days": (1, 365),
        "max_events": (1000, 200000),
        "ai_cooldown_s": (60, 86400),
    }
    STR_SETTINGS = {"ai_model", "toast_min_severity", "ollama_url"}

    def update_settings(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("设置必须是 JSON 对象")
        errors: list[str] = []
        for key, value in payload.items():
            if key in self.BOOL_SETTINGS:
                self.cfg[key] = bool(value)
            elif key in self.INT_SETTINGS:
                low, high = self.INT_SETTINGS[key]
                try:
                    number = int(value)
                except (TypeError, ValueError):
                    errors.append(f"{key} 必须是整数")
                    continue
                self.cfg[key] = max(low, min(high, number))
            elif key == "ai_model":
                text = str(value or "").strip()
                if not text or len(text) > 100:
                    errors.append("ai_model 无效")
                    continue
                self.cfg[key] = text
            elif key == "toast_min_severity":
                text = str(value or "").upper()
                if text not in SEVERITIES:
                    errors.append("toast_min_severity 无效")
                    continue
                self.cfg[key] = text
            elif key == "ollama_url":
                try:
                    self.cfg[key] = config.validate_ollama_url(value)
                except ValueError:
                    errors.append("ollama_url 只允许本机回环地址（127.0.0.1 / localhost / ::1）")
                    continue
            elif key == "allowlist":
                self.cfg["allowlist"] = self._validate_allowlist(value)
            elif key in INTERVAL_SETTING_TO_ATTR:
                try:
                    number = float(value)
                except (TypeError, ValueError):
                    errors.append(f"{key} 必须是数字")
                    continue
                number = max(1.0, min(3600.0 * 6, number))
                self.cfg[key] = number
                self._apply_interval(key, number)
            # 其它键忽略（不开放任意配置写入）
        config.save_config(self.cfg)
        if errors:
            logger.info("设置部分更新失败：%s", "; ".join(errors))
        return {"settings": self.public_settings(), "errors": errors}

    def _apply_interval(self, key: str, value: float) -> None:
        sensor_id = INTERVAL_SETTING_TO_ATTR.get(key)
        for sensor in self.sensors:
            if sensor.id == sensor_id:
                sensor.interval = value

    def _validate_allowlist(self, value: Any) -> dict[str, list[str]]:
        current = self.cfg.get("allowlist") or {}
        result: dict[str, list[str]] = {}
        allowed_keys = set(config.DEFAULT_ALLOWLIST) | {"suppress_rules"}
        if isinstance(value, dict):
            for kind, entries in value.items():
                if kind not in allowed_keys or not isinstance(entries, list):
                    continue
                cleaned: list[str] = []
                for entry in entries[:200]:
                    text = str(entry).strip()
                    if text and text not in cleaned:
                        cleaned.append(text[:300])
                result[kind] = cleaned
            for kind in allowed_keys:
                if kind not in result:
                    result[kind] = list(current.get(kind) or [])
        return result

    def allowlist_change(self, payload: dict[str, Any]) -> dict[str, Any]:
        action = str(payload.get("action") or "").lower()
        kind = str(payload.get("kind") or "").strip()
        value = str(payload.get("value") or "").strip()
        allowed_kinds = set(config.DEFAULT_ALLOWLIST) | {"suppress_rules"}
        if kind not in allowed_kinds:
            return {"ok": False, "message": f"未知白名单类型：{kind}"}
        if not value:
            return {"ok": False, "message": "白名单值不能为空"}
        allowlist = dict(self.cfg.get("allowlist") or {})
        for key in allowed_kinds:
            allowlist.setdefault(key, [])
        items = list(allowlist.get(kind) or [])
        if action == "add":
            if value not in items:
                items.append(value[:300])
        elif action == "remove":
            items = [item for item in items if item != value]
        else:
            return {"ok": False, "message": "action 必须是 add 或 remove"}
        allowlist[kind] = items[:200]
        self.cfg["allowlist"] = allowlist
        config.save_config(self.cfg)
        logger.info("白名单更新：%s %s %s", action, kind, value)
        return {"ok": True, "message": "白名单已更新", "allowlist": allowlist}

    def reset_baselines(self) -> None:
        for key in ("autorun", "listeners", "defender_exclusions"):
            self.baselines.set(key, None, save=False)
        self.baselines.set("baseline_reset_ts", time.time())
        try:
            self.db.set_meta("baseline_reset_ts", time.time())
        except Exception:  # noqa: BLE001
            pass
        logger.info("用户重置了自启动/监听/排除项基线")

    # ------------------------------------------------------------------ 自启动
    def _autostart_command(self) -> str:
        entry = Path(config.BASE_DIR) / "sentinel.py"
        return f'"{winutil.system_pythonw()}" "{entry}" --daemon'

    def autostart_state(self) -> dict[str, Any]:
        command = self._autostart_command()
        value = winutil.registry_value("HKEY_CURRENT_USER", RUN_KEY_PATH, AUTOSTART_VALUE)
        return {
            "enabled": bool(value),
            "value": str(value or ""),
            "expected": command,
            "scope": "当前用户（HKCU Run，登录时自动启动）",
        }

    def install_autostart(self) -> dict[str, Any]:
        if not winutil.IS_WINDOWS:
            return {"ok": False, "message": "仅支持 Windows"}
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_SET_VALUE
            ) as key:
                winreg.SetValueEx(key, AUTOSTART_VALUE, 0, winreg.REG_SZ, self._autostart_command())
            logger.info("已注册开机自启动：%s", self._autostart_command())
            return {"ok": True, "message": "已注册登录自启动", **self.autostart_state()}
        except OSError as exc:
            logger.warning("注册自启动失败：%s", exc)
            return {"ok": False, "message": f"注册自启动失败：{exc}"}

    def uninstall_autostart(self) -> dict[str, Any]:
        if not winutil.IS_WINDOWS:
            return {"ok": False, "message": "仅支持 Windows"}
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_SET_VALUE
            ) as key:
                try:
                    winreg.DeleteValue(key, AUTOSTART_VALUE)
                except FileNotFoundError:
                    pass
            logger.info("已移除开机自启动")
            return {"ok": True, "message": "已移除登录自启动", **self.autostart_state()}
        except OSError as exc:
            return {"ok": False, "message": f"移除自启动失败：{exc}"}

    # ------------------------------------------------------------------ 其它
    def web_url(self) -> str:
        return f"http://127.0.0.1:{int(self.cfg.get('port') or config.DEFAULT_PORT)}/"

    def is_elevated(self) -> bool:
        return bool(self.ctx.is_admin)

    def ai_status(self) -> dict[str, Any]:
        return {
            "enabled": bool(self.cfg.get("ai_enabled")),
            "model": self.cfg.get("ai_model"),
            "available": bool(self.analyst.ai_available),
            "queue": self.analyst._ai_queue.qsize(),
        }
