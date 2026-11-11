"""WHX 哨兵 · 安全配置暴露面传感器。

只读取注册表 / 本机资源做体检，不修改任何配置：

- RDP：HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server 的 fDenyTSConnections；
- SMBv1：LanmanServer\\Parameters 的 SMB1 与 mrxsmb10 服务启动类型（4=禁用）；
- UAC：HKLM\\...\\Policies\\System 的 EnableLUA（0=关闭）；
- Secure Boot：HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State 的 UEFISecureBootEnabled；
- 自动播放：HKCU（回退 HKLM）AutoplayHandlers 的 DisableAutoplay（0=开启）。

active 的检查项调用 rules.match_exposure 产生 finding（12 小时去重窗口），
并把主机信息写入 ctx.shared["host"]、体检结果写入 ctx.shared["exposure"]。
注册表读不到时跳过该项，不误报、不崩溃。
"""

from __future__ import annotations

import logging
import os
import shutil
import time
from typing import Any

import rules
import rules_data
import winutil
from sensors.base import Sensor

logger = logging.getLogger("whx.sentinel.sensor.exposure")

CHECK_IDS = (
    "exposure.rdp_enabled",
    "exposure.smb1_enabled",
    "exposure.uac_disabled",
    "exposure.secureboot_off",
    "exposure.autoplay_enabled",
)


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------
def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _reg(root_name: str, path: str, value_name: str) -> Any:
    try:
        return winutil.registry_value(root_name, path, value_name)
    except Exception:  # noqa: BLE001 - 不可读按未知处理
        return None


def _result(check_id: str, active: bool, detail: str, value: Any) -> dict[str, Any]:
    rule = rules_data.EXPOSURE_CHECKS.get(check_id) or {}
    return {
        "id": check_id,
        "active": bool(active),
        "title": str(rule.get("title") or check_id),
        "severity": str(rule.get("severity") or "LOW"),
        "detail": detail,
        "value": value,
    }


class ExposureSensor(Sensor):
    id = "exposure"
    name = "安全配置"
    description = "体检 RDP / SMBv1 / UAC / Secure Boot / 自动播放等暴露面配置，并采集主机信息"
    interval_key = "exposure_interval_s"
    default_interval = 1800.0
    initial_delay = 20.0
    requires_admin = False

    # ------------------------------------------------------------------ 采集
    def collect(self) -> list:
        try:
            return self._collect()
        except Exception:  # noqa: BLE001 - 传感器不允许抛异常
            logger.exception("安全配置传感器采集异常")
            self.capability = "degraded"
            return []

    def _collect(self) -> list:
        now = time.time()
        findings: list = []
        checks: list[dict[str, Any]] = []
        unknown: list[str] = []

        readers = (
            ("exposure.rdp_enabled", self._check_rdp),
            ("exposure.smb1_enabled", self._check_smb1),
            ("exposure.uac_disabled", self._check_uac),
            ("exposure.secureboot_off", self._check_secureboot),
            ("exposure.autoplay_enabled", self._check_autoplay),
        )
        for check_id, reader in readers:
            try:
                result = reader()
            except Exception:  # noqa: BLE001 - 单项失败不影响其它检查
                logger.debug("安全配置检查失败：%s", check_id, exc_info=True)
                result = None
            if result is None:
                unknown.append(check_id)
                continue
            checks.append(result)
            if not result.get("active"):
                continue
            try:
                hits = rules.match_exposure(check_id, True, str(result.get("detail") or ""))
            except Exception:  # noqa: BLE001
                logger.exception("暴露面规则匹配异常：%s", check_id)
                continue
            for hit in hits:
                findings.append(
                    hit.finding(
                        sensor=self.id,
                        subject=str(result.get("title") or check_id),
                        metadata={
                            "check_id": check_id,
                            "value": result.get("value"),
                            "detail": result.get("detail"),
                            "active": True,
                        },
                        dedupe_key=f"exposure:{check_id}",
                    )
                )

        host = self._host_info()
        self.ctx.shared["host"] = host
        self.ctx.shared["exposure"] = {
            "checks": [
                {
                    "id": item["id"],
                    "active": bool(item["active"]),
                    "title": item["title"],
                    "severity": item["severity"],
                }
                for item in checks
            ],
            "checked_at": now,
            "unknown": unknown,
        }
        if len(checks) >= 3:
            self.capability = "ok"
        elif checks:
            self.capability = "degraded"
        else:
            self.capability = "unavailable"
        if findings:
            self.ctx.shared["exposure"]["last_alert_ts"] = now
        return findings

    # ------------------------------------------------------------------ 检查项
    def _check_rdp(self) -> dict[str, Any] | None:
        value = _to_int(
            _reg(
                "HKEY_LOCAL_MACHINE",
                r"SYSTEM\CurrentControlSet\Control\Terminal Server",
                "fDenyTSConnections",
            )
        )
        if value is None:
            return None
        active = value == 0
        detail = (
            f"fDenyTSConnections={value}（0 表示允许远程桌面连接）。"
            if active
            else f"fDenyTSConnections={value}，远程桌面已禁用。"
        )
        return _result("exposure.rdp_enabled", active, detail, value)

    def _check_smb1(self) -> dict[str, Any] | None:
        server = _to_int(
            _reg(
                "HKEY_LOCAL_MACHINE",
                r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                "SMB1",
            )
        )
        client = _to_int(
            _reg("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start")
        )
        if server is None and client is None:
            return None
        active = (server == 1) or (client is not None and client != 4)
        detail = (
            f"LanmanServer.SMB1={server if server is not None else '未设置'}，"
            f"mrxsmb10.Start={client if client is not None else '不存在'}"
            "（SMB1=1 或 mrxsmb10 启动类型非 4 表示 SMBv1 可用）。"
        )
        return _result("exposure.smb1_enabled", active, detail, {"server": server, "client_start": client})

    def _check_uac(self) -> dict[str, Any] | None:
        value = _to_int(
            _reg(
                "HKEY_LOCAL_MACHINE",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "EnableLUA",
            )
        )
        if value is None:
            return None
        active = value == 0
        detail = f"EnableLUA={value}（0 表示用户账户控制已关闭）。"
        return _result("exposure.uac_disabled", active, detail, value)

    def _check_secureboot(self) -> dict[str, Any] | None:
        value = _to_int(
            _reg(
                "HKEY_LOCAL_MACHINE",
                r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
                "UEFISecureBootEnabled",
            )
        )
        if value is None:
            return None
        active = value == 0
        detail = f"UEFISecureBootEnabled={value}（0 表示安全启动未开启）。"
        return _result("exposure.secureboot_off", active, detail, value)

    def _check_autoplay(self) -> dict[str, Any] | None:
        value = _to_int(
            _reg(
                "HKEY_CURRENT_USER",
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers",
                "DisableAutoplay",
            )
        )
        source = "HKCU"
        if value is None:
            value = _to_int(
                _reg(
                    "HKEY_LOCAL_MACHINE",
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers",
                    "DisableAutoplay",
                )
            )
            source = "HKLM"
        if value is None:
            return None
        active = value == 0
        detail = f"{source} DisableAutoplay={value}（0 表示自动播放未被禁用）。"
        return _result("exposure.autoplay_enabled", active, detail, value)

    # ------------------------------------------------------------------ 主机信息
    def _host_info(self) -> dict[str, Any]:
        version = winutil.windows_version()
        os_name = str(version.get("name") or "Windows")
        build = str(version.get("build") or "")

        uptime = winutil.machine_uptime_s()
        if not uptime:
            try:
                import psutil

                uptime = max(0.0, time.time() - float(psutil.boot_time()))
            except Exception:  # noqa: BLE001
                uptime = 0.0
        ram_total, ram_available = self._memory_mb()
        return {
            "os": os_name,
            "os_build": build,
            "uptime_s": round(float(uptime), 1),
            "ram_total_mb": ram_total,
            "ram_available_mb": ram_available,
            "disk_free_gb": self._disk_free_gb(),
            "cpu_count": int(os.cpu_count() or 0),
            "user": winutil.username(),
            "hostname": winutil.hostname(),
            "elevated": bool(self.ctx.is_admin or winutil.is_admin()),
        }

    @staticmethod
    def _memory_mb() -> tuple[int, int]:
        try:
            import psutil

            memory = psutil.virtual_memory()
            return int(memory.total // 1048576), int(memory.available // 1048576)
        except Exception:  # noqa: BLE001 - psutil 缺失时走 ctypes
            pass
        try:
            import ctypes

            class _MemoryStatusEx(ctypes.Structure):
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

            status = _MemoryStatusEx()
            status.dwLength = ctypes.sizeof(_MemoryStatusEx)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return int(status.ullTotalPhys // 1048576), int(status.ullAvailPhys // 1048576)
        except Exception:  # noqa: BLE001
            pass
        return 0, 0

    @staticmethod
    def _disk_free_gb() -> float:
        drive = (os.environ.get("SystemDrive") or "C:") + "\\"
        try:
            usage = shutil.disk_usage(drive)
        except OSError:
            return 0.0
        return round(usage.free / (1024**3), 1)
