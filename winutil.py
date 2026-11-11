"""WHX 哨兵 · Windows 通用工具（进程 / PowerShell / 注册表 / 文件哈希）。"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

FALLBACK_INTERNAL_MARKER = "WHX_SENTINEL_INTERNAL"
_INTERNAL_MARKER = FALLBACK_INTERNAL_MARKER


def set_internal_marker(marker: str) -> None:
    """由 SentinelCore 在加载配置后设置；每个安装随机不同，避免开源后变成公开免检口令。"""

    global _INTERNAL_MARKER
    text = str(marker or "").strip()
    _INTERNAL_MARKER = text or FALLBACK_INTERNAL_MARKER


def internal_marker() -> str:
    return _INTERNAL_MARKER
IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if IS_WINDOWS else 0

_POWERSHELL = shutil.which("powershell.exe") or shutil.which("powershell") or "powershell.exe"

_PS_PRELUDE = (
    "$ProgressPreference='SilentlyContinue'; "
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
    "$ErrorActionPreference='Continue'; "
)


class ProbeError(RuntimeError):
    """A PowerShell/registry probe could not produce usable output."""


def is_admin() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 - best effort
        return False


def powershell_available() -> bool:
    return shutil.which(_POWERSHELL) is not None or Path(_POWERSHELL).is_file()


def run_ps_text(script: str, timeout: float = 25.0) -> str:
    """Run a PowerShell script hidden from the desktop and return its stdout."""

    if not IS_WINDOWS:
        raise ProbeError("PowerShell 探针仅支持 Windows")
    command = f"{_PS_PRELUDE}{script} # {internal_marker()}"
    try:
        completed = subprocess.run(
            [
                _POWERSHELL,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command,
            ],
            capture_output=True,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
    except subprocess.TimeoutExpired as exc:
        raise ProbeError(f"PowerShell 探针超时（{timeout:.0f}s）") from exc
    except OSError as exc:
        raise ProbeError(f"无法启动 PowerShell：{exc}") from exc
    stdout = completed.stdout.decode("utf-8", "replace").strip()
    if completed.returncode != 0 and not stdout:
        stderr = completed.stderr.decode("utf-8", "replace").strip()
        raise ProbeError(stderr[:400] or f"PowerShell 退出码 {completed.returncode}")
    return stdout


def run_ps_json(script: str, timeout: float = 25.0) -> Any:
    """Run PowerShell and parse the last JSON blob printed by ConvertTo-Json."""

    script = script.strip().rstrip(";")
    stdout = run_ps_text(f"{script} | ConvertTo-Json -Depth 7 -Compress", timeout=timeout)
    if not stdout:
        raise ProbeError("PowerShell 探针没有输出")
    import json

    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ProbeError(f"PowerShell 输出不是合法 JSON：{stdout[:200]}") from exc


def ps_quote(value: str) -> str:
    """Quote a value for a single-quoted PowerShell literal."""

    return "'" + str(value).replace("'", "''") + "'"


def spawn_hidden(args: list[str], cwd: str | None = None) -> subprocess.Popen:
    """Start a detached helper (Defender scan, browser ...) without a console."""

    return subprocess.Popen(
        args,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=CREATE_NO_WINDOW if IS_WINDOWS else 0,
    )


def run_powershell_detached(script: str) -> None:
    """Run a PowerShell one-liner in the background; used for long actions."""

    command = f"{_PS_PRELUDE}{script} # {internal_marker()}"
    spawn_hidden(
        [
            _POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-WindowStyle",
            "Hidden",
            "-Command",
            command,
        ]
    )


def hash_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_signature(path: str | Path) -> dict[str, Any]:
    """Cheap metadata + content hash used by the file guard."""

    target = Path(path)
    try:
        stat = target.stat()
    except OSError as exc:
        return {"path": str(target), "exists": False, "error": str(exc)}
    return {
        "path": str(target),
        "exists": True,
        "size": stat.st_size,
        "mtime": stat.st_mtime,
        "hash": hash_file(target),
    }


def hostname() -> str:
    return os.environ.get("COMPUTERNAME") or "."


def username() -> str:
    return os.environ.get("USERNAME") or "."


def user_home() -> Path:
    return Path(os.environ.get("USERPROFILE") or str(Path.home()))


def temp_dirs() -> list[Path]:
    """Directories that normal software almost never executes programs from."""

    home = user_home()
    candidates = [
        Path(tempfile.gettempdir()),
        home / "AppData" / "Local" / "Temp",
        home / "Downloads",
        Path(os.environ.get("PUBLIC") or "C:/Users/Public"),
        # 注意：不要把 AppData\Roaming 整体算进来——微信、Code 等正常程序会从
        # 这里启动，会把正常行为误报成「临时目录执行」。只保留真正的临时/下载区。
    ]
    seen: list[Path] = []
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved not in seen and resolved.is_dir():
            seen.append(resolved)
    return seen


def path_under(path: str | Path, roots: list[Path]) -> bool:
    try:
        target = Path(path).resolve()
    except (OSError, ValueError):
        return False
    for root in roots:
        try:
            target.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(str(value).split("%", 1)[0])
    except ValueError:
        return False
    return bool(address.is_global)


def is_loopback_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(str(value).split("%", 1)[0])
    except ValueError:
        return False
    return bool(address.is_loopback) or bool(address.is_link_local)


def ip_in_entries(ip: str, entries: list[str]) -> bool:
    """Match an IP against a list of IPs/CIDRs (fail closed on bad entries)."""

    try:
        address = ipaddress.ip_address(str(ip).split("%", 1)[0])
    except ValueError:
        return False
    for entry in entries:
        text = str(entry).strip()
        if not text:
            continue
        try:
            if address in ipaddress.ip_network(text, strict=False):
                return True
        except ValueError:
            continue
    return False


def windows_version() -> dict[str, str]:
    """Read the Windows product info from HKLM (no admin required)."""

    if not IS_WINDOWS:
        return {"name": os.uname().sysname if hasattr(os, "uname") else "Unknown"}
    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        )
        try:
            values = {}
            for name in ("ProductName", "DisplayVersion", "CurrentBuild", "UBR", "EditionID"):
                try:
                    values[name] = str(winreg.QueryValueEx(key, name)[0])
                except OSError:
                    continue
            name = values.get("ProductName", "Windows")
            build = values.get("CurrentBuild", "")
            ubr = values.get("UBR", "")
            version = values.get("DisplayVersion", "")
            label = f"{name} {version}".strip()
            if build:
                label += f" (build {build}.{ubr})" if ubr else f" (build {build})"
            return {"name": label, "build": build, "version": version}
        finally:
            winreg.CloseKey(key)
    except OSError:
        return {"name": "Windows"}


_REGISTRY_ROOTS = {
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE",
    "HKCU": "HKEY_CURRENT_USER",
    "HKEY_CURRENT_USER": "HKEY_CURRENT_USER",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKEY_CLASSES_ROOT": "HKEY_CLASSES_ROOT",
    "HKU": "HKEY_USERS",
    "HKEY_USERS": "HKEY_USERS",
    "HKCC": "HKEY_CURRENT_CONFIG",
    "HKEY_CURRENT_CONFIG": "HKEY_CURRENT_CONFIG",
}


def registry_value(root_name: str, path: str, value_name: str) -> Any:
    """读取注册表值；支持 HKLM/HKCU 短名，失败返回 None。"""

    if not IS_WINDOWS:
        return None
    try:
        import winreg

        canonical = _REGISTRY_ROOTS.get(str(root_name).strip().upper())
        if not canonical:
            return None
        root = getattr(winreg, canonical, None)
        if root is None:  # 极少数解释器没有全部根键
            return None
        with winreg.OpenKey(root, path) as key:
            return winreg.QueryValueEx(key, value_name)[0]
    except (OSError, AttributeError, ValueError):
        return None


def now() -> float:
    return time.time()


def human_uptime(seconds: float) -> str:
    seconds = max(0, int(seconds))
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    parts = []
    if days:
        parts.append(f"{days} 天")
    if hours:
        parts.append(f"{hours} 小时")
    parts.append(f"{minutes} 分钟")
    return " ".join(parts)


def machine_uptime_s() -> float:
    if not IS_WINDOWS:
        return 0.0
    try:
        import ctypes

        return ctypes.windll.kernel32.GetTickCount64() / 1000.0
    except Exception:  # noqa: BLE001 - best effort
        return 0.0


def system_pythonw() -> str:
    """Path to pythonw.exe for the *current* interpreter (autostart entry)."""

    executable = Path(sys.executable)
    candidate = executable.with_name("pythonw.exe")
    if candidate.is_file():
        return str(candidate)
    return str(executable)
