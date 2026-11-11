"""WHX 哨兵 · 文件完整性传感器（hosts 文件 + 勒索诱饵文件）。

监控点：

1. C:\\Windows\\System32\\drivers\\etc\\hosts 的 SHA-256：
   首次运行只保存基线 fileguard_hosts，之后哈希变化 →
   rules.match_fileguard("hosts_changed", ...)；
2. 勒索诱饵：canary_enabled 为真时在
   %USERPROFILE%\\Documents\\WHX-Sentinel-Canary\\ 下创建 3 个带随机标记的
   诱饵文本文件，基线 canary 保存标记与哈希；每次校验存在性与哈希，
   被修改 / 被删除 → match_fileguard("canary_changed" / "canary_missing")，
   并尝试用原内容恢复，保证后续还能继续监控。

只读 + 仅在自己创建的诱饵目录里写入，不碰系统文件、不联网。
"""

from __future__ import annotations

import logging
import secrets
import time
from pathlib import Path
from typing import Any

import rules
import winutil
from sensors.base import Sensor

logger = logging.getLogger("whx.sentinel.sensor.fileguard")

HOSTS_PATH = Path(r"C:\Windows\System32\drivers\etc\hosts")
CANARY_FILES = ("canary-1.txt", "canary-2.txt", "canary-3.txt")
CANARY_DIR_NAME = "WHX-Sentinel-Canary"
ALERT_MIN_INTERVAL_S = 3600.0
CANARY_MARKER_BYTES = 16
CANARY_TEMPLATE = """WHX Sentinel 勒索诱饵文件
=============================
这是 WHX 哨兵创建的诱饵文件，不是你的文档。
如果它被修改或删除，可能说明有程序在批量加密/删除文件。
标记: {marker}
"""


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------
def _hash_file(path: Path) -> str:
    try:
        return str(winutil.hash_file(path))
    except (OSError, ValueError):
        return ""


def _canary_content(marker: str) -> str:
    return CANARY_TEMPLATE.format(marker=marker)


class FileGuardSensor(Sensor):
    id = "fileguard"
    name = "文件完整性"
    description = "监控 hosts 文件哈希与勒索诱饵文件，发现篡改、删除行为"
    interval_key = "fileguard_interval_s"
    default_interval = 60.0
    initial_delay = 12.0
    requires_admin = False

    def __init__(self, ctx):
        super().__init__(ctx)
        # 告警节流（恢复失败时避免每 60 秒重复刷同一条）
        self._last_alert: dict[str, float] = {}

    # ------------------------------------------------------------------ 采集
    def collect(self) -> list:
        try:
            return self._collect()
        except Exception:  # noqa: BLE001 - 传感器不允许抛异常
            logger.exception("文件完整性传感器采集异常")
            self.capability = "degraded"
            return []

    def _collect(self) -> list:
        now = time.time()
        findings: list = []

        hosts_ok = self._check_hosts(findings)
        canary_ok, canary_error = self._check_canary(findings, now)

        if hosts_ok and canary_ok:
            self.capability = "ok"
        elif hosts_ok or canary_ok:
            self.capability = "degraded"
        else:
            self.capability = "unavailable"
        if canary_error:
            self.ctx.shared.setdefault("canary", {})["error"] = canary_error[:300]
        if findings:
            self.ctx.shared["fileguard"] = {
                "last_alert_ts": now,
                "findings": len(findings),
            }
        self._prune_alerts(now)
        return findings

    # ------------------------------------------------------------------ hosts
    def _hosts_path(self) -> Path:
        override = self.ctx.cfg.get("fileguard_hosts_path")
        return Path(str(override)) if override else HOSTS_PATH

    def _check_hosts(self, findings: list) -> bool:
        path = self._hosts_path()
        try:
            signature = winutil.file_signature(path)
        except (OSError, ValueError) as exc:
            logger.debug("hosts 文件读取失败：%s", exc)
            self.ctx.shared["fileguard_hosts"] = {"path": str(path), "readable": False, "error": str(exc)[:200]}
            return False

        self.ctx.shared["fileguard_hosts"] = {
            "path": str(path),
            "readable": bool(signature.get("exists")),
            "size": signature.get("size"),
            "checked_at": time.time(),
        }
        if not signature.get("exists"):
            return False
        current_hash = str(signature.get("hash") or "")
        if not current_hash:
            return False

        stored = self.ctx.baselines.get("fileguard_hosts")
        if not isinstance(stored, dict) or not stored.get("hash"):
            self.ctx.baselines.set(
                "fileguard_hosts",
                {
                    "hash": current_hash,
                    "path": str(path),
                    "size": signature.get("size"),
                    "ts": time.time(),
                },
            )
            return True

        old_hash = str(stored.get("hash") or "")
        if old_hash == current_hash:
            return True

        detail = (
            f"hosts 文件内容发生变化：SHA-256 {old_hash[:16]}… → {current_hash[:16]}…，"
            "可能被用于劫持域名或阻断安全更新。"
        )
        try:
            hits = rules.match_fileguard("hosts_changed", str(path), detail=detail)
        except Exception:  # noqa: BLE001
            logger.exception("hosts 规则匹配异常")
            hits = []
        for hit in hits:
            findings.append(
                hit.finding(
                    sensor=self.id,
                    subject=str(path),
                    metadata={
                        "kind": "hosts",
                        "path": str(path),
                        "old_hash": old_hash,
                        "new_hash": current_hash,
                        "size": signature.get("size"),
                    },
                    dedupe_key="file:hosts_changed",
                )
            )
        self.ctx.baselines.set(
            "fileguard_hosts",
            {
                "hash": current_hash,
                "path": str(path),
                "size": signature.get("size"),
                "ts": time.time(),
            },
        )
        return True

    # ------------------------------------------------------------------ 诱饵
    def _canary_dir(self) -> Path:
        override = self.ctx.cfg.get("canary_dir")
        if override:
            return Path(str(override))
        return winutil.user_home() / "Documents" / CANARY_DIR_NAME

    def _check_canary(self, findings: list, now: float) -> tuple[bool, str]:
        directory = self._canary_dir()
        if not self.ctx.cfg.get("canary_enabled", True):
            self.ctx.shared["canary"] = {
                "dir": str(directory),
                "files": [],
                "enabled": False,
                "checked_at": now,
            }
            return True, ""

        baseline = self.ctx.baselines.get("canary")
        valid = (
            isinstance(baseline, dict)
            and isinstance(baseline.get("files"), dict)
            and baseline.get("dir") == str(directory)
            and all(isinstance(baseline["files"].get(name), dict) for name in CANARY_FILES)
        )
        if not valid:
            baseline = self._create_canary(directory)
            if baseline is None:
                self.ctx.shared["canary"] = {
                    "dir": str(directory),
                    "files": [],
                    "enabled": True,
                    "created": False,
                    "checked_at": now,
                    "error": "无法创建诱饵目录（需要用户 Documents 写权限）",
                }
                return False, "无法创建诱饵目录"
            self.ctx.baselines.set("canary", baseline)
            self.ctx.shared["canary"] = {
                "dir": str(directory),
                "files": sorted(baseline["files"]),
                "enabled": True,
                "created": True,
                "checked_at": now,
            }
            return True, ""

        files = baseline["files"]
        healthy = 0
        for name in CANARY_FILES:
            record = files[name]
            marker = str(record.get("marker") or "")
            expected_hash = str(record.get("hash") or "")
            path = directory / name
            if not path.is_file():
                self._emit_canary(findings, "canary_missing", path, name, "", "", now)
                if not self._restore_canary(path, marker):
                    continue
                healthy += 1
                continue
            current_hash = _hash_file(path)
            if current_hash and current_hash != expected_hash:
                self._emit_canary(
                    findings, "canary_changed", path, name, expected_hash, current_hash, now
                )
                self._restore_canary(path, marker)
                continue
            healthy += 1

        self.ctx.shared["canary"] = {
            "dir": str(directory),
            "files": sorted(files),
            "enabled": True,
            "healthy": healthy,
            "total": len(CANARY_FILES),
            "checked_at": now,
        }
        return True, ""

    def _create_canary(self, directory: Path) -> dict[str, Any] | None:
        files: dict[str, dict[str, Any]] = {}
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.warning("创建诱饵目录失败：%s", exc)
            return None
        created_at = time.time()
        for name in CANARY_FILES:
            marker = secrets.token_hex(CANARY_MARKER_BYTES)
            path = directory / name
            try:
                path.write_text(_canary_content(marker), encoding="utf-8")
            except OSError as exc:
                logger.warning("创建诱饵文件失败 %s：%s", name, exc)
                return None
            files[name] = {
                "marker": marker,
                "hash": _hash_file(path),
                "size": path.stat().st_size if path.is_file() else 0,
                "created_at": created_at,
            }
        return {"dir": str(directory), "files": files, "created_at": created_at}

    def _restore_canary(self, path: Path, marker: str) -> bool:
        if not marker:
            return False
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(_canary_content(marker), encoding="utf-8")
            return True
        except OSError as exc:
            logger.debug("恢复诱饵文件失败 %s：%s", path, exc)
            return False

    def _emit_canary(
        self,
        findings: list,
        kind: str,
        path: Path,
        name: str,
        old_hash: str,
        new_hash: str,
        now: float,
    ) -> None:
        throttle_key = f"file:{kind}:{name.lower()}"
        if not self._allow_alert(throttle_key, now):
            return
        if kind == "canary_missing":
            detail = (
                f"勒索诱饵文件 {path} 被删除，可能有程序在批量删除/加密文件。"
                "哨兵已尝试用原内容恢复该诱饵。"
            )
        else:
            detail = (
                f"勒索诱饵文件 {path} 内容被修改：SHA-256 {old_hash[:16]}… → {new_hash[:16]}…，"
                "可能存在批量加密行为；哨兵已尝试恢复该诱饵。"
            )
        try:
            hits = rules.match_fileguard(kind, str(path), detail=detail)
        except Exception:  # noqa: BLE001
            logger.exception("诱饵规则匹配异常：%s", name)
            return
        for hit in hits:
            findings.append(
                hit.finding(
                    sensor=self.id,
                    subject=str(path),
                    metadata={
                        "kind": "canary",
                        "path": str(path),
                        "file": name,
                        "old_hash": old_hash,
                        "new_hash": new_hash,
                        "detected_at": now,
                    },
                    dedupe_key=throttle_key,
                )
            )

    # ------------------------------------------------------------------ 节流
    def _allow_alert(self, key: str, now: float) -> bool:
        last = self._last_alert.get(key, 0.0)
        if now - last < ALERT_MIN_INTERVAL_S:
            return False
        self._last_alert[key] = now
        return True

    def _prune_alerts(self, now: float) -> None:
        if len(self._last_alert) <= 32:
            return
        cutoff = now - ALERT_MIN_INTERVAL_S
        self._last_alert = {key: ts for key, ts in self._last_alert.items() if ts >= cutoff}
