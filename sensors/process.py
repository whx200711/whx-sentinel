"""WHX 哨兵 · 进程监控传感器。

每 2 秒枚举一次进程，只对「启动后新出现的进程」做规则匹配（启动前的进程作为基线），
避免开机后满屏历史告警。检测内容包括可疑命令行、临时目录执行、办公软件派生 shell 等。
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import rules
from sensors.base import Sensor

logger = logging.getLogger("whx.sentinel.sensor.process")

MAX_FINDINGS_PER_CYCLE = 25


class ProcessSensor(Sensor):
    id = "process"
    name = "进程监控"
    description = "监控新进程命令行、临时目录执行、办公软件派生 shell 等可疑行为"
    interval_key = "process_interval_s"
    default_interval = 2.0
    initial_delay = 2.0
    requires_admin = False

    def __init__(self, ctx):
        super().__init__(ctx)
        self._seen: dict[int, float] = {}
        self._baseline_done = False
        self._self_pid = os.getpid()
        self._self_ppid = os.getppid()
        # 每次安装随机生成，不再使用公开常量作免检口令
        self._internal_marker = str((getattr(ctx, "cfg", {}) or {}).get("internal_marker") or "")

    # ------------------------------------------------------------------
    def collect(self) -> list:
        try:
            import psutil
        except ImportError:
            self.capability = "unavailable"
            return []

        findings = []
        try:
            processes = list(
                psutil.process_iter(
                    attrs=["pid", "name", "exe", "cmdline", "ppid", "username", "create_time"],
                    ad_value=None,
                )
            )
        except (psutil.Error, OSError) as exc:
            self.capability = "degraded"
            raise RuntimeError(f"枚举进程失败：{exc}") from exc

        current: dict[int, dict[str, Any]] = {}
        names: dict[int, str] = {}
        for process in processes:
            info = process.info or {}
            pid = info.get("pid")
            if not pid:
                continue
            create = float(info.get("create_time") or 0.0)
            current[pid] = {"create": create, "info": info}
            names[pid] = str(info.get("name") or "")

        # 进程退出后清理，避免 pid 复用造成漏报
        self._seen = {
            pid: create
            for pid, create in self._seen.items()
            if pid in current and abs(current[pid]["create"] - create) < 0.01
        }

        if not self._baseline_done:
            # 启动前已存在的进程全部记为基线，不产生历史告警
            self._seen.update({pid: item["create"] for pid, item in current.items()})
            self._baseline_done = True
            self.ctx.shared["process_count"] = len(current)
            self.ctx.shared["process_baseline_ts"] = time.time()
            self.capability = "ok"
            return []

        total_findings = 0
        for pid, item in current.items():
            if total_findings >= MAX_FINDINGS_PER_CYCLE:
                break
            if pid == self._self_pid:
                continue
            create = item["create"]
            if pid in self._seen:
                continue
            if create and create < self.ctx.started_at - 2:
                # 启动前就存在的进程（例如进程表在基线之后才可读）不重复告警
                self._seen[pid] = create
                continue
            self._seen[pid] = create

            info = item["info"]
            name = str(info.get("name") or "")
            exe = str(info.get("exe") or "")
            raw_cmdline = info.get("cmdline") or []
            if isinstance(raw_cmdline, (list, tuple)):
                cmdline = " ".join(str(part) for part in raw_cmdline)
            else:
                cmdline = str(raw_cmdline)
            cmdline = cmdline[:1800]
            ppid = int(info.get("ppid") or 0)
            parent_name = names.get(ppid, "")
            username = str(info.get("username") or "")

            # 自己的 PowerShell 探针 / 测试进程不产生告警（标记每个安装随机生成）
            if self._internal_marker and self._internal_marker in cmdline:
                continue

            metadata = {
                "pid": pid,
                "process_name": name,
                "exe": exe,
                "cmdline": cmdline,
                "ppid": ppid,
                "parent_name": parent_name,
                "username": username,
                "create_time": create,
            }
            try:
                hits = rules.match_process(name, exe, cmdline, parent_name)
            except Exception:  # noqa: BLE001 - 单条规则异常不影响其它进程
                logger.exception("进程规则匹配异常：%s", name)
                continue
            for hit in hits:
                if total_findings >= MAX_FINDINGS_PER_CYCLE:
                    break
                finding = hit.finding(
                    sensor=self.id,
                    subject=f"{name or '?'}:{pid}",
                    metadata=metadata,
                    dedupe_key=(
                        f"proc:{hit.rule_id}:{(name or '?').lower()}:{(exe or '').lower()}"
                    ),
                )
                findings.append(finding)
                total_findings += 1

        self.ctx.shared["process_count"] = len(current)
        self.ctx.shared["process_scan_ts"] = time.time()
        self.ctx.shared["process_baseline_done"] = True
        self.capability = "ok"
        if findings:
            self.ctx.shared["last_process_alert_ts"] = time.time()
        return findings
