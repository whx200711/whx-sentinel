"""WHX 哨兵 · 网络连接传感器。

每 4 秒检查一次 TCP 连接：
- 新出现的「对外监听」端口（非回环绑定）；
- 已知高危监听端口（RDP/SMB/数据库等）即使早已存在也会提示暴露风险；
- 出站连接到可疑远端端口（反弹 shell/C2/挖矿/代理等）或用户黑名单 IP。

只读取连接表，不做任何主动探测、不向外网发包。
"""

from __future__ import annotations

import logging
import time
from typing import Any

import rules
import rules_data
import winutil
from sensors.base import Sensor

logger = logging.getLogger("whx.sentinel.sensor.network")

MAX_FINDINGS_PER_CYCLE = 20
LOOPBACK_PREFIXES = ("127.", "::1", "0:0:0:0:0:0:0:1")


def _is_loopback(ip: str) -> bool:
    text = str(ip or "")
    if not text:
        return False
    if text in {"::1", "0:0:0:0:0:0:0:1", "localhost"}:
        return True
    return text.startswith(LOOPBACK_PREFIXES)


class NetworkSensor(Sensor):
    id = "network"
    name = "网络连接"
    description = "监控新增对外监听端口、可疑出站端口/黑名单 IP 连接"
    interval_key = "network_interval_s"
    default_interval = 4.0
    initial_delay = 3.0
    requires_admin = False

    def __init__(self, ctx):
        super().__init__(ctx)
        self._baseline: set[str] | None = None
        self._conn_seen: dict[str, float] = {}

    # ------------------------------------------------------------------
    def _load_baseline(self) -> set[str]:
        stored = self.ctx.baselines.get("listeners")
        baseline: set[str] = set()
        if isinstance(stored, list):
            baseline = {str(item) for item in stored if item}
        elif isinstance(stored, dict):
            baseline = {str(item) for item in stored.get("entries") or []}
        return baseline

    def _save_baseline(self, baseline: set[str]) -> None:
        self.ctx.baselines.set("listeners", sorted(baseline))

    # ------------------------------------------------------------------
    def collect(self) -> list:
        try:
            import psutil
        except ImportError:
            self.capability = "unavailable"
            return []

        findings = []
        try:
            connections = psutil.net_connections(kind="inet")
            self.capability = "ok"
        except psutil.AccessDenied:
            self.capability = "needs_admin"
            connections = []
        except (psutil.Error, OSError) as exc:
            self.capability = "degraded"
            raise RuntimeError(f"读取网络连接失败：{exc}") from exc

        listeners: list[tuple[str, int, int | None]] = []
        outbound: list[Any] = []
        for connection in connections:
            try:
                status = str(connection.status or "")
                if status == getattr(psutil, "CONN_LISTEN", "LISTEN") and connection.laddr:
                    listeners.append(
                        (
                            str(connection.laddr.ip),
                            int(connection.laddr.port),
                            connection.pid,
                        )
                    )
                elif connection.raddr and status in {
                    getattr(psutil, "CONN_ESTABLISHED", "ESTABLISHED"),
                    getattr(psutil, "CONN_SYN_SENT", "SYN_SENT"),
                }:
                    outbound.append(connection)
            except (AttributeError, ValueError):
                continue

        # ---- 监听端口 -----------------------------------------------------
        baseline = self._load_baseline()
        first_run = self.ctx.baselines.get("listeners") is None
        if self._baseline is None:
            self._baseline = set(baseline)
        current_listeners = {f"{ip}:{port}" for ip, port, _pid in listeners}
        self._baseline |= current_listeners

        for bind_ip, port, pid in listeners:
            if _is_loopback(bind_ip):
                continue
            key = f"{bind_ip}:{port}"
            is_new = not first_run and key not in baseline
            try:
                hits = rules.match_listener(port, bind_ip, is_new)
            except Exception:  # noqa: BLE001
                logger.exception("监听端口规则匹配异常：%s", key)
                continue
            for hit in hits:
                # 同一端口在 0.0.0.0 与 :: 上会各出现一次，按端口合并去重
                dedupe = (
                    f"net:{hit.rule_id}:{port}"
                    if hit.rule_id == "net.exposed_listener"
                    else f"net:{hit.rule_id}:{key}"
                )
                finding = hit.finding(
                    sensor=self.id,
                    subject=f"listen:{key}",
                    metadata={
                        "pid": pid,
                        "bind_ip": bind_ip,
                        "local_port": port,
                        "protocol": "tcp",
                        "kind": "listener",
                    },
                    dedupe_key=dedupe,
                )
                findings.append(finding)
            if len(findings) >= MAX_FINDINGS_PER_CYCLE:
                break

        # 基线只增不减：第一次看到某监听端口时产生「新增」告警，之后记住
        if current_listeners - baseline:
            self._save_baseline(self._baseline)

        # ---- 出站连接 -----------------------------------------------------
        now = time.time()
        emitted_keys: dict[str, float] = {}
        for connection in outbound:
            if len(findings) >= MAX_FINDINGS_PER_CYCLE:
                break
            try:
                remote_ip = str(connection.raddr.ip)
                remote_port = int(connection.raddr.port)
                local_port = int(connection.laddr.port) if connection.laddr else 0
                pid = connection.pid
            except (AttributeError, ValueError):
                continue
            if _is_loopback(remote_ip):
                continue
            proc_name = ""
            if pid:
                try:
                    proc_name = psutil.Process(pid).name()
                except (psutil.Error, OSError):
                    proc_name = ""
            public = winutil.is_public_ip(remote_ip)
            try:
                hits = rules.match_network_connection(remote_ip, remote_port, proc_name, public)
            except Exception:  # noqa: BLE001
                logger.exception("出站连接规则匹配异常")
                continue
            for hit in hits:
                key = f"net:{hit.rule_id}:{(proc_name or '?').lower()}:{remote_ip}:{remote_port}"
                if key in emitted_keys:
                    continue
                emitted_keys[key] = now
                self._conn_seen[key] = now
                finding = hit.finding(
                    sensor=self.id,
                    subject=f"{proc_name or '?'}→{remote_ip}:{remote_port}",
                    metadata={
                        "pid": pid,
                        "process_name": proc_name,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "local_port": local_port,
                        "protocol": "tcp",
                        "status": "established",
                    },
                    dedupe_key=key,
                )
                findings.append(finding)
                if len(findings) >= MAX_FINDINGS_PER_CYCLE:
                    break

        # 清理过期的连接去重记录（10 分钟）
        cutoff = now - 600
        self._conn_seen = {key: ts for key, ts in self._conn_seen.items() if ts >= cutoff}

        self.ctx.shared["network"] = {
            "connections": len(connections),
            "listeners": len(listeners),
            "outbound": len(outbound),
            "exposed": [
                f"{ip}:{port}"
                for ip, port, _pid in listeners
                if not _is_loopback(ip) and int(port) in rules_data.RISKY_LISTEN_PORTS
            ],
            "scan_ts": now,
            "baseline_size": len(self._baseline),
        }
        return findings
