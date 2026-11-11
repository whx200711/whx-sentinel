"""WHX 哨兵 · Windows 事件日志传感器。

覆盖范围（全部为只读查询，不修改日志设置）：

- System 日志：7045（安装服务）/ 7040（服务启动类型变更）/ 104（日志被清除）/
  41（非正常关机）/ 6008（意外关闭）—— 标准用户通常可读；
- Security 日志（需要管理员）：1102（安全日志被清除）/ 4720（创建用户）/
  4728、4732（加入管理员组）；4625 不做逐条告警，而是用 10 分钟时间窗计数，
  达到阈值时调用 rules.match_failed_logon_burst 产生「疑似暴力破解」告警；
- Defender Operational 日志：1116（发现威胁）/ 1117（处置威胁）/
  5001（实时保护关闭）/ 5010（扫描功能关闭）/ 5007（配置被修改）——
  多数系统标准用户可读，读不到则自动降级。

实现要点：
- 首次启动只回看最近 5 分钟，之后每次回看 90 秒，避免重启后刷屏；
- 用 (log, RecordId) 在内存里去重，finding.dedupe_key = f"log:{log}:{record_id}"；
- 只通过 ctx.probe_json 调 PowerShell（Get-WinEvent -FilterHashtable + ConvertTo-Json）；
- 权限不足时 capability="needs_admin"，但 System 日志照常工作，绝不抛异常；
- 可读日志能力写入 ctx.shared["eventlog"]，供 /api/status 展示。
"""

from __future__ import annotations

import logging
import time
from typing import Any

import rules
from sensors.base import Sensor

logger = logging.getLogger("whx.sentinel.sensor.eventlog")

FIRST_WINDOW_S = 300  # 首次启动回看 5 分钟
WINDOW_S = 90  # 之后每次回看 90 秒
FAILED_LOGON_MIN = 8  # 与 rules.match_failed_logon_burst 内部阈值一致
FAILED_LOGON_WINDOW_MIN = 10
FAILED_LOGON_COOLDOWN_S = 1800.0
MAX_FINDINGS_PER_CYCLE = 50
MESSAGE_LIMIT = 1200
SEEN_TTL_S = 6 * 3600
SEEN_LIMIT = 8000

SYSTEM_IDS = (7045, 7040, 104, 41, 6008)
SECURITY_IDS = (1102, 4720, 4728, 4732)
FAILED_LOGON_ID = 4625
DEFENDER_IDS = (1116, 1117, 5001, 5010, 5007)
DEFENDER_LOG = "Microsoft-Windows-Windows Defender/Operational"

# PowerShell 探针：每个日志独立 try/catch，错误只回传 language-neutral 的
# FullyQualifiedErrorId（例如 NoMatchingEventsFound / UnauthorizedAccessException），
# Python 侧据此区分「没有事件」「无权限」「日志不存在」。
EVENTS_PS = r"""
$start = (Get-Date).AddSeconds(-__WINDOW__)
function New-Rec($ev, $log) {
  $m = [string]$ev.Message
  if ($m.Length -gt __MSG__) { $m = $m.Substring(0, __MSG__) }
  [pscustomobject]@{
    log = $log
    event_id = [int]$ev.Id
    record_id = [long]$ev.RecordId
    filetime = [long]$ev.TimeCreated.ToFileTimeUtc()
    time_text = $ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
    provider = [string]$ev.ProviderName
    level = [string]$ev.LevelDisplayName
    message = $m
  }
}
$r = [pscustomobject]@{
  start = $start.ToString('yyyy-MM-dd HH:mm:ss')
  system_ok = $false; system_error = ''; system = @()
  security_attempted = __WANT_SECURITY__; security_ok = $false; security_error = ''; security = @()
  defender_ok = $false; defender_error = ''; defender = @()
  failed_logon_count = 0; failed_logon_error = ''
}
try {
  $events = @(Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$start; Id=@(7045,7040,104,41,6008)} -MaxEvents 200 -ErrorAction Stop)
  $r.system = @($events | ForEach-Object { New-Rec $_ 'System' })
  $r.system_ok = $true
} catch {
  $err = "$($_.FullyQualifiedErrorId)"
  if ($err -like '*NoMatchingEventsFound*') { $r.system_ok = $true } else { $r.system_error = $err }
}
if ($r.security_attempted) {
  try {
    $sec = @(Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$start; Id=@(1102,4720,4728,4732)} -MaxEvents 300 -ErrorAction Stop)
    $r.security = @($sec | ForEach-Object { New-Rec $_ 'Security' })
    $r.security_ok = $true
  } catch {
    $err = "$($_.FullyQualifiedErrorId)"
    if ($err -like '*NoMatchingEventsFound*') { $r.security_ok = $true } else { $r.security_error = $err }
  }
  try {
    $failed = @(Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddMinutes(-10); Id=4625} -MaxEvents 2000 -ErrorAction Stop)
    $r.failed_logon_count = [int]$failed.Count
  } catch {
    $err = "$($_.FullyQualifiedErrorId)"
    if ($err -notlike '*NoMatchingEventsFound*') { $r.failed_logon_error = $err }
  }
}
try {
  $def = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; StartTime=$start; Id=@(1116,1117,5001,5010,5007)} -MaxEvents 200 -ErrorAction Stop)
  $r.defender = @($def | ForEach-Object { New-Rec $_ 'Microsoft-Windows-Windows Defender/Operational' })
  $r.defender_ok = $true
} catch {
  $err = "$($_.FullyQualifiedErrorId)"
  if ($err -like '*NoMatchingEventsFound*') { $r.defender_ok = $true } else { $r.defender_error = $err }
}
$r
"""

_DENIED_HINTS = (
    "unauthorized",
    "accessdenied",
    "access is denied",
    "notauthorized",
    "0x80041003",
    "拒绝访问",
)
_MISSING_HINTS = (
    "0x8004100e",
    "notfound",
    "not found",
    "does not exist",
    "找不到",
)


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


def _err_kind(error_id: Any) -> str:
    """把 PowerShell 的 FullyQualifiedErrorId 归类：empty / denied / missing / other。"""

    text = str(error_id or "").lower()
    if not text:
        return "other"
    if "nomatchingeventsfound" in text:
        return "empty"
    if any(hint in text for hint in _DENIED_HINTS):
        return "denied"
    if any(hint in text for hint in _MISSING_HINTS):
        return "missing"
    return "other"


def _ft_to_epoch(value: Any) -> float | None:
    try:
        raw = int(value)
    except (TypeError, ValueError):
        return None
    if raw <= 0:
        return None
    return raw / 10_000_000.0 - 11_644_473_600.0


# ---------------------------------------------------------------------------
# 传感器
# ---------------------------------------------------------------------------
class EventLogSensor(Sensor):
    id = "eventlog"
    name = "事件日志"
    description = "轮询系统/安全/Defender 事件日志（服务安装、日志清除、账号变更、暴力破解等）"
    interval_key = "eventlog_interval_s"
    default_interval = 30.0
    initial_delay = 6.0
    requires_admin = False

    def __init__(self, ctx):
        super().__init__(ctx)
        # (log, record_id) -> 第一次看到的时间，用于内存去重
        self._seen: dict[tuple[str, int], float] = {}
        self._primed = False
        self._last_burst_ts = 0.0

    # ------------------------------------------------------------------ 采集
    def collect(self) -> list:
        try:
            return self._collect()
        except Exception:  # noqa: BLE001 - 采集线程不能被异常打断
            logger.exception("事件日志传感器采集异常")
            self.capability = "degraded"
            return []

    def _collect(self) -> list:
        now = time.time()
        window = WINDOW_S if self._primed else FIRST_WINDOW_S
        try:
            env = self.ctx.probe_json(self._build_script(window), timeout=45.0)
        except Exception as exc:  # noqa: BLE001 - PowerShell 不可用时降级
            logger.debug("事件日志探针失败：%s", exc)
            self.capability = "unavailable"
            self.ctx.shared["eventlog"] = {
                "system": False,
                "security": None,
                "defender_operational": False,
                "attempted": {"system": True, "security": False, "defender": True},
                "window_s": window,
                "counts": {},
                "checked_at": now,
                "errors": {"system": str(exc)[:300]},
            }
            return []

        if not isinstance(env, dict):
            self.capability = "unavailable"
            return []

        system_ok = bool(env.get("system_ok"))
        if not system_ok:
            kind = _err_kind(env.get("system_error"))
            self.capability = "needs_admin" if kind == "denied" else "unavailable"
            self.ctx.shared["eventlog"] = {
                "system": False,
                "security": None,
                "defender_operational": False,
                "attempted": {"system": True, "security": False, "defender": True},
                "window_s": window,
                "counts": {},
                "checked_at": now,
                "errors": {"system": str(env.get("system_error") or "")[:300]},
            }
            return []

        # 首次成功查询后才开始用 90 秒窗口
        self._primed = True
        findings: list = []

        # ---- System 日志 -----------------------------------------------------
        for event in _as_list(env.get("system")):
            if len(findings) >= MAX_FINDINGS_PER_CYCLE:
                break
            self._handle_event(event, "System", findings)

        # ---- Security 日志 ---------------------------------------------------
        security_attempted = bool(env.get("security_attempted"))
        security_ok = security_attempted and bool(env.get("security_ok"))
        security_error = str(env.get("security_error") or "")
        security_kind = _err_kind(security_error) if security_attempted and not security_ok else ""

        if security_ok:
            for event in _as_list(env.get("security")):
                if len(findings) >= MAX_FINDINGS_PER_CYCLE:
                    break
                self._handle_event(event, "Security", findings)
            burst = self._failed_logon_burst(env.get("failed_logon_count"), findings)
            if burst:
                findings.append(burst)

        # ---- Defender Operational 日志 --------------------------------------
        defender_ok = bool(env.get("defender_ok"))
        defender_error = str(env.get("defender_error") or "")
        defender_kind = _err_kind(defender_error) if not defender_ok else ""
        if defender_ok:
            for event in _as_list(env.get("defender")):
                if len(findings) >= MAX_FINDINGS_PER_CYCLE:
                    break
                self._handle_event(event, DEFENDER_LOG, findings)

        # ---- 去重表清理 ------------------------------------------------------
        cutoff = now - SEEN_TTL_S
        if len(self._seen) > SEEN_LIMIT:
            newest = sorted(self._seen.items(), key=lambda item: item[1], reverse=True)[:SEEN_LIMIT]
            self._seen = dict(newest)
        elif len(self._seen) > 2000:
            self._seen = {key: ts for key, ts in self._seen.items() if ts >= cutoff}

        # ---- 能力判定 --------------------------------------------------------
        if not self.ctx.is_admin:
            # Security 日志需要管理员，非管理员下必有盲区
            self.capability = "needs_admin"
        elif security_ok and defender_ok:
            self.capability = "ok"
        elif security_kind == "denied" or defender_kind == "denied":
            self.capability = "needs_admin"
        else:
            self.capability = "degraded"

        errors: dict[str, str] = {}
        if not security_ok and security_attempted:
            errors["security"] = security_error[:300]
        if not defender_ok:
            errors["defender_operational"] = defender_error[:300]
        self.ctx.shared["eventlog"] = {
            "system": True,
            "security": security_ok if security_attempted else None,
            "defender_operational": defender_ok,
            "attempted": {
                "system": True,
                "security": security_attempted,
                "defender": True,
            },
            "window_s": window,
            "server_time": env.get("start"),
            "counts": {
                "system": len(_as_list(env.get("system"))),
                "security": len(_as_list(env.get("security"))),
                "defender": len(_as_list(env.get("defender"))),
            },
            "failed_logons_10m": int(env.get("failed_logon_count") or 0) if security_ok else 0,
            "checked_at": now,
            "errors": errors,
        }
        if findings:
            self.ctx.shared["eventlog"]["last_alert_ts"] = now
        return findings

    # ------------------------------------------------------------------ 内部
    def _build_script(self, window: int) -> str:
        # Security 日志只在管理员模式下查询（标准用户必然被拒绝，省掉一次失败探针）
        want_security = "$true" if self.ctx.is_admin else "$false"
        return (
            EVENTS_PS.replace("__WINDOW__", str(int(window)))
            .replace("__MSG__", str(MESSAGE_LIMIT))
            .replace("__WANT_SECURITY__", want_security)
        )

    def _handle_event(self, event: Any, log_name: str, findings: list) -> None:
        if not isinstance(event, dict):
            return
        event_id = event.get("event_id")
        record_id = event.get("record_id")
        try:
            event_id = int(event_id)
            record_id = int(record_id)
        except (TypeError, ValueError):
            return
        if record_id <= 0:
            return
        seen_key = (log_name, record_id)
        if seen_key in self._seen:
            return

        message = str(event.get("message") or "")
        try:
            hits = rules.match_eventlog(log_name, event_id, message, record_id=record_id)
        except Exception:  # noqa: BLE001 - 单条日志规则异常不影响其它事件
            logger.exception("事件日志规则匹配异常：%s/%s", log_name, event_id)
            self._seen[seen_key] = time.time()
            return

        ts = _ft_to_epoch(event.get("filetime"))
        if ts is None or ts <= 0:
            ts = time.time()
        metadata = {
            "log": log_name,
            "event_id": event_id,
            "record_id": record_id,
            "provider": str(event.get("provider") or ""),
            "level": str(event.get("level") or ""),
            "event_time": str(event.get("time_text") or ""),
            "message": message[:800],
        }
        for hit in hits:
            findings.append(
                hit.finding(
                    sensor=self.id,
                    subject=f"{log_name} / EventID {event_id}",
                    metadata=metadata,
                    dedupe_key=f"log:{log_name}:{record_id}",
                    ts=ts,
                )
            )
        self._seen[seen_key] = time.time()

    def _failed_logon_burst(self, count: Any, findings: list) -> Any:
        try:
            total = int(count)
        except (TypeError, ValueError):
            return None
        if total < FAILED_LOGON_MIN:
            return None
        now = time.time()
        if now - self._last_burst_ts < FAILED_LOGON_COOLDOWN_S:
            return None
        try:
            hits = rules.match_failed_logon_burst(total, FAILED_LOGON_WINDOW_MIN)
        except Exception:  # noqa: BLE001
            logger.exception("失败登录规则匹配异常")
            return None
        if not hits:
            return None
        self._last_burst_ts = now
        hit = hits[0]
        return hit.finding(
            sensor=self.id,
            subject=f"Security / EventID {FAILED_LOGON_ID} 近 {FAILED_LOGON_WINDOW_MIN} 分钟 {total} 次",
            metadata={
                "log": "Security",
                "event_id": FAILED_LOGON_ID,
                "count": total,
                "window_minutes": FAILED_LOGON_WINDOW_MIN,
            },
            dedupe_key="log:failed_logon_burst",
        )
