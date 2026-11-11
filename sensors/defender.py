"""WHX 哨兵 · Windows Defender / 防火墙状态传感器。

只读采集，不修改任何系统设置。数据来源按优先级自动降级：

1. PowerShell 安全模块：Get-MpComputerStatus / Get-MpPreference / Get-NetFirewallProfile；
2. SecurityCenter2 WMI：AntiVirusProduct（确认杀软是否在保护状态）；
3. 注册表 + psutil：WinDefend 服务状态、病毒库目录时间戳、防火墙配置键；
4. netsh advfirewall show allprofiles state（仅管理员兜底）。

DSH 沙箱 / 标准用户下 WMI 与安全模块通常会被拒绝，本传感器会优雅降级：
拿到部分数据时 capability="degraded" 并照常跑规则；完全拿不到时
capability="needs_admin"（或 unavailable）并返回 []，不抛异常。

新增 Defender 排除项会与基线 defender_exclusions 比对，并调用
rules.match_fileguard("exclusion_added", ...) 产生高危告警。
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

import rules
import winutil
from sensors.base import Sensor

logger = logging.getLogger("whx.sentinel.sensor.defender")

MAX_FINDINGS_PER_CYCLE = 10

# ---------------------------------------------------------------------------
# PowerShell 状态探针（一次进程内取完 MPS / 偏好 / 防火墙 / SecurityCenter2）
# 每个区块独立 try/catch，互不影响；错误只记录 language-neutral 的
# FullyQualifiedErrorId（如 HRESULT、UnauthorizedAccessException），便于分类。
# ---------------------------------------------------------------------------
STATUS_PS = r"""
$r = [pscustomobject]@{
  mps = $null; mps_error = ''
  pref = $null; pref_error = ''
  fw = @(); fw_error = ''
  sc2_av = @(); sc2_error = ''
}
try {
  $cs = Get-MpComputerStatus -ErrorAction Stop
  $qs = $null; if ($cs.QuickScanEndTime) { $qs = [long]$cs.QuickScanEndTime.ToFileTimeUtc() }
  $fs = $null; if ($cs.FullScanEndTime) { $fs = [long]$cs.FullScanEndTime.ToFileTimeUtc() }
  $age = $null; if ($null -ne $cs.AntivirusSignatureAge) { $age = [int]$cs.AntivirusSignatureAge }
  $r.mps = [pscustomobject]@{
    am_service = [bool]$cs.AMServiceEnabled
    antivirus = [bool]$cs.AntivirusEnabled
    realtime = [bool]$cs.RealTimeProtectionEnabled
    behavior = [bool]$cs.BehaviorMonitorEnabled
    signature_age_days = $age
    signature_version = "$($cs.AntivirusSignatureVersion)"
    engine_version = "$($cs.AMEngineVersion)"
    last_quick_scan = $qs
    last_full_scan = $fs
  }
} catch { $r.mps_error = "$($_.FullyQualifiedErrorId)" }

try {
  $p = Get-MpPreference -ErrorAction Stop
  $paths = @($p.ExclusionPath | Where-Object { $_ } | ForEach-Object { [string]$_ })
  $exts = @($p.ExclusionExtension | Where-Object { $_ } | ForEach-Object { [string]$_ })
  $procs = @($p.ExclusionProcess | Where-Object { $_ } | ForEach-Object { [string]$_ })
  $r.pref = [pscustomobject]@{ paths = $paths; extensions = $exts; processes = $procs }
} catch { $r.pref_error = "$($_.FullyQualifiedErrorId)" }

try {
  $r.fw = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{ name = "$($_.Name)"; enabled = [bool]$_.Enabled }
  })
} catch { $r.fw_error = "$($_.FullyQualifiedErrorId)" }

try {
  $r.sc2_av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object {
    [pscustomobject]@{ name = "$($_.displayName)"; state = [long]$_.productState }
  })
} catch { $r.sc2_error = "$($_.FullyQualifiedErrorId)" }

$r
"""

# Defender 注册表位置
_RTP_KEYS = (
    r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
    r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
)
_DEFENDER_POLICY = r"SOFTWARE\Policies\Microsoft\Windows Defender"
_DEFENDER_LOCAL = r"SOFTWARE\Microsoft\Windows Defender"
_SIGNATURE_UPDATES = r"SOFTWARE\Microsoft\Windows Defender\Signature Updates"
_DEFINITION_DIR = Path(r"C:\ProgramData\Microsoft\Windows Defender\Definition Updates")
_FIREWALL_PROFILES = (
    ("domain", "DomainProfile"),
    ("private", "StandardProfile"),
    ("public", "PublicProfile"),
)


# ---------------------------------------------------------------------------
# 小工具（只在本文件内使用，不修改共享模块）
# ---------------------------------------------------------------------------
def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return [value]


def _tri(value: Any) -> bool | None:
    """JSON bool/数字 → 三态布尔（None 表示未知）。"""

    if isinstance(value, bool):
        return value
    if value is None:
        return None
    try:
        return bool(int(value))
    except (TypeError, ValueError):
        return None


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _ft_to_epoch(value: Any) -> float | None:
    """Windows FILETIME（100ns since 1601）→ Unix 时间戳。"""

    raw = _to_int(value)
    if raw is None or raw <= 0:
        return None
    return raw / 10_000_000.0 - 11_644_473_600.0


def _reg_value(root_name: str, path: str, value_name: str) -> Any:
    try:
        return winutil.registry_value(root_name, path, value_name)
    except Exception:  # noqa: BLE001 - 注册表不可读时按未知处理
        return None


def _reg_subkeys(root_name: str, path: str) -> list[str] | None:
    """枚举子键；键不存在返回 []，无权限返回 None（用于区分「没有排除项」和「读不到」）。"""

    if not winutil.IS_WINDOWS:
        return None
    try:
        import winreg

        root = getattr(winreg, root_name, None)
        if root is None:
            return None
        with winreg.OpenKey(root, path) as key:
            count = winreg.QueryInfoKey(key)[0]
            names: list[str] = []
            for index in range(count):
                try:
                    names.append(winreg.EnumKey(key, index))
                except OSError:
                    break
            return names
    except OSError as exc:
        if getattr(exc, "winerror", None) in (2, 3):
            return []
        return None


def _signature_age_days() -> float | None:
    """用病毒库目录的更新时间估算病毒库年龄（注册表回退路径使用）。"""

    if not _DEFINITION_DIR.is_dir():
        return None
    newest = 0.0
    try:
        for child in _DEFINITION_DIR.iterdir():
            try:
                if child.is_dir():
                    newest = max(newest, child.stat().st_mtime)
            except OSError:
                continue
    except OSError:
        return None
    if newest <= 0:
        return None
    return max(0.0, round((time.time() - newest) / 86400.0, 1))


def _empty_status(checked_at: float) -> dict[str, Any]:
    return {
        "available": False,
        "realtime": None,
        "antivirus": None,
        "am_service": None,
        "behavior": None,
        "signature_age_days": None,
        "signature_version": "",
        "engine_version": "",
        "last_quick_scan": None,
        "last_full_scan": None,
        "firewall": {"available": False, "domain": None, "private": None, "public": None},
        "exclusions": [],
        "source": "none",
        "checked_at": checked_at,
    }


def _empty_firewall() -> dict[str, Any]:
    return {"available": False, "domain": None, "private": None, "public": None}


def _apply_mps(status: dict[str, Any], mps: dict[str, Any]) -> None:
    status["am_service"] = _tri(mps.get("am_service"))
    status["antivirus"] = _tri(mps.get("antivirus"))
    status["realtime"] = _tri(mps.get("realtime"))
    status["behavior"] = _tri(mps.get("behavior"))
    age = mps.get("signature_age_days")
    if isinstance(age, (int, float)):
        status["signature_age_days"] = int(age)
    version = str(mps.get("signature_version") or "").strip()
    if version:
        status["signature_version"] = version
    engine = str(mps.get("engine_version") or "").strip()
    if engine:
        status["engine_version"] = engine
    status["last_quick_scan"] = _ft_to_epoch(mps.get("last_quick_scan"))
    status["last_full_scan"] = _ft_to_epoch(mps.get("last_full_scan"))


def _flat_exclusions(pref: dict[str, Any]) -> list[str]:
    """Get-MpPreference 的三类排除项 → 扁平的「类型:值」列表。"""

    items: list[str] = []
    for field, kind in (
        ("paths", "path"),
        ("extensions", "extension"),
        ("processes", "process"),
    ):
        for value in _as_list(pref.get(field)):
            text = str(value or "").strip()
            if text:
                items.append(f"{kind}:{text}")
    return sorted(set(items))


def _firewall_from_profiles(items: Any) -> dict[str, Any]:
    firewall = _empty_firewall()
    for item in _as_list(items):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip().lower()
        enabled = item.get("enabled")
        field = {"domain": "domain", "private": "private", "standard": "private", "public": "public"}.get(name)
        if field:
            firewall[field] = enabled if isinstance(enabled, bool) else _tri(enabled)
    firewall["available"] = any(firewall[key] is not None for key in ("domain", "private", "public"))
    return firewall


def _firewall_from_registry() -> dict[str, Any]:
    firewall = _empty_firewall()
    for key, sub_profile in _FIREWALL_PROFILES:
        value = _reg_value(
            "HKEY_LOCAL_MACHINE",
            rf"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{sub_profile}",
            "EnableFirewall",
        )
        raw = _to_int(value)
        if raw is not None:
            firewall[key] = raw != 0
    firewall["available"] = any(firewall[key] is not None for key in ("domain", "private", "public"))
    return firewall


_PROFILE_ALIASES = (
    ("domain", ("domain profile", "domainprofile", "域配置文件", "域配置")),
    ("private", ("private profile", "privateprofile", "专用配置文件", "专用配置")),
    ("public", ("public profile", "publicprofile", "公用配置文件", "公用配置")),
)


def _firewall_from_netsh(text: str) -> dict[str, Any]:
    """解析 netsh advfirewall show allprofiles state 的本地化文本。"""

    firewall = _empty_firewall()
    current: str | None = None
    for line in str(text or "").splitlines():
        lowered = line.lower().strip()
        if not lowered:
            continue
        for profile, aliases in _PROFILE_ALIASES:
            if any(alias in lowered or alias in line for alias in aliases):
                current = profile
                break
        if current and ("state" in lowered or "状态" in line):
            if "on" in lowered.split() or "启用" in line:
                firewall[current] = True
            elif "off" in lowered.split() or "禁用" in line:
                firewall[current] = False
    firewall["available"] = any(firewall[key] is not None for key in ("domain", "private", "public"))
    return firewall


def _sc2_antivirus(env: dict[str, Any]) -> tuple[bool | None, bool, list[str]]:
    """SecurityCenter2 杀软产品 → (是否启用, 是否探测到产品, 产品名列表)。

    productState 字节约定（业界常用解码）：(state >> 8) & 0xFF 为扫描器状态，
    0x10/0x11 表示启用；未知编码一律按「未知」处理，避免误报。
    """

    enabled: bool | None = None
    available = False
    names: list[str] = []
    for item in _as_list(env.get("sc2_av")):
        if not isinstance(item, dict):
            continue
        available = True
        name = str(item.get("name") or "").strip()
        if name:
            names.append(name)
        state = _to_int(item.get("state"))
        if state is None:
            continue
        scanner = (state >> 8) & 0xFF
        if scanner in (0x10, 0x11):
            enabled = True
        elif scanner in (0x00, 0x01) and enabled is None:
            enabled = False
    return enabled, available, names


# ---------------------------------------------------------------------------
# 传感器
# ---------------------------------------------------------------------------
class DefenderSensor(Sensor):
    id = "defender"
    name = "Defender / 防火墙"
    description = "采集 Windows Defender 实时保护、病毒库与防火墙状态，监控新增查杀排除项"
    interval_key = "defender_interval_s"
    default_interval = 60.0
    initial_delay = 4.0
    requires_admin = False

    # ------------------------------------------------------------------ 采集
    def collect(self) -> list:
        try:
            return self._collect()
        except Exception:  # noqa: BLE001 - 传感器不允许把异常抛给采集线程
            logger.exception("Defender 传感器采集异常")
            self.capability = "degraded"
            return []

    def _collect(self) -> list:
        checked_at = time.time()
        status = _empty_status(checked_at)
        findings: list = []
        findings_limit = MAX_FINDINGS_PER_CYCLE

        env = self._probe_status()
        mps_ok = False
        pref_ok = False
        sc2_enabled: bool | None = None
        sc2_available = False

        if env:
            mps = env.get("mps")
            if isinstance(mps, dict):
                _apply_mps(status, mps)
                mps_ok = True
                status["source"] = "mps"
            pref = env.get("pref")
            if isinstance(pref, dict):
                status["exclusions"] = _flat_exclusions(pref)
                pref_ok = True
            elif status["source"] == "mps":
                status["source"] = "mps"
            firewall = _firewall_from_profiles(env.get("fw"))
            if firewall["available"]:
                status["firewall"] = firewall
            sc2_enabled, sc2_available, _names = _sc2_antivirus(env)

        # ---- 回退 1：注册表 / psutil / SecurityCenter2 --------------------
        fallback_used = False
        if not mps_ok:
            registry_status = self._registry_status()
            for key, value in registry_status.items():
                if value in (None, ""):
                    continue
                if status.get(key) in (None, ""):
                    status[key] = value
            if registry_status:
                fallback_used = True
            if status["antivirus"] is None and sc2_available and sc2_enabled is not None:
                status["antivirus"] = sc2_enabled
                fallback_used = True
            if fallback_used:
                status["source"] = "securitycenter+registry" if sc2_available else "registry"

        # ---- 回退 2：防火墙 ------------------------------------------------
        if not status["firewall"]["available"]:
            firewall = _firewall_from_registry()
            if firewall["available"]:
                status["firewall"] = firewall
                status["source"] = self._append_source(status["source"], "registry")
                fallback_used = True
            elif self.ctx.is_admin:
                netsh = self._firewall_from_netsh()
                if netsh["available"]:
                    status["firewall"] = netsh
                    status["source"] = self._append_source(status["source"], "netsh")
                    fallback_used = True

        # ---- 回退 3：排除项（仅注册表可读时） -----------------------------
        exclusions_known = pref_ok
        if not exclusions_known:
            registry_exclusions = self._registry_exclusions()
            if registry_exclusions is not None:
                status["exclusions"] = registry_exclusions
                exclusions_known = True
                status["source"] = self._append_source(status["source"], "registry")
                fallback_used = True

        # ---- 可用性判定 -----------------------------------------------------
        available = bool(
            mps_ok
            or pref_ok
            or fallback_used
            or status["firewall"]["available"]
            or exclusions_known
        )
        if not available:
            status["available"] = False
            status["source"] = "none"
            self.capability = "needs_admin" if not self.ctx.is_admin else "unavailable"
            self._publish(status)
            return []

        status["available"] = True
        if mps_ok and pref_ok:
            self.capability = "ok"
        else:
            self.capability = "degraded"

        # ---- 规则匹配 --------------------------------------------------------
        try:
            hits = rules.match_defender(status)
        except Exception:  # noqa: BLE001 - 单次规则异常不影响采集
            logger.exception("Defender 规则匹配异常")
            hits = []
        for hit in hits:
            if len(findings) >= findings_limit:
                break
            findings.append(
                hit.finding(
                    sensor=self.id,
                    subject=self._subject_for(hit.rule_id),
                    metadata={
                        "source": status["source"],
                        "value": self._rule_value(hit.rule_id, status),
                        "checked_at": checked_at,
                    },
                    dedupe_key=hit.rule_id,
                )
            )

        # ---- 新增排除项 ------------------------------------------------------
        if exclusions_known and len(findings) < findings_limit:
            findings.extend(
                self._exclusion_findings(status["exclusions"], status["source"], findings_limit - len(findings))
            )

        self._publish(status)
        return findings

    # ------------------------------------------------------------------ 探针
    def _probe_status(self) -> dict[str, Any]:
        try:
            env = self.ctx.probe_json(STATUS_PS, timeout=45.0)
        except Exception as exc:  # noqa: BLE001 - PowerShell/沙箱失败属预期
            logger.debug("Defender PowerShell 探针失败：%s", exc)
            return {}
        return env if isinstance(env, dict) else {}

    def _registry_status(self) -> dict[str, Any]:
        """只读注册表 + psutil 的 Defender 状态回退（标准用户通常可用）。"""

        status: dict[str, Any] = {}

        # WinDefend 服务状态：psutil 直读 SCM，失败再看启动类型
        try:
            import psutil

            service = psutil.win_service_get("WinDefend")
            state = str(service.status() or "").strip().lower()
            status["am_service"] = state == "running"
        except Exception:  # noqa: BLE001 - 权限不足时忽略
            start = _to_int(
                _reg_value("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\WinDefend", "Start")
            )
            if start is not None:
                status["am_service"] = start != 4

        # 实时保护 / 行为监控 / 防病毒：Disable* 值为 1 表示关闭
        for path in _RTP_KEYS:
            raw = _to_int(_reg_value("HKEY_LOCAL_MACHINE", path, "DisableRealtimeMonitoring"))
            if raw is not None:
                status["realtime"] = raw == 0
                break
        for path in _RTP_KEYS:
            raw = _to_int(_reg_value("HKEY_LOCAL_MACHINE", path, "DisableBehaviorMonitoring"))
            if raw is not None:
                status["behavior"] = raw == 0
                break
        for path in (_DEFENDER_POLICY, _DEFENDER_LOCAL):
            raw = _to_int(_reg_value("HKEY_LOCAL_MACHINE", path, "DisableAntiSpyware"))
            if raw is not None:
                status["antivirus"] = raw == 0
                break

        # 病毒库版本 / 引擎版本 / 估算年龄
        signature_version = _reg_value("HKEY_LOCAL_MACHINE", _SIGNATURE_UPDATES, "AVSignatureVersion")
        if signature_version:
            status["signature_version"] = str(signature_version)
        engine_version = _reg_value("HKEY_LOCAL_MACHINE", _SIGNATURE_UPDATES, "EngineVersion")
        if engine_version:
            status["engine_version"] = str(engine_version)
        age = _signature_age_days()
        if age is not None:
            status["signature_age_days"] = age

        return {key: value for key, value in status.items() if value is not None}

    def _registry_exclusions(self) -> list[str] | None:
        items: list[str] = []
        for sub_key, kind in (("Paths", "path"), ("Extensions", "extension"), ("Processes", "process")):
            names = _reg_subkeys(
                "HKEY_LOCAL_MACHINE", rf"SOFTWARE\Microsoft\Windows Defender\Exclusions\{sub_key}"
            )
            if names is None:
                return None
            items.extend(f"{kind}:{name}" for name in names if name)
        return sorted(set(items))

    def _firewall_from_netsh(self) -> dict[str, Any]:
        try:
            text = self.ctx.probe_text("netsh advfirewall show allprofiles state", timeout=25.0)
        except Exception:  # noqa: BLE001 - 需要管理员，失败即降级
            return _empty_firewall()
        return _firewall_from_netsh(text)

    # ------------------------------------------------------------------ 结果
    def _exclusion_findings(self, exclusions: list[str], source: str, limit: int) -> list:
        current = sorted({str(item) for item in exclusions if item})
        stored = self.ctx.baselines.get("defender_exclusions")
        if stored is None:
            # 第一次拿到排除列表：只保存基线，不告警
            self.ctx.baselines.set("defender_exclusions", current)
            return []

        if isinstance(stored, list):
            previous = {str(item) for item in stored if item}
        elif isinstance(stored, dict):
            previous = {str(item) for item in _as_list(stored.get("items")) if item}
        else:
            # 旧格式/损坏基线：重新建立，避免把所有排除项当成「新增」
            self.ctx.baselines.set("defender_exclusions", current)
            return []

        findings: list = []
        for item in sorted(set(current) - previous):
            kind, _, value = item.partition(":")
            try:
                hits = rules.match_fileguard(
                    "exclusion_added",
                    value or item,
                    detail=f"Defender 排除列表新增 {item}（攻击者常用排除项绕过查杀，请确认是否为本人操作）。",
                )
            except Exception:  # noqa: BLE001
                logger.exception("排除项规则匹配异常：%s", item)
                continue
            for hit in hits:
                if len(findings) >= limit:
                    break
                findings.append(
                    hit.finding(
                        sensor=self.id,
                        subject=f"Defender 排除项 {value or item}",
                        metadata={
                            "source": source,
                            "exclusion": item,
                            "exclusion_kind": kind or "unknown",
                            "exclusion_value": value or item,
                        },
                        dedupe_key=f"defender:exclusion:{item.lower()}",
                    )
                )
        if current != sorted(previous):
            self.ctx.baselines.set("defender_exclusions", current)
        return findings

    @staticmethod
    def _append_source(source: str, extra: str) -> str:
        if not source or source == "none":
            return extra
        if extra in source.split("+"):
            return source
        return f"{source}+{extra}"

    @staticmethod
    def _subject_for(rule_id: str) -> str:
        if rule_id.startswith("firewall") or "firewall" in rule_id:
            return "Windows 防火墙"
        return "Windows Defender"

    @staticmethod
    def _rule_value(rule_id: str, status: dict[str, Any]) -> Any:
        field = {
            "defender.service_off": "am_service",
            "defender.antivirus_off": "antivirus",
            "defender.realtime_off": "realtime",
            "defender.behavior_off": "behavior",
            "defender.signatures_stale": "signature_age_days",
            "firewall.profile_off": "firewall",
        }.get(rule_id)
        return status.get(field) if field else None

    def _publish(self, status: dict[str, Any]) -> None:
        self.ctx.shared["defender"] = status
        self.ctx.shared["firewall"] = status.get("firewall") or _empty_firewall()
