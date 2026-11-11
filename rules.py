"""WHX 哨兵 · 规则匹配与 Finding 构造。

纯函数为主：输入传感器采集到的事实，输出 RuleHit / Finding。
传感器可以独立单元测试，不需要真实系统环境。
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any

import rules_data
import winutil
from events import Finding, normalize_severity

_COMPILED: dict[str, re.Pattern[str]] = {}


def _compile(pattern: str) -> re.Pattern[str]:
    compiled = _COMPILED.get(pattern)
    if compiled is None:
        compiled = re.compile(pattern, re.I)
        _COMPILED[pattern] = compiled
    return compiled


def _any_match(patterns: list[str], text: str) -> str | None:
    for pattern in patterns:
        if _compile(pattern).search(text):
            return pattern
    return None


@dataclass
class RuleHit:
    rule_id: str
    severity: str
    title: str
    detail: str = ""
    ai_eligible: bool = False
    dedupe_window_s: float = rules_data.DEDUPE_WINDOW_DEFAULT
    extra: dict[str, Any] = field(default_factory=dict)

    def finding(
        self,
        sensor: str,
        subject: str = "",
        metadata: dict[str, Any] | None = None,
        dedupe_key: str = "",
        ts: float | None = None,
    ) -> Finding:
        merged = dict(metadata or {})
        merged.update(self.extra.get("metadata") or {})
        return Finding(
            sensor=sensor,
            rule_id=self.rule_id,
            severity=normalize_severity(self.severity),
            title=self.title,
            detail=self.detail,
            subject=subject,
            metadata=merged,
            dedupe_key=dedupe_key,
            ts=ts if ts is not None else time.time(),
            ai_eligible=self.ai_eligible,
            dedupe_window_s=self.dedupe_window_s,
        )


# ---------------------------------------------------------------------------
# 进程
# ---------------------------------------------------------------------------
def match_process(
    name: str,
    exe: str,
    cmdline: str,
    parent_name: str | None = None,
) -> list[RuleHit]:
    """Match a newly-started process against the built-in process rules."""

    name = (name or "").strip()
    exe = (exe or "").strip()
    cmdline = (cmdline or "").strip()
    text = f"{name} {exe} {cmdline}".lower()
    hits: list[RuleHit] = []
    seen: set[str] = set()

    for rule in rules_data.PROCESS_RULES:
        pattern = _any_match(rule["patterns"], text)
        if not pattern or rule["id"] in seen:
            continue
        seen.add(rule["id"])
        detail = f"进程 {name or '?'}（{exe or '路径未知'}）命中规则「{rule['title']}」。"
        if cmdline:
            detail += f" 命令行：{cmdline[:400]}"
        hits.append(
            RuleHit(
                rule_id=rule["id"],
                severity=rule["severity"],
                title=rule["title"],
                detail=detail,
                ai_eligible=bool(rule.get("ai_eligible")),
                dedupe_window_s=rules_data.PROCESS_COOLDOWN.get(
                    rule["id"], rules_data.DEDUPE_WINDOW_DEFAULT
                ),
            )
        )

    # 从临时/下载目录执行可执行文件
    if exe:
        lowered = exe.lower()
        extension = "." + lowered.rsplit(".", 1)[-1] if "." in lowered.rsplit("\\", 1)[-1] else ""
        if extension in rules_data.DANGEROUS_EXTENSIONS and winutil.path_under(
            exe, winutil.temp_dirs()
        ):
            hits.append(
                RuleHit(
                    rule_id="proc.temp_exec",
                    severity="MEDIUM",
                    title="从临时/下载目录执行程序",
                    detail=f"进程 {name} 从通常不应运行程序的位置启动：{exe}",
                    ai_eligible=True,
                )
            )

    # 办公软件启动 shell / 脚本宿主（钓鱼宏典型行为）
    if parent_name and name:
        parent_leaf = parent_name.lower()
        child_leaf = name.lower()
        if parent_leaf in rules_data.OFFICE_PARENTS and child_leaf in rules_data.SHELL_CHILDREN:
            hits.append(
                RuleHit(
                    rule_id="proc.office_spawn_shell",
                    severity="HIGH",
                    title="办公软件启动了命令解释器/脚本宿主",
                    detail=(
                        f"{parent_name} 启动了 {name}，这是钓鱼文档宏执行恶意代码的典型行为。"
                        + (f" 命令行：{cmdline[:400]}" if cmdline else "")
                    ),
                    ai_eligible=True,
                )
            )
    return hits


# ---------------------------------------------------------------------------
# 网络
# ---------------------------------------------------------------------------
def match_network_connection(
    remote_ip: str,
    remote_port: int,
    process_name: str,
    is_public: bool,
) -> list[RuleHit]:
    hits: list[RuleHit] = []
    rule = rules_data.SUSPICIOUS_REMOTE_PORTS.get(int(remote_port))
    if rule:
        severity = rule["public" if is_public else "private"]
        hits.append(
            RuleHit(
                rule_id="net.suspicious_remote_port",
                severity=severity,
                title=f"连接到{rule['title']}",
                detail=(
                    f"进程 {process_name or '?'} 连接到 {remote_ip}:{remote_port}，"
                    f"{rule['title']}（{'公网' if is_public else '内网'}地址）。"
                ),
                ai_eligible=normalize_severity(severity) == "HIGH",
            )
        )

    for entry in _blocklist_cache():
        if entry and winutil.ip_in_entries(remote_ip, [entry]):
            hits.append(
                RuleHit(
                    rule_id="net.blocklisted_ip",
                    severity="HIGH",
                    title="连接到黑名单 IP",
                    detail=f"进程 {process_name or '?'} 连接到用户黑名单中的地址 {remote_ip}:{remote_port}。",
                    ai_eligible=True,
                )
            )
            break
    return hits


_BLOCKLIST_CACHE: list[str] = []
_BLOCKLIST_MTIME: float = -1.0


def _blocklist_cache() -> list[str]:
    """Reload data/blocklist.txt only when the file changes."""

    global _BLOCKLIST_CACHE, _BLOCKLIST_MTIME
    try:
        import config

        path = config.BLOCKLIST_PATH
        mtime = path.stat().st_mtime if path.is_file() else 0.0
        if mtime != _BLOCKLIST_MTIME:
            _BLOCKLIST_MTIME = mtime
            _BLOCKLIST_CACHE = config.load_blocklist()
    except Exception:  # noqa: BLE001 - keep previous cache
        pass
    return _BLOCKLIST_CACHE


def match_listener(port: int, bind_ip: str, is_new: bool) -> list[RuleHit]:
    loopback = bind_ip in {"127.0.0.1", "::1", "localhost"} or bind_ip.startswith("127.")
    if loopback:
        return []
    hits: list[RuleHit] = []
    rule = rules_data.RISKY_LISTEN_PORTS.get(int(port))
    if rule:
        hits.append(
            RuleHit(
                rule_id="net.exposed_listener",
                severity=rule["severity"],
                title=rule["title"],
                detail=(
                    f"端口 {port} 监听在 {bind_ip}，可被局域网/公网访问。"
                    "如果 Windows 防火墙已开启且未放行该端口，外部访问仍会被拦截；"
                    "此告警用于提示本机暴露面，可结合「Defender / 防火墙」卡片判断风险。"
                ),
                ai_eligible=rule["severity"] == "HIGH",
                dedupe_window_s=rules_data.DEDUPE_WINDOW_STATE,
            )
        )
    elif is_new:
        hits.append(
            RuleHit(
                rule_id="net.new_listener",
                severity="MEDIUM",
                title="新增对外监听端口",
                detail=f"检测到新的对外监听：{bind_ip}:{port}（此前基线中不存在）。",
                ai_eligible=True,
                dedupe_window_s=rules_data.DEDUPE_WINDOW_STATE,
            )
        )
    return hits


# ---------------------------------------------------------------------------
# 持久化：注册表 Run / 启动目录 / 计划任务 / 服务
# ---------------------------------------------------------------------------
def match_autorun(entry: dict[str, Any], is_new: bool, changed: bool = False) -> list[RuleHit]:
    command = str(entry.get("command") or entry.get("path") or "")
    location = str(entry.get("location") or entry.get("kind") or "")
    name = str(entry.get("name") or "")
    hits: list[RuleHit] = []

    for rule in rules_data.AUTORUN_SUSPICIOUS:
        if _any_match(rule["patterns"], command):
            hits.append(
                RuleHit(
                    rule_id=rule["id"],
                    severity=rule["severity"],
                    title=rule["title"],
                    detail=f"自启动项「{name}」（{location}）指向：{command[:500]}",
                    ai_eligible=True,
                )
            )

    if changed:
        hits.append(
            RuleHit(
                rule_id="persist.autorun_changed",
                severity="MEDIUM",
                title="自启动项被修改",
                detail=f"自启动项「{name}」（{location}）内容发生变化：{command[:400]}",
                dedupe_window_s=rules_data.DEDUPE_WINDOW_STATE,
            )
        )
    elif is_new:
        hits.append(
            RuleHit(
                rule_id="persist.new_autorun",
                severity="MEDIUM",
                title="新增自启动项",
                detail=f"新增自启动项「{name}」（{location}）：{command[:400]}",
                dedupe_window_s=rules_data.DEDUPE_WINDOW_STATE,
            )
        )
    return hits


def match_startup_file(path: str, is_new: bool) -> list[RuleHit]:
    if not is_new:
        return []
    lowered = path.lower()
    extension = "." + lowered.rsplit(".", 1)[-1] if "." in lowered else ""
    if extension in rules_data.STARTUP_DANGEROUS_EXT:
        return [
            RuleHit(
                rule_id="persist.suspicious_startup_file",
                severity="HIGH",
                title="启动目录出现可执行文件",
                detail=f"启动目录新增了可直接执行的项：{path}",
                ai_eligible=True,
                dedupe_window_s=rules_data.DEDUPE_WINDOW_STATE,
            )
        ]
    return [
        RuleHit(
            rule_id="persist.new_startup_file",
            severity="MEDIUM",
            title="启动目录新增条目",
            detail=f"启动目录新增了文件/快捷方式：{path}",
            dedupe_window_s=rules_data.DEDUPE_WINDOW_STATE,
        )
    ]


TASK_SUSPICIOUS_PATTERNS = [
    r"(powershell|pwsh)[^\n]{0,200}(-enc|-encodedcommand|-w(indowstyle)?\s+hidden)",
    r"(mshta|regsvr32|rundll32)[^\n]{0,160}(https?://|javascript:)",
    r"(\\temp\\|\\downloads\\|appdata\\local\\temp)",
    r"[A-Za-z0-9+/]{120,}={0,2}",
]


def match_scheduled_task(
    name: str, execute: str, arguments: str, is_new: bool, changed: bool = False
) -> list[RuleHit]:
    combined = f"{execute} {arguments}".strip()
    hits: list[RuleHit] = []
    for pattern in TASK_SUSPICIOUS_PATTERNS:
        if _compile(pattern).search(combined):
            hits.append(
                RuleHit(
                    rule_id="persist.suspicious_task",
                    severity="HIGH",
                    title="计划任务指向可疑命令",
                    detail=f"计划任务「{name}」执行：{combined[:500]}",
                    ai_eligible=True,
                    dedupe_window_s=rules_data.DEDUPE_WINDOW_STATE,
                )
            )
            break
    if is_new:
        hits.append(
            RuleHit(
                rule_id="persist.new_task",
                severity="MEDIUM",
                title="新增计划任务",
                detail=f"新增计划任务「{name}」：{combined[:400]}",
                dedupe_window_s=rules_data.DEDUPE_WINDOW_STATE,
            )
        )
    elif changed and not any(hit.rule_id == "persist.suspicious_task" for hit in hits):
        hits.append(
            RuleHit(
                rule_id="persist.task_changed",
                severity="MEDIUM",
                title="计划任务命令被修改",
                detail=f"计划任务「{name}」的执行命令发生变化：{combined[:400]}",
                dedupe_window_s=rules_data.DEDUPE_WINDOW_STATE,
            )
        )
    return hits


def match_service(
    name: str, binpath: str, is_new: bool, changed: bool = False
) -> list[RuleHit]:
    hits: list[RuleHit] = []
    suspicious = False
    for pattern, _reason in rules_data.SERVICE_EVENT_SUSPICIOUS:
        if _compile(pattern).search(binpath or ""):
            suspicious = True
            break
    if suspicious:
        hits.append(
            RuleHit(
                rule_id="persist.suspicious_service",
                severity="HIGH",
                title="新服务的程序路径可疑",
                detail=f"服务「{name}」的程序路径为：{binpath[:500]}",
                ai_eligible=True,
                dedupe_window_s=rules_data.DEDUPE_WINDOW_STATE,
            )
        )
    elif is_new:
        hits.append(
            RuleHit(
                rule_id="persist.new_service",
                severity="MEDIUM",
                title="新增系统服务",
                detail=f"检测到新服务「{name}」：{binpath[:400]}",
                dedupe_window_s=rules_data.DEDUPE_WINDOW_STATE,
            )
        )
    elif changed and not suspicious:
        hits.append(
            RuleHit(
                rule_id="persist.service_changed",
                severity="MEDIUM",
                title="系统服务的程序路径被修改",
                detail=f"服务「{name}」的程序路径发生变化：{binpath[:400]}",
                dedupe_window_s=rules_data.DEDUPE_WINDOW_STATE,
            )
        )
    return hits


# ---------------------------------------------------------------------------
# 事件日志
# ---------------------------------------------------------------------------
def match_eventlog(
    log_name: str, event_id: int, message: str, record_id: int | None = None
) -> list[RuleHit]:
    rule = rules_data.EVENTLOG_RULES.get((log_name, int(event_id)))
    if not rule:
        return []
    severity = rule["severity"]
    detail = f"{rule['detail']} 事件日志：{log_name} / EventID {event_id}。"
    if message:
        detail += f" 摘要：{message[:600]}"
    if log_name == "System" and int(event_id) == 7045:
        for pattern, reason in rules_data.SERVICE_EVENT_SUSPICIOUS:
            if _compile(pattern).search(message or ""):
                severity = "HIGH"
                detail += f"（{reason}）"
                break
    ai_eligible = normalize_severity(severity) == "HIGH"
    return [
        RuleHit(
            rule_id=rule["id"],
            severity=severity,
            title=rule["title"],
            detail=detail,
            ai_eligible=ai_eligible,
            dedupe_window_s=rules_data.DEDUPE_WINDOW_LOG
            if rule["id"] != "log.failed_logon"
            else rules_data.DEDUPE_WINDOW_DEFAULT,
        )
    ]


def match_failed_logon_burst(count: int, window_minutes: int) -> list[RuleHit]:
    if count < 8:
        return []
    severity = "HIGH" if count >= 30 else "MEDIUM"
    return [
        RuleHit(
            rule_id="log.failed_logon_burst",
            severity=severity,
            title="短时间内多次登录失败（疑似暴力破解）",
            detail=f"{window_minutes} 分钟内检测到 {count} 次登录失败（EventID 4625）。",
            ai_eligible=True,
            dedupe_window_s=1800.0,
        )
    ]


# ---------------------------------------------------------------------------
# Defender / 防火墙状态
# ---------------------------------------------------------------------------
def match_defender(status: dict[str, Any]) -> list[RuleHit]:
    if not status or status.get("available") is False:
        return []
    hits: list[RuleHit] = []
    state = rules_data.DEDUPE_WINDOW_STATE

    def flag(key: str, enabled: bool | None, rule_id: str, title: str, detail: str) -> None:
        if enabled is False:
            hits.append(
                RuleHit(
                    rule_id=rule_id,
                    severity="HIGH",
                    title=title,
                    detail=detail,
                    ai_eligible=True,
                    dedupe_window_s=state,
                )
            )

    flag(
        "am_service",
        status.get("am_service"),
        "defender.service_off",
        "Windows Defender 防病毒服务未运行",
        "Defender 防病毒服务（WinDefend）当前未运行，系统失去主要实时防护。",
    )
    flag(
        "antivirus",
        status.get("antivirus"),
        "defender.antivirus_off",
        "Windows Defender 防病毒功能已关闭",
        "Defender 防病毒功能处于关闭状态，请立即在 Windows 安全中心重新开启。",
    )
    flag(
        "realtime",
        status.get("realtime"),
        "defender.realtime_off",
        "Windows Defender 实时保护已关闭",
        "实时保护关闭后，新出现的恶意程序不会被即时拦截。",
    )
    flag(
        "behavior",
        status.get("behavior"),
        "defender.behavior_off",
        "Windows Defender 行为监控已关闭",
        "行为监控关闭会削弱对未知恶意行为的检测能力。",
    )

    age = status.get("signature_age_days")
    if isinstance(age, (int, float)) and age > 7:
        hits.append(
            RuleHit(
                rule_id="defender.signatures_stale",
                severity="MEDIUM",
                title="Defender 病毒库过旧",
                detail=f"病毒库已 {int(age)} 天未更新（阈值 7 天），建议联网更新。",
                dedupe_window_s=state,
            )
        )

    firewall = status.get("firewall") or {}
    if firewall.get("available"):
        off = [
            label
            for key, label in (
                ("domain", "域网络"),
                ("private", "专用网络"),
                ("public", "公用网络"),
            )
            if firewall.get(key) is False
        ]
        if off:
            hits.append(
                RuleHit(
                    rule_id="firewall.profile_off",
                    severity="HIGH",
                    title="Windows 防火墙有配置文件未开启",
                    detail=f"以下防火墙配置文件处于关闭状态：{'、'.join(off)}。",
                    ai_eligible=True,
                    dedupe_window_s=state,
                )
            )
    return hits


# ---------------------------------------------------------------------------
# 文件 / 配置完整性
# ---------------------------------------------------------------------------
FILEGUARD_RULES: dict[str, dict] = {
    "hosts_changed": {
        "id": "file.hosts_changed",
        "severity": "HIGH",
        "title": "hosts 文件被修改",
        "detail": "hosts 文件内容发生变化，可能被用于劫持域名或阻断安全软件更新。",
    },
    "canary_changed": {
        "id": "file.canary_changed",
        "severity": "HIGH",
        "title": "勒索诱饵文件被修改",
        "detail": "诱饵文件内容被改动，可能存在批量文件加密行为。",
    },
    "canary_missing": {
        "id": "file.canary_missing",
        "severity": "HIGH",
        "title": "勒索诱饵文件被删除",
        "detail": "诱饵文件消失，可能存在恶意删除/加密行为。",
    },
    "exclusion_added": {
        "id": "defender.exclusion_added",
        "severity": "HIGH",
        "title": "新增 Defender 排除项",
        "detail": "Defender 排除列表中新增了路径/进程，攻击者常用此方式绕过查杀。",
    },
    "startup_changed": {
        "id": "persist.startup_changed",
        "severity": "MEDIUM",
        "title": "启动目录内容发生变化",
        "detail": "启动目录中的文件发生变化。",
    },
}


def match_fileguard(kind: str, path: str, detail: str = "") -> list[RuleHit]:
    rule = FILEGUARD_RULES.get(kind)
    if not rule:
        return []
    return [
        RuleHit(
            rule_id=rule["id"],
            severity=rule["severity"],
            title=rule["title"],
            detail=detail or f"{rule['detail']} 路径：{path}",
            ai_eligible=normalize_severity(rule["severity"]) == "HIGH",
            dedupe_window_s=rules_data.DEDUPE_WINDOW_STATE,
        )
    ]


# ---------------------------------------------------------------------------
# 系统暴露面
# ---------------------------------------------------------------------------
def match_exposure(check_id: str, active: bool, detail: str = "") -> list[RuleHit]:
    if not active:
        return []
    rule = rules_data.EXPOSURE_CHECKS.get(check_id)
    if not rule:
        return []
    return [
        RuleHit(
            rule_id=check_id,
            severity=rule["severity"],
            title=rule["title"],
            detail=detail or rule["detail"],
            dedupe_window_s=rules_data.DEDUPE_WINDOW_EXPOSURE,
        )
    ]


# ---------------------------------------------------------------------------
# 白名单 / 过滤器
# ---------------------------------------------------------------------------
def is_allowlisted(finding: Finding, cfg: dict[str, Any]) -> bool:
    allow = cfg.get("allowlist") or {}
    if finding.rule_id in {str(item) for item in allow.get("suppress_rules", [])}:
        return True

    if finding.sensor == "process":
        meta = finding.metadata or {}
        name = str(meta.get("process_name") or "").lower()
        allow_names = {str(item).lower() for item in allow.get("process_names", [])}
        if name and name in allow_names:
            return True
        cmdline = str(meta.get("cmdline") or "").lower()
        for marker in allow.get("cmdline_contains", []):
            if marker and str(marker).lower() in cmdline:
                return True
        exe = str(meta.get("exe") or "").lower()
        for prefix in allow.get("paths", []):
            if prefix and exe.startswith(str(prefix).lower()):
                return True

    if finding.sensor == "network":
        meta = finding.metadata or {}
        remote_ip = str(meta.get("remote_ip") or "")
        if remote_ip and remote_ip in {str(item) for item in allow.get("remote_ips", [])}:
            return True
    return False


def filter_findings(findings: list[Finding], cfg: dict[str, Any]) -> list[Finding]:
    return [finding for finding in findings if not is_allowlisted(finding, cfg)]
