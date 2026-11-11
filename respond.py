"""WHX 哨兵 · 通知与处置动作。

安全原则：
- 默认只告警、不自动改动系统；
- 会改动系统的动作（防火墙封锁、结束进程、Defender 扫描/更新）都需要
  用户在看板上手动点击确认，且多数需要管理员权限；
- 每个动作都写入 actions 表，便于审计。
"""

from __future__ import annotations

import ipaddress
import logging
import os
import signal
import threading
import time
from typing import Any

import ai
import rules_data
import winutil

logger = logging.getLogger("whx.sentinel.respond")

_TOAST_APPID = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe"


def _result(ok: bool, message: str, **detail: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"ok": bool(ok), "message": str(message)[:500]}
    if detail:
        payload["detail"] = detail
    return payload


# ---------------------------------------------------------------------------
# Windows 通知（Toast）
# ---------------------------------------------------------------------------
def send_toast(title: str, message: str, timeout: float = 20.0) -> tuple[bool, str]:
    """Show a native Windows notification (NotifyIcon balloon, no package identity needed).

    新版 Windows 对未打包进程的 WinRT Toast 有限制（no package identity），
    因此改用 System.Windows.Forms.NotifyIcon 的气泡通知；Win10/Win11 会把它
    作为普通系统通知展示，且不要求管理员权限。
    """

    if not winutil.IS_WINDOWS:
        return False, "仅支持 Windows"
    safe_title = str(title).replace("\r", " ").replace("\n", " ")[:80]
    safe_message = str(message).replace("\r", " ").replace("\n", " ")[:300]
    script = (
        "$ErrorActionPreference='Stop';"
        "Add-Type -AssemblyName System.Windows.Forms;"
        "Add-Type -AssemblyName System.Drawing;"
        "$n = New-Object System.Windows.Forms.NotifyIcon;"
        "$n.Icon = [System.Drawing.SystemIcons]::Warning;"
        f"$n.BalloonTipTitle = {winutil.ps_quote(safe_title)};"
        f"$n.BalloonTipText = {winutil.ps_quote(safe_message)};"
        "$n.Visible = $true;"
        "$n.ShowBalloonTip(6000);"
        "Start-Sleep -Seconds 6;"
        "$n.Dispose();"
        "'ok'"
    )
    try:
        output = winutil.run_ps_text(script, timeout=timeout)
        return True, "notification shown" if "ok" in output.lower() else "notification sent"
    except winutil.ProbeError as exc:
        logger.info("系统通知发送失败：%s", exc)
        return False, str(exc)


# ---------------------------------------------------------------------------
# 系统动作
# ---------------------------------------------------------------------------
def open_security_center() -> dict[str, Any]:
    try:
        winutil.spawn_hidden(["cmd", "/c", "start", "", "windowsdefender://"])
        return _result(True, "已打开 Windows 安全中心")
    except OSError:
        try:
            winutil.spawn_hidden(["cmd", "/c", "start", "", "ms-settings:windowsdefender"])
            return _result(True, "已打开 Windows 安全设置")
        except OSError as exc:
            return _result(False, f"无法打开 Windows 安全中心：{exc}")


def defender_quick_scan() -> dict[str, Any]:
    if not winutil.is_admin():
        return _result(
            False,
            "需要管理员权限。请用 install/start_elevated.bat（会弹 UAC）启动哨兵后再试。",
        )
    try:
        winutil.run_powershell_detached("Start-MpScan -ScanType QuickScan")
        return _result(True, "已启动 Defender 快速扫描（后台运行，结果见 Windows 安全中心）")
    except OSError as exc:
        return _result(False, f"启动扫描失败：{exc}")


def defender_update() -> dict[str, Any]:
    if not winutil.is_admin():
        return _result(
            False,
            "需要管理员权限。请用 install/start_elevated.bat（会弹 UAC）启动哨兵后再试。",
        )
    try:
        winutil.run_powershell_detached("Update-MpSignature")
        return _result(True, "已开始更新 Defender 病毒库（后台运行）")
    except OSError as exc:
        return _result(False, f"更新病毒库失败：{exc}")


def _valid_firewall_ip(ip: str) -> str | None:
    try:
        address = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        return None
    return str(address)


def block_ip(ip: str) -> dict[str, Any]:
    address = _valid_firewall_ip(ip)
    if not address:
        return _result(False, "不是可封锁的有效 IP（拒绝回环/组播/未指定地址）")
    if not winutil.is_admin():
        return _result(
            False,
            "封锁 IP 需要管理员权限。请用 install/start_elevated.bat（会弹 UAC）启动哨兵。",
        )
    name_out = f"WHX Sentinel Block {address} (out)"
    name_in = f"WHX Sentinel Block {address} (in)"
    script = (
        "$ErrorActionPreference='Stop';"
        f"$existing = Get-NetFirewallRule -DisplayName 'WHX Sentinel Block {address}*' "
        "-ErrorAction SilentlyContinue;"
        "if ($existing) { $existing | Remove-NetFirewallRule -ErrorAction SilentlyContinue };"
        f"New-NetFirewallRule -DisplayName '{name_out}' -Direction Outbound -Action Block "
        f"-RemoteAddress '{address}' -Profile Any | Out-Null;"
        f"New-NetFirewallRule -DisplayName '{name_in}' -Direction Inbound -Action Block "
        f"-RemoteAddress '{address}' -Profile Any | Out-Null;"
        "'ok'"
    )
    try:
        winutil.run_ps_text(script, timeout=25)
        return _result(True, f"已在 Windows 防火墙中封锁 {address}（入站+出站，重启后仍有效）")
    except winutil.ProbeError as exc:
        return _result(False, f"封锁失败：{exc}")


def unblock_ip(ip: str) -> dict[str, Any]:
    address = _valid_firewall_ip(ip)
    if not address:
        return _result(False, "不是有效的 IP")
    if not winutil.is_admin():
        return _result(False, "解除封锁需要管理员权限。")
    script = (
        "$ErrorActionPreference='Stop';"
        f"$existing = Get-NetFirewallRule -DisplayName 'WHX Sentinel Block {address}*' "
        "-ErrorAction SilentlyContinue;"
        "if (!$existing) { 'none' } else { $existing | Remove-NetFirewallRule; 'removed' }"
    )
    try:
        output = winutil.run_ps_text(script, timeout=25).strip().lower()
        if "removed" in output:
            return _result(True, f"已解除对 {address} 的封锁")
        return _result(True, f"没有找到 {address} 的哨兵封锁规则")
    except winutil.ProbeError as exc:
        return _result(False, f"解除封锁失败：{exc}")


def kill_process(pid: int, event_id: int | None = None) -> dict[str, Any]:
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return _result(False, "无效的进程 PID")
    # Low-3：PID 0/4 等系统内核进程直接拒绝（避免被诱导杀关键进程）
    if pid <= 4:
        return _result(False, f"PID {pid} 属于系统内核进程，哨兵拒绝结束它")
    if pid == os.getpid():
        return _result(False, "不能结束哨兵自身")
    try:
        import psutil
    except ImportError:
        return _result(False, "psutil 不可用")
    try:
        process = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return _result(False, f"进程 {pid} 已不存在")
    try:
        name = (process.name() or "").lower()
        exe = ""
        try:
            exe = process.exe() or ""
        except (psutil.AccessDenied, OSError):
            exe = ""
        if name in rules_data.PROTECTED_PROCESS_NAMES:
            return _result(False, f"{name} 是关键系统进程，哨兵拒绝结束它")
        owner = ""
        try:
            owner = process.username() or ""
        except (psutil.AccessDenied, OSError):
            owner = ""
        current_user = winutil.username().lower()
        if owner and current_user not in owner.lower() and not winutil.is_admin():
            return _result(False, "该进程属于其他用户，需要管理员权限才能结束")
        process.terminate()
        try:
            process.wait(timeout=4)
        except psutil.TimeoutExpired:
            process.kill()
        return _result(True, f"已结束进程 {name or pid}（PID {pid}）", exe=exe)
    except psutil.AccessDenied:
        return _result(False, "没有权限结束该进程（需要管理员权限）")
    except psutil.NoSuchProcess:
        return _result(False, f"进程 {pid} 已退出")
    except OSError as exc:
        return _result(False, f"结束进程失败：{exc}")


# ---------------------------------------------------------------------------
# 看板动作分发
# ---------------------------------------------------------------------------
def _event_id_from(payload: dict[str, Any]) -> int | None:
    value = payload.get("event_id")
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _handle_scan(core, payload):
    result = defender_quick_scan()
    core.db.record_action(_event_id_from(payload), "defender_scan", "Defender", result["message"], result["ok"])
    return result


def _handle_update(core, payload):
    result = defender_update()
    core.db.record_action(None, "defender_update", "Defender", result["message"], result["ok"])
    return result


def _handle_open_security(core, payload):
    return open_security_center()


def _handle_block_ip(core, payload):
    result = block_ip(str(payload.get("ip") or ""))
    core.db.record_action(_event_id_from(payload), "block_ip", str(payload.get("ip") or ""), result["message"], result["ok"])
    return result


def _handle_unblock_ip(core, payload):
    result = unblock_ip(str(payload.get("ip") or ""))
    core.db.record_action(_event_id_from(payload), "unblock_ip", str(payload.get("ip") or ""), result["message"], result["ok"])
    return result


def _handle_kill(core, payload):
    result = kill_process(payload.get("pid"), _event_id_from(payload))
    core.db.record_action(
        _event_id_from(payload),
        "kill_process",
        f"pid={payload.get('pid')}",
        result["message"],
        result["ok"],
    )
    return result


def _handle_ack(core, payload):
    event_id = _event_id_from(payload)
    if not event_id:
        return _result(False, "缺少 event_id")
    ok = core.db.mark_status(event_id, "ack")
    core.db.record_action(event_id, "ack_event", "", "用户已确认", ok)
    return _result(ok, "事件已确认" if ok else "事件不存在")


def _handle_ignore(core, payload):
    event_id = _event_id_from(payload)
    if not event_id:
        return _result(False, "缺少 event_id")
    ok = core.db.mark_status(event_id, "ignored")
    core.db.record_action(event_id, "ignore_event", "", "用户已忽略", ok)
    return _result(ok, "事件已忽略" if ok else "事件不存在")


def _handle_ai(core, payload):
    event_id = _event_id_from(payload)
    if not event_id:
        return _result(False, "缺少 event_id")
    event = core.db.get_event(event_id)
    if not event:
        return _result(False, "事件不存在")
    result = ai.analyze(event, core.cfg)
    if not result:
        return _result(
            False,
            "本地 AI 暂时不可用：请确认 Ollama 正在运行且已安装 "
            f"{core.cfg.get('ai_model')}（或关闭 AI 研判）。",
        )
    note = ai.note_text(result)
    core.db.set_ai_note(event_id, note, str(result.get("engine") or "ollama"))
    core.db.record_action(event_id, "ai_analyze", str(result.get("engine") or ""), note, True)
    return _result(True, "AI 研判完成", note=note, ai=result)


def _handle_reset_baseline(core, payload):
    core.reset_baselines()
    core.db.record_action(None, "reset_baseline", "", "重建自启动/监听/排除项基线", True)
    return _result(True, "基线已重置：下一轮采集会重新学习现状，期间不产生「新增」类告警")


def _handle_test_toast(core, payload):
    ok, detail = send_toast("通知测试", "如果你看到这条通知，说明告警弹窗工作正常。")
    core.db.record_action(None, "test_toast", "", detail, ok)
    return _result(ok, "通知已发送" if ok else f"通知发送失败：{detail}")


def _handle_shutdown(core, payload):
    core.request_shutdown()
    core.db.record_action(None, "shutdown", "", "用户从看板停止哨兵", True)
    return _result(True, "哨兵正在退出…")


_HANDLERS = {
    "scan": _handle_scan,
    "defender_scan": _handle_scan,
    "defender_update": _handle_update,
    "open_security_center": _handle_open_security,
    "block_ip": _handle_block_ip,
    "unblock_ip": _handle_unblock_ip,
    "kill_process": _handle_kill,
    "ack_event": _handle_ack,
    "ignore_event": _handle_ignore,
    "ai_analyze": _handle_ai,
    "reset_baseline": _handle_reset_baseline,
    "test_toast": _handle_test_toast,
    "shutdown": _handle_shutdown,
}

ACTION_NAMES = {
    "scan": "Defender 快速扫描",
    "defender_scan": "Defender 快速扫描",
    "defender_update": "更新病毒库",
    "open_security_center": "打开安全中心",
    "block_ip": "防火墙封锁 IP",
    "unblock_ip": "解除 IP 封锁",
    "kill_process": "结束进程",
    "ack_event": "确认事件",
    "ignore_event": "忽略事件",
    "ai_analyze": "AI 研判",
    "reset_baseline": "重置基线",
    "test_toast": "测试通知",
    "shutdown": "停止哨兵",
}


def execute(core, action: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    handler = _HANDLERS.get(str(action))
    if handler is None:
        return _result(False, f"未知动作：{action}")
    try:
        return handler(core, payload or {})
    except Exception as exc:  # noqa: BLE001 - 动作失败不应拖垮服务
        logger.exception("动作 %s 执行失败", action)
        return _result(False, f"动作执行失败：{exc}")


# ---------------------------------------------------------------------------
# 自动处置（默认关闭，由设置显式开启）
# ---------------------------------------------------------------------------
def auto_react(core, event: dict[str, Any]) -> None:
    cfg = core.cfg
    severity = str(event.get("severity") or "")
    rule_id = str(event.get("rule_id") or "")
    metadata = event.get("metadata") or {}
    try:
        if cfg.get("auto_quick_scan_on_malware") and rule_id == "defender.malware_detected":
            result = defender_quick_scan()
            core.db.record_action(event.get("id"), "auto_defender_scan", rule_id, result["message"], result["ok"])
            return
        if cfg.get("auto_block_high_remote") and severity == "HIGH":
            remote_ip = str(metadata.get("remote_ip") or "")
            if remote_ip and winutil.is_public_ip(remote_ip):
                result = block_ip(remote_ip)
                core.db.record_action(event.get("id"), "auto_block_ip", remote_ip, result["message"], result["ok"])
    except Exception:  # noqa: BLE001 - 自动处置失败只记录
        logger.exception("自动处置失败")
