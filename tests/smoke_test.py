#!/usr/bin/env python3
"""WHX 哨兵 · 自动化冒烟测试（无副作用）。

用法：
    python tests/smoke_test.py
    python sentinel.py --smoke-test

覆盖范围：
    * compileall 编译项目全部 .py
    * rules.py 各匹配器（进程 / Defender / 防火墙 / 事件日志 / 监听端口 /
      网络连接 / 自启动 / 启动目录 / 计划任务 / 服务 / 文件完整性 / 暴露面）
      的正例与反例
    * 白名单过滤（cmdline_contains / process_names / paths / remote_ips / suppress_rules）
    * db.py：插入、去重合并（seen_count）、统计、24 小时时间线、标记状态、
      actions、prune、metadata、导出
    * config.py：临时数据目录下首次加载自动生成 token、保存/重载、损坏配置自愈
    * SentinelCore + webapi.create_app：用 FastAPI TestClient 请求
      /api/health、/api/status、/api/events、/api/timeline、/api/settings、
      /api/actions/*、/api/allowlist、/api/export；GET /api/token 在 TestClient
      下必须 403（非回环客户端），写接口用 core.cfg["control_token"] 直连
    * web/ 前端资产存在性与 app.js 语法（node --check，缺失时 SKIP）
    * install/ 六个启动脚本的存在性 / 编码 / 关键内容
    * 交付文档 README.md 关键章节

安全约束（本脚本刻意不做任何有副作用的系统操作）：
    * 不调用 core.start()，不启动传感器/分析管线线程；
    * 不发送 Windows Toast，不执行 Defender 扫描/更新，不修改防火墙，
      不写注册表自启动，不结束进程；
    * 所有临时数据只写入项目目录下的 _smoke_data，测试结束（含异常）自动删除。

退出码：全部 PASS（允许 SKIP）为 0；出现 FAIL 为 1。
"""

from __future__ import annotations

import compileall
import contextlib
import io
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Callable

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

SMOKE_DIR = BASE_DIR / "_smoke_data"

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"
RESULTS: list[tuple[str, str, str, str]] = []  # (status, group, name, detail)

# 惰性共享的测试夹具（同一个进程内复用）
_DB: dict[str, Any] = {}
_CONFIG: dict[str, Any] = {}
_CORE: dict[str, Any] = {}
_RULES_READY = False

# compileall / 文件枚举时跳过的目录（临时数据、缓存、历史自测残留）
_SKIP_RX = re.compile(
    r"(?i)[\\/](?:__pycache__|_smoke_data|_runtime_test|_selftest_app|\.git|\.hg|\.svn)(?:[\\/]|$)"
)


# ---------------------------------------------------------------------------
# 测试运行器
# ---------------------------------------------------------------------------
class SkipTest(Exception):
    """当前检查项无法执行（依赖尚未交付或缺少外部工具），记为 SKIP。"""


def check(condition: Any, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def run_case(group: str, name: str, func: Callable[[], Any]) -> None:
    started = time.perf_counter()
    detail = ""
    try:
        detail = str(func() or "")
        status = PASS
    except SkipTest as exc:
        status, detail = SKIP, str(exc)
    except Exception as exc:  # noqa: BLE001 - 汇总所有失败项，不中断后续用例
        status = FAIL
        detail = f"{type(exc).__name__}: {exc}"
        if os.environ.get("SMOKE_VERBOSE"):
            traceback.print_exc()
    elapsed_ms = (time.perf_counter() - started) * 1000
    RESULTS.append((status, group, name, detail))
    suffix = f"：{detail}" if detail else ""
    if status == FAIL:
        suffix += f"  [{elapsed_ms:.0f} ms]"
    print(f"[{status}] {group} · {name}{suffix}", flush=True)


def _configure_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream is not None:
                stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - 老版本/重定向流没有 reconfigure
            pass


def _cleanup() -> None:
    """关闭可能占用 _smoke_data 的句柄，然后删除临时数据目录。"""

    client = _CORE.pop("client", None)
    if client is not None:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass
    core = _CORE.pop("core", None)
    if core is not None:
        try:
            core.db.close()
        except Exception:  # noqa: BLE001
            pass
    database = _DB.pop("db", None)
    if database is not None:
        try:
            database.close()
        except Exception:  # noqa: BLE001
            pass
    _CONFIG.clear()

    # 关闭 core 注册的日志文件句柄，否则 Windows 上 rmtree 会因文件占用失败
    root = logging.getLogger("whx.sentinel")
    for handler in list(root.handlers):
        try:
            handler.close()
        except Exception:  # noqa: BLE001
            pass
        root.removeHandler(handler)

    for _attempt in range(6):
        try:
            if SMOKE_DIR.exists():
                shutil.rmtree(SMOKE_DIR)
            return
        except OSError:
            time.sleep(0.3)


def _py_files() -> list[Path]:
    return [path for path in BASE_DIR.rglob("*.py") if not _SKIP_RX.search(str(path))]


def _relative(path: Path) -> str:
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return str(path)


# ---------------------------------------------------------------------------
# 0. compileall
# ---------------------------------------------------------------------------
def case_compileall() -> str:
    files = _py_files()
    check(files, f"在 {BASE_DIR} 下没有找到任何 .py 文件")
    output = io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
        ok = compileall.compile_dir(str(BASE_DIR), quiet=1, force=True, rx=_SKIP_RX)
    text = output.getvalue().strip()
    check(ok, f"compileall 编译失败：{text[-1200:] or '无错误输出'}")
    check("SyntaxError" not in text, f"compileall 输出包含语法错误：{text[-1200:]}")
    return f"{len(files)} 个 .py 文件全部编译通过"


# ---------------------------------------------------------------------------
# 1. rules.py 匹配器（正例 + 反例）
# ---------------------------------------------------------------------------
def _rules():
    """初始化 rules 的测试环境：黑名单指向不存在的临时文件，保证结果可重复。"""

    global _RULES_READY
    if not _RULES_READY:
        import config

        config.configure(SMOKE_DIR / "rules")
        _RULES_READY = True
    import rules

    return rules


def case_match_process_positive() -> str:
    rules = _rules()
    hits = rules.match_process(
        "powershell.exe",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell.exe -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQ==",
    )
    ids = {hit.rule_id for hit in hits}
    check("proc.ps_encoded" in ids, f"未命中 proc.ps_encoded，实际命中：{sorted(ids)}")
    return "PowerShell -EncodedCommand -> proc.ps_encoded"


def case_match_process_negative() -> str:
    rules = _rules()
    hits = rules.match_process(
        "notepad.exe",
        r"C:\Windows\System32\notepad.exe",
        r"notepad.exe C:\Users\Public\note.txt",
    )
    check(not hits, f"正常进程被误报：{[hit.rule_id for hit in hits]}")
    return "正常记事本进程 0 告警"


def case_match_process_temp_exec() -> str:
    import tempfile

    rules = _rules()
    exe = str(Path(tempfile.gettempdir()) / "whx_smoke_demo.exe")
    hits = rules.match_process("whx_smoke_demo.exe", exe, exe)
    ids = {hit.rule_id for hit in hits}
    check("proc.temp_exec" in ids, f"临时目录执行未告警，实际：{sorted(ids)}")
    return "临时目录执行 -> proc.temp_exec"


def case_match_process_office_spawn() -> str:
    rules = _rules()
    hits = rules.match_process(
        "cmd.exe", r"C:\Windows\System32\cmd.exe", "cmd.exe /c calc.exe", parent_name="winword.exe"
    )
    ids = {hit.rule_id for hit in hits}
    check("proc.office_spawn_shell" in ids, f"办公软件派生 shell 未告警，实际：{sorted(ids)}")
    return "winword -> cmd -> proc.office_spawn_shell"


def case_match_defender_positive() -> str:
    rules = _rules()
    hits = rules.match_defender(
        {
            "available": True,
            "am_service": True,
            "antivirus": True,
            "realtime": False,
            "behavior": True,
            "signature_age_days": 2,
            "firewall": {"available": True, "domain": True, "private": True, "public": True},
        }
    )
    ids = {hit.rule_id for hit in hits}
    check("defender.realtime_off" in ids, f"实时保护关闭未告警，实际：{sorted(ids)}")
    return "实时保护关闭 -> defender.realtime_off"


def case_match_defender_negative() -> str:
    rules = _rules()
    hits = rules.match_defender(
        {
            "available": True,
            "am_service": True,
            "antivirus": True,
            "realtime": True,
            "behavior": True,
            "signature_age_days": 1,
            "firewall": {"available": True, "domain": True, "private": True, "public": True},
        }
    )
    check(not hits, f"Defender 全部正常时不应告警，实际：{[hit.rule_id for hit in hits]}")
    return "Defender 正常状态 0 告警"


def case_match_defender_stale_signature() -> str:
    rules = _rules()
    stale = rules.match_defender({"available": True, "realtime": True, "signature_age_days": 12})
    fresh = rules.match_defender({"available": True, "realtime": True, "signature_age_days": 1})
    check(
        any(hit.rule_id == "defender.signatures_stale" for hit in stale),
        f"病毒库过旧未告警，实际：{[hit.rule_id for hit in stale]}",
    )
    check(not any(hit.rule_id == "defender.signatures_stale" for hit in fresh), "病毒库较新时不应告警")
    return "病毒库 12 天 -> 告警 / 1 天 -> 不告警"


def case_match_firewall_positive() -> str:
    rules = _rules()
    hits = rules.match_defender(
        {
            "available": True,
            "realtime": True,
            "firewall": {"available": True, "domain": True, "private": True, "public": False},
        }
    )
    ids = {hit.rule_id for hit in hits}
    check("firewall.profile_off" in ids, f"防火墙配置文件关闭未告警，实际：{sorted(ids)}")
    return "公用网络防火墙关闭 -> firewall.profile_off"


def case_match_firewall_negative() -> str:
    rules = _rules()
    hits = rules.match_defender(
        {
            "available": True,
            "realtime": True,
            "firewall": {"available": True, "domain": True, "private": True, "public": True},
        }
    )
    check(not hits, f"防火墙全部开启时不应告警，实际：{[hit.rule_id for hit in hits]}")
    return "防火墙全部开启 0 告警"


def case_match_eventlog_positive() -> str:
    rules = _rules()
    hits = rules.match_eventlog("Security", 1102, "The audit log was cleared.")
    check(
        any(hit.rule_id == "log.security_log_cleared" and hit.severity == "HIGH" for hit in hits),
        f"安全日志清除未告警，实际：{[(hit.rule_id, hit.severity) for hit in hits]}",
    )
    return "Security 1102 -> log.security_log_cleared HIGH"


def case_match_eventlog_negative() -> str:
    rules = _rules()
    check(not rules.match_eventlog("System", 4625, ""), "非安全日志的 4625 不应命中")
    check(not rules.match_eventlog("Security", 999_999, ""), "未登记的 EventID 不应命中")
    return "未知日志/事件 ID 0 告警"


def case_match_eventlog_service_install() -> str:
    rules = _rules()
    hits = rules.match_eventlog(
        "System", 7045, r"Service File Name: C:\Users\a\AppData\Local\Temp\evil.exe"
    )
    check(
        any(hit.rule_id == "log.service_install" and hit.severity == "HIGH" for hit in hits),
        f"可疑服务安装未升级为 HIGH，实际：{[(hit.rule_id, hit.severity) for hit in hits]}",
    )
    return "7045 + 临时目录路径 -> HIGH"


def case_match_listener_positive() -> str:
    rules = _rules()
    hits = rules.match_listener(3389, "0.0.0.0", True)
    check(
        any(hit.rule_id == "net.exposed_listener" and hit.severity == "HIGH" for hit in hits),
        f"RDP 对外监听未告警，实际：{[(hit.rule_id, hit.severity) for hit in hits]}",
    )
    return "3389 监听 0.0.0.0 -> net.exposed_listener HIGH"


def case_match_listener_negative() -> str:
    rules = _rules()
    check(not rules.match_listener(3389, "127.0.0.1", True), "回环监听不应告警")
    check(not rules.match_listener(8080, "0.0.0.0", False), "非高危端口且非新增不应告警")
    return "回环 / 非新增普通端口 0 告警"


def case_match_listener_new_port() -> str:
    rules = _rules()
    hits = rules.match_listener(8080, "0.0.0.0", True)
    ids = {hit.rule_id for hit in hits}
    check("net.new_listener" in ids, f"新增对外监听未告警，实际：{sorted(ids)}")
    return "新增 8080 对外监听 -> net.new_listener"


def case_match_network_connection_positive() -> str:
    rules = _rules()
    hits = rules.match_network_connection("8.8.8.8", 4444, "evil.exe", True)
    check(
        any(hit.rule_id == "net.suspicious_remote_port" and hit.severity == "HIGH" for hit in hits),
        f"反弹 shell 端口外连未告警，实际：{[(hit.rule_id, hit.severity) for hit in hits]}",
    )
    return "8.8.8.8:4444 -> net.suspicious_remote_port HIGH"


def case_match_network_connection_negative() -> str:
    rules = _rules()
    hits = rules.match_network_connection("93.184.216.34", 443, "chrome.exe", True)
    check(not hits, f"普通 HTTPS 外连被误报：{[hit.rule_id for hit in hits]}")
    return "普通 HTTPS 外连 0 告警"


def case_match_autorun_positive() -> str:
    rules = _rules()
    hits = rules.match_autorun(
        {
            "name": "EvilUpdater",
            "location": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "command": "powershell.exe -WindowStyle Hidden -EncodedCommand SQBFAFgA",
        },
        is_new=False,
    )
    ids = {hit.rule_id for hit in hits}
    check("persist.autorun_encoded" in ids, f"可疑自启动命令未告警，实际：{sorted(ids)}")
    return "隐藏编码 PowerShell 自启动 -> persist.autorun_encoded"


def case_match_autorun_negative() -> str:
    rules = _rules()
    hits = rules.match_autorun(
        {
            "name": "OneDrive",
            "location": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "command": r'"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background',
        },
        is_new=False,
    )
    check(not hits, f"正常自启动项被误报：{[hit.rule_id for hit in hits]}")
    return "OneDrive 正常自启动 0 告警"


def case_match_autorun_new_and_changed() -> str:
    rules = _rules()
    entry = {"name": "NormalApp", "location": "HKCU Run", "command": r'"C:\Program Files\App\app.exe" -startup'}
    new_ids = {hit.rule_id for hit in rules.match_autorun(entry, is_new=True)}
    changed_ids = {hit.rule_id for hit in rules.match_autorun(entry, is_new=False, changed=True)}
    check("persist.new_autorun" in new_ids, f"新增自启动未告警，实际：{sorted(new_ids)}")
    check("persist.autorun_changed" in changed_ids, f"自启动修改未告警，实际：{sorted(changed_ids)}")
    return "新增 -> persist.new_autorun / 修改 -> persist.autorun_changed"


def case_match_startup_file_positive() -> str:
    rules = _rules()
    hits = rules.match_startup_file(
        r"C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.bat", True
    )
    check(
        any(hit.rule_id == "persist.suspicious_startup_file" and hit.severity == "HIGH" for hit in hits),
        f"启动目录新增可执行文件未告警，实际：{[(hit.rule_id, hit.severity) for hit in hits]}",
    )
    return "Startup\\evil.bat 新增 -> persist.suspicious_startup_file HIGH"


def case_match_startup_file_negative() -> str:
    rules = _rules()
    path = r"C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\helper.txt"
    check(not rules.match_startup_file(path, False), "非新增启动项不应告警")
    return "已存在/非新增启动文件 0 告警"


def case_match_startup_file_new_link() -> str:
    rules = _rules()
    hits = rules.match_startup_file(
        r"C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\app.lnk", True
    )
    ids = {hit.rule_id for hit in hits}
    check("persist.new_startup_file" in ids, f"启动目录新增快捷方式未告警，实际：{sorted(ids)}")
    return "Startup\\app.lnk 新增 -> persist.new_startup_file"


def case_match_scheduled_task_positive() -> str:
    rules = _rules()
    hits = rules.match_scheduled_task(
        "EvilTask", "powershell.exe", "-EncodedCommand SQBFAFgA", is_new=True
    )
    ids = {hit.rule_id for hit in hits}
    check("persist.suspicious_task" in ids, f"可疑计划任务未告警，实际：{sorted(ids)}")
    check("persist.new_task" in ids, f"新增计划任务未告警，实际：{sorted(ids)}")
    return "powershell 编码命令计划任务 -> persist.suspicious_task + persist.new_task"


def case_match_scheduled_task_negative() -> str:
    rules = _rules()
    hits = rules.match_scheduled_task(
        "OneDrive Update", r"C:\Program Files\Microsoft OneDrive\OneDrive.exe", "/update", is_new=False
    )
    check(not hits, f"正常计划任务被误报：{[hit.rule_id for hit in hits]}")
    return "OneDrive 正常计划任务 0 告警"


def case_match_service_positive() -> str:
    rules = _rules()
    hits = rules.match_service(
        "EvilSvc", r"C:\Users\a\AppData\Local\Temp\evil.exe", is_new=True
    )
    check(
        any(hit.rule_id == "persist.suspicious_service" and hit.severity == "HIGH" for hit in hits),
        f"可疑服务路径未告警，实际：{[(hit.rule_id, hit.severity) for hit in hits]}",
    )
    return "服务指向 Temp -> persist.suspicious_service HIGH"


def case_match_service_negative() -> str:
    rules = _rules()
    hits = rules.match_service("Spooler", r"C:\Windows\System32\spoolsv.exe", is_new=False)
    check(not hits, f"正常服务被误报：{[hit.rule_id for hit in hits]}")
    return "正常打印服务 0 告警"


def case_match_fileguard_positive() -> str:
    rules = _rules()
    hits = rules.match_fileguard("hosts_changed", r"C:\Windows\System32\drivers\etc\hosts")
    check(
        any(hit.rule_id == "file.hosts_changed" and hit.severity == "HIGH" for hit in hits),
        f"hosts 修改未告警，实际：{[(hit.rule_id, hit.severity) for hit in hits]}",
    )
    canary = rules.match_fileguard("canary_missing", r"C:\whx\data\canary\decoy.docx")
    check(
        any(hit.rule_id == "file.canary_missing" for hit in canary),
        f"诱饵文件删除未告警，实际：{[hit.rule_id for hit in canary]}",
    )
    return "hosts 修改 / 诱饵文件删除均告警"


def case_match_fileguard_negative() -> str:
    rules = _rules()
    check(not rules.match_fileguard("unknown_kind", r"C:\any\file.txt"), "未知完整性类型不应告警")
    return "未知 kind 0 告警"


def case_match_exposure_positive() -> str:
    rules = _rules()
    hits = rules.match_exposure("exposure.rdp_enabled", True)
    check(
        any(hit.rule_id == "exposure.rdp_enabled" and hit.severity == "MEDIUM" for hit in hits),
        f"RDP 暴露面未告警，实际：{[(hit.rule_id, hit.severity) for hit in hits]}",
    )
    return "RDP 已开启 -> exposure.rdp_enabled MEDIUM"


def case_match_exposure_negative() -> str:
    rules = _rules()
    check(not rules.match_exposure("exposure.rdp_enabled", False), "检查未命中不应告警")
    check(not rules.match_exposure("exposure.not_exist", True), "未登记的暴露面检查不应告警")
    return "未命中 / 未知检查 0 告警"


def case_match_failed_logon_burst() -> str:
    rules = _rules()
    burst = rules.match_failed_logon_burst(12, 10)
    calm = rules.match_failed_logon_burst(3, 10)
    check(any(hit.rule_id == "log.failed_logon_burst" for hit in burst), "暴力破解阈值未触发")
    check(not calm, f"少量失败不应告警，实际：{[hit.rule_id for hit in calm]}")
    return "10 分钟内 12 次失败 -> 告警 / 3 次 -> 不告警"


# ---------------------------------------------------------------------------
# 2. 白名单过滤
# ---------------------------------------------------------------------------
def _allow_cfg() -> dict[str, Any]:
    return {
        "allowlist": {
            "process_names": ["chrome.exe"],
            "cmdline_contains": ["WHX_SENTINEL_INTERNAL"],
            "paths": ["c:\\tools\\trusted\\"],
            "remote_ips": ["203.0.113.10"],
            "suppress_rules": ["proc.remote_tool"],
        }
    }


def case_allowlist_cmdline_contains() -> str:
    rules = _rules()
    from events import Finding

    cfg = _allow_cfg()
    blocked = Finding(
        sensor="process",
        rule_id="proc.ps_encoded",
        severity="HIGH",
        title="测试",
        metadata={"process_name": "powershell.exe", "cmdline": "powershell -enc AAA WHX_SENTINEL_INTERNAL", "exe": ""},
    )
    normal = Finding(
        sensor="process",
        rule_id="proc.ps_encoded",
        severity="HIGH",
        title="测试",
        metadata={"process_name": "powershell.exe", "cmdline": "powershell -enc AAA", "exe": ""},
    )
    check(rules.is_allowlisted(blocked, cfg), "cmdline_contains 白名单未生效")
    check(not rules.is_allowlisted(normal, cfg), "未命中白名单的事件被误过滤")
    kept = rules.filter_findings([blocked, normal], cfg)
    check(kept == [normal], f"filter_findings 结果错误，保留 {len(kept)} 条")
    return "命令行标记命中 -> 过滤，未命中 -> 保留"


def case_allowlist_process_names_and_paths() -> str:
    rules = _rules()
    from events import Finding

    cfg = _allow_cfg()
    by_name = Finding(
        sensor="process",
        rule_id="proc.test",
        severity="MEDIUM",
        title="测试",
        metadata={"process_name": "Chrome.exe", "cmdline": "chrome", "exe": r"C:\Program Files\Google\Chrome\chrome.exe"},
    )
    by_path = Finding(
        sensor="process",
        rule_id="proc.test",
        severity="MEDIUM",
        title="测试",
        metadata={"process_name": "tool.exe", "cmdline": "tool", "exe": r"C:\Tools\trusted\tool.exe"},
    )
    check(rules.is_allowlisted(by_name, cfg), "process_names 白名单未生效（应大小写不敏感）")
    check(rules.is_allowlisted(by_path, cfg), "paths 白名单未生效")
    return "进程名 / 路径前缀白名单生效"


def case_allowlist_network_and_suppress() -> str:
    rules = _rules()
    from events import Finding

    cfg = _allow_cfg()
    allowed_ip = Finding(
        sensor="network",
        rule_id="net.suspicious_remote_port",
        severity="HIGH",
        title="测试",
        metadata={"remote_ip": "203.0.113.10", "remote_port": 4444},
    )
    suppressed = Finding(sensor="process", rule_id="proc.remote_tool", severity="LOW", title="测试")
    check(rules.is_allowlisted(allowed_ip, cfg), "remote_ips 白名单未生效")
    check(rules.is_allowlisted(suppressed, cfg), "suppress_rules 白名单未生效")
    return "远端 IP / 规则抑制白名单生效"


# ---------------------------------------------------------------------------
# 3. db.py
# ---------------------------------------------------------------------------
def _get_db():
    if "db" not in _DB:
        import db as db_module

        path = SMOKE_DIR / "db" / "sentinel.db"
        database = db_module.Database(path)
        database.init()
        _DB["db"] = database
    return _DB["db"]


def _make_finding(**overrides):
    from events import Finding

    base: dict[str, Any] = {
        "sensor": "process",
        "rule_id": "proc.smoke_db",
        "severity": "HIGH",
        "title": "冒烟测试事件",
        "detail": "短详情",
        "subject": "smoke:db",
        "dedupe_key": "smoke:db:1",
        "ts": time.time() - 60,
    }
    base.update(overrides)
    return Finding(**base)


def case_db_init() -> str:
    database = _get_db()
    check(database.path.is_file(), f"数据库文件未创建：{database.path}")
    return _relative(database.path)


def case_db_insert_and_dedupe() -> str:
    from dataclasses import replace

    database = _get_db()
    first = _make_finding()
    first_id, first_new = database.insert_finding(first)
    check(first_new and first_id > 0, f"首次写入失败：id={first_id} is_new={first_new}")
    _DB["event_id"] = first_id

    second = replace(first, detail="更长更详细的事件说明内容", ts=first.ts + 5)
    second_id, second_new = database.insert_finding(second)
    check(second_id == first_id, "去重窗口内应合并为同一条事件")
    check(second_new is False, "去重窗口内 is_new 应为 False")
    event = database.get_event(first_id)
    check(event is not None, "写入后读取事件失败")
    check(event["seen_count"] == 2, f"seen_count 应为 2，实际 {event['seen_count']}")
    check("更长更详细" in str(event["detail"]), "合并时应保留更长的 detail")

    # 超出 600 秒去重窗口后应生成新事件
    third = replace(first, ts=first.ts + 700)
    third_id, third_new = database.insert_finding(third)
    check(third_new and third_id != first_id, "超出去重窗口应生成新事件")
    _DB["event_id_2"] = third_id
    return f"去重合并 event #{first_id}，窗口外新事件 #{third_id}"


def case_db_stats() -> str:
    database = _get_db()
    stats = database.stats(24)
    check(stats["high_24h"] >= 2, f"high_24h 应 >= 2，实际 {stats['high_24h']}")
    check(stats["events_24h"] >= 2, f"events_24h 应 >= 2，实际 {stats['events_24h']}")
    check(stats["total_events"] >= 2, f"total_events 应 >= 2，实际 {stats['total_events']}")
    check(stats["open_events"] >= 2, f"open_events 应 >= 2，实际 {stats['open_events']}")
    check(isinstance(stats["by_sensor"], list) and stats["by_sensor"], "by_sensor 应为非空列表")
    return f"high_24h={stats['high_24h']} · total={stats['total_events']}"


def case_db_timeline() -> str:
    database = _get_db()
    buckets = database.timeline(24)
    check(len(buckets) == 24, f"24 小时时间线应有 24 个桶，实际 {len(buckets)}")
    for bucket in buckets:
        for key in ("label", "HIGH", "MEDIUM", "LOW", "INFO", "total"):
            check(key in bucket, f"时间线桶缺少字段 {key}")
    total = sum(bucket["total"] for bucket in buckets)
    check(total >= 2, f"时间线应有事件，实际 total={total}")
    check(database.timeline(1) and len(database.timeline(1)) == 1, "hours=1 时间线应只有 1 个桶")
    return f"24 桶 · 合计 {total} 条"


def case_db_mark_status() -> str:
    database = _get_db()
    event_id = _DB["event_id"]
    check(database.mark_status(event_id, "ack") is True, "标记 ack 失败")
    event = database.get_event(event_id)
    check(event and event["status"] == "ack", f"状态应为 ack，实际 {event and event['status']}")
    check(database.mark_status(event_id, "not-a-status") is False, "非法状态应返回 False")
    check(database.mark_status(999_999_999, "ack") is False, "不存在的事件应返回 False")
    return "ack 标记生效，非法状态/不存在事件返回 False"


def case_db_actions() -> str:
    database = _get_db()
    event_id = _DB["event_id"]
    action_id = database.record_action(event_id, "ack_event", "", "用户已确认", True)
    check(action_id > 0, "record_action 应返回自增 id")
    database.record_action(None, "test_toast", "", "冒烟测试不应真的发通知", False)
    actions = database.recent_actions(10)
    check(actions, "recent_actions 不应为空")
    check(
        any(item["action"] == "ack_event" and item["event_id"] == event_id for item in actions),
        "recent_actions 中未找到 ack_event",
    )
    return f"actions 记录 {len(actions)} 条"


def case_db_list_events() -> str:
    database = _get_db()
    rows, total = database.list_events(limit=10, severity="HIGH")
    check(total >= 2, f"HIGH 事件应 >= 2，实际 {total}")
    check(all(row["severity"] == "HIGH" for row in rows), "severity 过滤结果包含非 HIGH 事件")
    searched, search_total = database.list_events(query="冒烟测试")
    check(search_total >= 1, "关键字搜索未命中事件")
    acked, acked_total = database.list_events(status="ack")
    check(acked_total >= 1, "status 过滤未命中事件")
    exported = database.export(limit=10)
    check(len(exported) >= 1, "export 不应为空")
    return f"总数 {database.count()} · 搜索结果 {search_total}"


def case_db_prune() -> str:
    database = _get_db()
    old = _make_finding(
        dedupe_key="smoke:db:old",
        title="40 天前的过期事件",
        ts=time.time() - 40 * 86400,
    )
    old_id, is_new = database.insert_finding(old)
    check(is_new and old_id > 0, "过期事件写入失败")
    before = database.count()
    removed = database.prune(30, 20000)
    after = database.count()
    check(removed >= 1, f"prune 应至少删除 1 条过期事件，实际 {removed}")
    check(after < before, f"prune 后总数应减少：{before} -> {after}")
    check(database.get_event(old_id) is None, "过期事件应已被删除")
    # 未过期的近期事件应保留
    check(database.get_event(_DB["event_id"]) is not None, "prune 不应删除近期事件")
    return f"删除 {removed} 条过期事件，{before} -> {after}"


def case_db_metadata() -> str:
    database = _get_db()
    database.set_meta("smoke_meta", {"reset": True, "n": 3})
    check(database.get_meta("smoke_meta") == {"reset": True, "n": 3}, "metadata 读写不一致")
    check(database.get_meta("smoke_missing", "fallback") == "fallback", "metadata 默认值未生效")
    return "set_meta / get_meta 正常"


# ---------------------------------------------------------------------------
# 4. config.py
# ---------------------------------------------------------------------------
def case_config_generate_token() -> str:
    import config

    cfg_dir = SMOKE_DIR / "config"
    config.configure(cfg_dir)
    _CONFIG["dir"] = cfg_dir
    cfg = config.load_config()
    check(config.CONFIG_PATH.is_file(), f"配置文件未生成：{config.CONFIG_PATH}")
    token = cfg.get("control_token")
    check(isinstance(token, str) and len(token) >= 20, f"control_token 应自动生成，实际：{token!r}")
    check(float(cfg.get("first_run_ts") or 0) > 0, "first_run_ts 应自动写入")
    check(cfg.get("host") == "127.0.0.1" and int(cfg.get("port")) == 8765, "默认监听地址/端口不对")
    marker = str(cfg.get("internal_marker") or "")
    check(
        marker.startswith("WHX_SENTINEL_") and len(marker) >= 24,
        f"内部探针标记应随机生成，实际：{marker!r}",
    )
    check(
        marker in (cfg.get("allowlist") or {}).get("cmdline_contains", []),
        "白名单应包含本次安装的随机探针标记",
    )
    check(cfg.get("ai_enabled") is False, "默认应关闭 AI 研判（无 Ollama 机器不走失败路径）")
    for bad_url in (
        "http://127.0.0.1@evil.example",
        "http://127.0.0.1.attacker.example",
        "https://8.8.8.8:11434",
        "http://127.0.0.1:9999",
    ):
        try:
            config.validate_ollama_url(bad_url)
        except ValueError:
            continue
        check(False, f"ollama_url 应拒绝非回环/非常用端口地址：{bad_url}")
    check(
        config.validate_ollama_url("http://127.0.0.1:11434") == "http://127.0.0.1:11434",
        "合法 ollama_url 应通过校验",
    )
    check(config.LOG_DIR.is_dir(), "日志目录未创建")
    # 再次加载不应更换 token
    reloaded = config.load_config()
    check(reloaded["control_token"] == token, "重新加载配置时 token 不应变化")
    _CONFIG["token"] = token
    return f"token 长度 {len(token)} · 配置 {_relative(config.CONFIG_PATH)}"


def case_config_save_reload() -> str:
    import config

    cfg = config.load_config()
    cfg["retention_days"] = 7
    cfg["toast_min_severity"] = "MEDIUM"
    config.save_config(cfg)
    raw = json.loads(config.CONFIG_PATH.read_text(encoding="utf-8"))
    check(raw["retention_days"] == 7, "配置文件未写入 retention_days=7")
    reloaded = config.load_config()
    check(reloaded["retention_days"] == 7, "重新加载后 retention_days 不为 7")
    check(reloaded["toast_min_severity"] == "MEDIUM", "重新加载后 toast_min_severity 不为 MEDIUM")
    check(reloaded["control_token"] == _CONFIG.get("token"), "保存/重载后 token 发生变化")
    return "保存 -> 重载 一致"


def case_config_recovers_broken_file() -> str:
    import config

    config.CONFIG_PATH.write_text("{ this is not valid json ", encoding="utf-8")
    recovered = config.load_config()
    check(recovered.get("control_token"), "损坏的配置应自动回退到默认值并生成新 token")
    check(recovered.get("host") == "127.0.0.1", "损坏配置恢复后默认值缺失")
    fixed = json.loads(config.CONFIG_PATH.read_text(encoding="utf-8"))
    check(fixed.get("control_token") == recovered["control_token"], "损坏配置应被自动修复为合法 JSON")
    return "损坏的 config.json 自动恢复为默认配置"


# ---------------------------------------------------------------------------
# 5. SentinelCore + webapi（TestClient）
# ---------------------------------------------------------------------------
def _get_core():
    if "core" in _CORE:
        return _CORE

    import core as core_module
    from events import Finding
    from fastapi.testclient import TestClient
    from webapi import create_app

    app_dir = SMOKE_DIR / "app"
    core_obj = core_module.SentinelCore(data_dir=app_dir)
    core_obj.db.init()
    # 测试进程不启动任何线程：即使有高危事件也不会真的弹 Toast / 跑 AI
    core_obj.cfg["toast_enabled"] = False
    core_obj.cfg["ai_enabled"] = False

    high = Finding(
        sensor="process",
        rule_id="proc.smoke_test.high",
        severity="HIGH",
        title="冒烟测试高危事件",
        detail="合成事件，仅用于冒烟测试，不代表真实系统状态。",
        subject="smoke:high",
        dedupe_key="smoke:test:high",
        ts=time.time(),
    )
    info = Finding(
        sensor="network",
        rule_id="net.smoke_test.info",
        severity="INFO",
        title="冒烟测试提示事件",
        detail="合成事件，仅用于冒烟测试。",
        subject="smoke:info",
        dedupe_key="smoke:test:info",
        ts=time.time(),
    )
    core_obj.ingest([high, info])
    rows, _total = core_obj.db.list_events(limit=20)
    by_rule = {row["rule_id"]: row for row in rows}

    _CORE.update(
        core=core_obj,
        app_dir=app_dir,
        rows=by_rule,
        client=TestClient(create_app(core_obj), base_url="http://127.0.0.1"),
    )
    return _CORE


def _client():
    return _get_core()["client"]


def case_core_init() -> str:
    data = _get_core()
    core_obj = data["core"]
    check(core_obj.db is not None, "core.db 未初始化")
    check(core_obj.sensors is not None, "core.sensors 未初始化")
    check(core_obj.cfg.get("control_token"), "core.cfg 缺少 control_token")
    check(str(data["app_dir"]) in str(core_obj.data_dir), "core.data_dir 未指向临时数据目录")
    return f"传感器 {len(core_obj.sensors)} 个 · 管理员模式={bool(core_obj.ctx.is_admin)}"


def case_core_ingest_pipeline() -> str:
    from dataclasses import replace

    data = _get_core()
    core_obj = data["core"]
    check("proc.smoke_test.high" in data["rows"], "分析管线未把高危事件写入数据库")
    check("net.smoke_test.info" in data["rows"], "分析管线未把提示事件写入数据库")
    stats = core_obj.db.stats(24)
    check(stats["events_24h"] >= 2, f"24h 事件统计应 >= 2，实际 {stats['events_24h']}")
    # 相同 dedupe_key 再进一次管线应合并
    duplicate = replace(
        _find_row_as_finding(data["rows"]["proc.smoke_test.high"]),
        ts=time.time(),
    )
    core_obj.ingest([duplicate])
    event = core_obj.db.get_event(data["rows"]["proc.smoke_test.high"]["id"])
    check(event and event["seen_count"] >= 2, "重复事件应合并 seen_count")
    return "白名单过滤 + 入库 + 去重 + 统计正常"


def _find_row_as_finding(row: dict[str, Any]):
    from events import Finding

    return Finding(
        sensor=row["sensor"],
        rule_id=row["rule_id"],
        severity=row["severity"],
        title=row["title"],
        detail=row.get("detail") or "",
        subject=row.get("subject") or "",
        metadata=row.get("metadata") or {},
        dedupe_key=row["dedupe_key"],
    )


def case_api_health() -> str:
    response = _client().get("/api/health")
    check(response.status_code == 200, f"/api/health 状态码 {response.status_code}")
    body = response.json()
    check(body.get("app") == "whx-sentinel", f"/api/health app 字段错误：{body.get('app')!r}")
    check(body.get("status") == "ok", "/api/health status 应为 ok")
    check("version" in body and "uptime_s" in body, "/api/health 缺少 version/uptime_s")
    return f"HTTP 200 · v{body.get('version')}"


def case_api_status() -> str:
    response = _client().get("/api/status")
    check(response.status_code == 200, f"/api/status 状态码 {response.status_code}")
    body = response.json()
    for key in ("app", "version", "elevated", "host", "sensors", "stats", "settings", "db"):
        check(key in body, f"/api/status 缺少字段：{key}")
    check(isinstance(body["sensors"], list), "sensors 应为列表")
    check(isinstance(body["stats"], dict), "stats 应为对象")
    check(isinstance(body["settings"], dict), "settings 应为对象")
    check(str(body["db"].get("path", "")).endswith("sentinel.db"), "db.path 应指向 sentinel.db")
    return f"传感器 {len(body['sensors'])} 个 · 事件 {body['db'].get('events')} 条"


def case_api_events() -> str:
    response = _client().get("/api/events", params={"limit": 10})
    check(response.status_code == 200, f"/api/events 状态码 {response.status_code}")
    body = response.json()
    check(body.get("total", 0) >= 2, f"/api/events total 应 >= 2，实际 {body.get('total')}")
    check(isinstance(body.get("events"), list) and body["events"], "events 应为非空列表")
    first = body["events"][0]
    for key in ("id", "ts", "severity", "title", "sensor", "status"):
        check(key in first, f"/api/events 事件缺少字段：{key}")
    bad = _client().get("/api/events", params={"severity": "NOPE"})
    check(bad.status_code == 422, f"非法 severity 应返回 422，实际 {bad.status_code}")
    return f"total={body['total']} · 非法筛选 422"


def case_api_event_detail() -> str:
    data = _get_core()
    event_id = data["rows"]["proc.smoke_test.high"]["id"]
    response = _client().get(f"/api/events/{event_id}")
    check(response.status_code == 200, f"/api/events/{{id}} 状态码 {response.status_code}")
    check(response.json().get("id") == event_id, "事件详情 id 不匹配")
    missing = _client().get("/api/events/999999999")
    check(missing.status_code == 404, f"不存在的事件应返回 404，实际 {missing.status_code}")
    return f"事件 #{event_id} 详情正常 · 404 正常"


def case_api_timeline() -> str:
    response = _client().get("/api/timeline", params={"hours": 24})
    check(response.status_code == 200, f"/api/timeline 状态码 {response.status_code}")
    body = response.json()
    check(len(body.get("buckets") or []) == 24, f"应返回 24 个时间桶，实际 {len(body.get('buckets') or [])}")
    check(body.get("hours") == 24, "hours 字段应为 24")
    check(sum(bucket["total"] for bucket in body["buckets"]) >= 2, "时间线事件数应 >= 2")
    return "24 个时间桶"


def case_api_settings_get() -> str:
    data = _get_core()
    response = _client().get("/api/settings")
    check(response.status_code == 200, f"/api/settings 状态码 {response.status_code}")
    settings = response.json().get("settings") or {}
    check("ai_enabled" in settings and "allowlist" in settings, "/api/settings 缺少关键字段")
    check(settings["ai_enabled"] is False, f"测试环境应关闭 AI，实际 {settings['ai_enabled']}")
    check(data["core"].cfg.get("toast_enabled") is False, "测试环境应关闭 Toast")
    return "settings 字段完整（AI/Toast 已关闭）"


def case_api_token_loopback_only() -> str:
    response = _client().get("/api/token")
    check(
        response.status_code == 403,
        f"TestClient 不是 127.0.0.1 回环客户端，/api/token 必须 403，实际 {response.status_code}",
    )
    return "非回环客户端返回 403（符合安全设计）"


def case_api_write_requires_token() -> str:
    response = _client().post("/api/actions/ack_event", json={"event_id": 1})
    check(response.status_code == 403, f"无令牌写接口应 403，实际 {response.status_code}")
    response = _client().post("/api/settings", json={"retention_days": 30})
    check(response.status_code == 403, f"无令牌改设置应 403，实际 {response.status_code}")
    return "写接口无令牌 403"


def case_api_ack_event_with_token() -> str:
    data = _get_core()
    token = str(data["core"].cfg["control_token"])
    event_id = data["rows"]["proc.smoke_test.high"]["id"]
    response = _client().post(
        "/api/actions/ack_event",
        json={"event_id": event_id},
        headers={"X-Sentinel-Token": token},
    )
    check(response.status_code == 200, f"带令牌 ack_event 状态码 {response.status_code}")
    body = response.json()
    check(body.get("ok") is True, f"ack_event 应返回 ok=True：{body}")
    event = _client().get(f"/api/events/{event_id}").json()
    check(event.get("status") == "ack", f"事件状态应变为 ack，实际 {event.get('status')}")
    return f"事件 #{event_id} 已确认（status=ack）"


def case_api_recent_actions() -> str:
    response = _client().get("/api/actions/recent", params={"limit": 10})
    check(response.status_code == 200, f"/api/actions/recent 状态码 {response.status_code}")
    actions = response.json().get("actions") or []
    check(any(item.get("action") == "ack_event" for item in actions), "处置记录中没有 ack_event")
    return f"{len(actions)} 条处置记录"


def case_api_allowlist_change() -> str:
    data = _get_core()
    token = str(data["core"].cfg["control_token"])
    headers = {"X-Sentinel-Token": token}
    added = _client().post(
        "/api/allowlist",
        json={"action": "add", "kind": "process_names", "value": "smoke-allowed.exe"},
        headers=headers,
    )
    check(added.status_code == 200, f"添加白名单状态码 {added.status_code}")
    body = added.json()
    check(body.get("ok") is True, f"添加白名单失败：{body}")
    check("smoke-allowed.exe" in (body.get("allowlist") or {}).get("process_names", []), "白名单未包含新值")
    listed = _client().get("/api/allowlist").json().get("allowlist") or {}
    check("smoke-allowed.exe" in listed.get("process_names", []), "GET /api/allowlist 未返回新值")
    removed = _client().post(
        "/api/allowlist",
        json={"action": "remove", "kind": "process_names", "value": "smoke-allowed.exe"},
        headers=headers,
    )
    check(removed.status_code == 200 and removed.json().get("ok") is True, "移除白名单失败")
    check(
        "smoke-allowed.exe" not in (removed.json().get("allowlist") or {}).get("process_names", []),
        "白名单移除后仍存在",
    )
    return "白名单 add / remove 生效"


def case_api_host_guard() -> str:
    bad = _client().get("/api/status", headers={"Host": "evil.example"})
    check(bad.status_code == 403, f"非回环 Host 应 403，实际 {bad.status_code}")
    good = _client().get("/api/status")
    check(good.status_code == 200, f"回环 Host 应 200，实际 {good.status_code}")
    return "Host 校验：evil.example 403 / 127.0.0.1 200"


def case_api_body_limit() -> str:
    data = _get_core()
    token = str(data["core"].cfg["control_token"])
    big = b"x" * (1024 * 1024 + 64)
    response = _client().post(
        "/api/settings",
        content=big,
        headers={"Content-Type": "application/json", "X-Sentinel-Token": token},
    )
    check(response.status_code == 413, f"超大请求体应 413，实际 {response.status_code}")
    return ">1 MB 请求体返回 413"


def case_respond_kill_guard() -> str:
    import os as _os

    import respond

    for pid in (0, 4, _os.getpid()):
        result = respond.kill_process(pid)
        check(result.get("ok") is False, f"PID {pid} 不应被结束：{result}")
    return "PID 0 / 4 / 自身 均被拒绝"


def case_api_settings_update() -> str:
    data = _get_core()
    token = str(data["core"].cfg["control_token"])
    response = _client().post(
        "/api/settings",
        json={"toast_min_severity": "MEDIUM", "retention_days": 14},
        headers={"X-Sentinel-Token": token},
    )
    check(response.status_code == 200, f"更新设置状态码 {response.status_code}")
    body = response.json()
    check(body.get("ok") is True, f"更新设置失败：{body}")
    check(body.get("errors") == [], f"更新设置不应有错误：{body.get('errors')}")
    check(body.get("settings", {}).get("retention_days") == 14, "retention_days 未更新为 14")
    current = _client().get("/api/settings").json()["settings"]
    check(current.get("toast_min_severity") == "MEDIUM", "toast_min_severity 未更新")
    rejected = _client().post(
        "/api/settings",
        json={"ollama_url": "http://127.0.0.1@evil.example"},
        headers={"X-Sentinel-Token": token},
    )
    check(rejected.status_code == 200, f"非法 ollama_url 状态码 {rejected.status_code}")
    check(bool(rejected.json().get("errors")), "非法 ollama_url 应返回错误而不是静默生效")
    return "retention_days=14 · toast_min_severity=MEDIUM · 非法 ollama_url 被拒"


def case_api_export() -> str:
    response = _client().get("/api/export", params={"limit": 10})
    check(response.status_code == 200, f"/api/export 状态码 {response.status_code}")
    payload = response.json()
    check(isinstance(payload, list) and payload, "/api/export 应返回非空事件列表")
    check("attachment" in (response.headers.get("content-disposition") or ""), "导出应带附件下载头")
    return f"导出 {len(payload)} 条事件"


def case_api_index_page() -> str:
    response = _client().get("/")
    check(response.status_code in (200, 503), f"GET / 状态码异常：{response.status_code}")
    if response.status_code == 200:
        check("WHX" in response.text, "GET / 返回的页面不像哨兵看板")
        return "HTTP 200 · 看板页面可访问"
    return "HTTP 503 · 看板文件缺失（web/index.html 未交付）"


# ---------------------------------------------------------------------------
# 6. web/ 前端资产
# ---------------------------------------------------------------------------
def case_web_index() -> str:
    path = BASE_DIR / "web" / "index.html"
    if not path.is_file():
        raise SkipTest("web/index.html 尚未交付（等待前端队友，集成复跑时应转为 PASS）")
    text = path.read_text(encoding="utf-8", errors="replace")
    check("<title>" in text.lower(), "web/index.html 缺少 <title>")
    check(len(text) > 1000, f"web/index.html 内容过短：{len(text)} 字符")
    return f"{len(text)} 字符"


def case_web_style() -> str:
    path = BASE_DIR / "web" / "style.css"
    if not path.is_file():
        raise SkipTest("web/style.css 尚未交付（等待前端队友，集成复跑时应转为 PASS）")
    text = path.read_text(encoding="utf-8", errors="replace")
    check(len(text) > 500, f"web/style.css 内容过短：{len(text)} 字符")
    return f"{len(text)} 字符"


def case_web_app_js() -> str:
    path = BASE_DIR / "web" / "app.js"
    if not path.is_file():
        raise SkipTest("web/app.js 尚未交付（等待前端队友，集成复跑时应转为 PASS）")
    node = shutil.which("node")
    if not node:
        raise SkipTest("未找到 node，跳过 app.js 语法校验")
    result = subprocess.run(
        [node, "--check", str(path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    check(
        result.returncode == 0,
        f"node --check 失败：{(result.stderr or result.stdout or '').strip()[-600:]}",
    )
    return f"node --check 通过 · {path.stat().st_size} 字节"


# ---------------------------------------------------------------------------
# 7. install/ 启动脚本
# ---------------------------------------------------------------------------
INSTALL_SCRIPTS: dict[str, list[str]] = {
    "start_sentinel.bat": ["chcp 65001", "pythonw", "sentinel.py", "--daemon", "--open"],
    "stop_sentinel.bat": ["chcp 65001", "sentinel.py", "--stop"],
    "install_autostart.bat": ["chcp 65001", "sentinel.py", "--install-autostart"],
    "uninstall_autostart.bat": ["chcp 65001", "sentinel.py", "--uninstall-autostart"],
    "start_elevated.bat": ["chcp 65001", "RunAs", "sentinel.py", "127.0.0.1:8765"],
    "uninstall.bat": ["chcp 65001", "sentinel.py", "--stop", "--uninstall-autostart", "data"],
}


def _install_case(name: str, needles: list[str]) -> Callable[[], str]:
    def runner() -> str:
        path = BASE_DIR / "install" / name
        if not path.is_file():
            raise AssertionError(f"缺少安装脚本 install/{name}")
        raw = path.read_bytes()
        check(raw, f"install/{name} 是空文件")
        check(b"\r\n" in raw, f"install/{name} 应使用 Windows CRLF 行尾")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AssertionError(f"install/{name} 不是合法 UTF-8：{exc}") from exc
        check('cd /d "%~dp0.."' in text, f'install/{name} 缺少 cd /d "%~dp0.."（进入项目根目录）')
        for needle in needles:
            check(needle in text, f"install/{name} 缺少预期内容：{needle}")
        return f"{len(raw)} 字节"

    return runner


# ---------------------------------------------------------------------------
# 8. 传感器模块交付状态（并行开发中，缺失时 SKIP）
# ---------------------------------------------------------------------------
EXPECTED_SENSOR_MODULES = ("defender", "eventlog", "autorun", "fileguard", "exposure")


def _sensor_module_case(module_name: str) -> Callable[[], str]:
    def runner() -> str:
        path = BASE_DIR / "sensors" / f"{module_name}.py"
        if not path.is_file():
            raise SkipTest(
                f"sensors/{module_name}.py 尚未交付（等待传感器队友；最终集成复跑时应转为 PASS）"
            )
        return f"{path.stat().st_size} 字节"

    return runner


# ---------------------------------------------------------------------------
# 9. 交付文档 README.md
# ---------------------------------------------------------------------------
def case_readme() -> str:
    path = BASE_DIR / "README.md"
    if not path.is_file():
        raise AssertionError("缺少交付文档 README.md")
    text = path.read_text(encoding="utf-8", errors="replace")
    required = [
        "SOC 演示环境",
        "不是杀毒软件",
        "Windows Defender",
        "data/sentinel.db",
        "增强模式",
        "标准模式",
        "退出码",
        "能力边界",
        "开机自启",
        "卸载",
        "目录结构",
    ]
    missing = [needle for needle in required if needle not in text]
    check(not missing, f"README.md 缺少必需内容：{missing}")
    check(len(text) > 3000, f"README.md 内容过短：{len(text)} 字符")
    return f"{len(text)} 字符"


# ---------------------------------------------------------------------------
# 10. CLI 入口（无副作用命令）
# ---------------------------------------------------------------------------
def case_cli_version() -> str:
    result = subprocess.run(
        [sys.executable, "sentinel.py", "--version"],
        cwd=str(BASE_DIR),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    check(result.returncode == 0, f"sentinel.py --version 退出码 {result.returncode}：{result.stderr[-400:]}")
    check("哨兵" in result.stdout, f"--version 输出异常：{result.stdout!r}")
    return result.stdout.strip().splitlines()[-1][:80]


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def _summary() -> int:
    counts = {PASS: 0, FAIL: 0, SKIP: 0}
    for status, _group, _name, _detail in RESULTS:
        counts[status] += 1
    total = sum(counts.values())
    print("-" * 72)
    failures = [item for item in RESULTS if item[0] == FAIL]
    skips = [item for item in RESULTS if item[0] == SKIP]
    if failures:
        print("失败明细：")
        for _status, group, name, detail in failures:
            print(f"  [FAIL] {group} · {name}：{detail}")
    if skips:
        print(f"跳过 {len(skips)} 项：")
        for _status, group, name, detail in skips:
            print(f"  [SKIP] {group} · {name}：{detail}")
    print(f"汇总：PASS {counts[PASS]} · FAIL {counts[FAIL]} · SKIP {counts[SKIP]} · 共 {total} 项")
    if counts[FAIL]:
        print("结果：FAIL（请修复上面的失败项）")
        return 1
    if counts[SKIP]:
        print("结果：PASS（含 SKIP 项：通常是并行开发中的文件尚未交付，或本机缺少 node）")
        return 0
    print("结果：全部 PASS")
    return 0


def main() -> int:
    _configure_console()
    print("=" * 72)
    print("WHX 哨兵 · 冒烟测试（无副作用）")
    print(f"项目目录：{BASE_DIR}")
    print(f"Python：{sys.version.split()[0]} · {sys.executable}")
    print(f"临时数据：{SMOKE_DIR}（测试结束自动删除）")
    print("=" * 72)
    _cleanup()
    started = time.perf_counter()
    try:
        run_case("compile", "compileall 编译全部 .py", case_compileall)

        run_case("rules.process", "正例：PowerShell 编码命令", case_match_process_positive)
        run_case("rules.process", "反例：正常进程", case_match_process_negative)
        run_case("rules.process", "正例：临时目录执行", case_match_process_temp_exec)
        run_case("rules.process", "正例：办公软件派生 shell", case_match_process_office_spawn)
        run_case("rules.defender", "正例：实时保护关闭", case_match_defender_positive)
        run_case("rules.defender", "反例：Defender 状态正常", case_match_defender_negative)
        run_case("rules.defender", "正/反例：病毒库过旧", case_match_defender_stale_signature)
        run_case("rules.firewall", "正例：防火墙配置文件关闭", case_match_firewall_positive)
        run_case("rules.firewall", "反例：防火墙全部开启", case_match_firewall_negative)
        run_case("rules.eventlog", "正例：安全日志被清除", case_match_eventlog_positive)
        run_case("rules.eventlog", "反例：无关日志/事件 ID", case_match_eventlog_negative)
        run_case("rules.eventlog", "正例：可疑服务安装事件", case_match_eventlog_service_install)
        run_case("rules.listener", "正例：RDP 对外监听", case_match_listener_positive)
        run_case("rules.listener", "反例：回环/普通端口", case_match_listener_negative)
        run_case("rules.listener", "正例：新增对外监听", case_match_listener_new_port)
        run_case("rules.network", "正例：反弹 shell 端口外连", case_match_network_connection_positive)
        run_case("rules.network", "反例：普通 HTTPS 外连", case_match_network_connection_negative)
        run_case("rules.autorun", "正例：隐藏编码 PowerShell 自启动", case_match_autorun_positive)
        run_case("rules.autorun", "反例：正常 OneDrive 自启动", case_match_autorun_negative)
        run_case("rules.autorun", "正例：新增/修改自启动", case_match_autorun_new_and_changed)
        run_case("rules.startup", "正例：启动目录新增可执行文件", case_match_startup_file_positive)
        run_case("rules.startup", "反例：非新增启动文件", case_match_startup_file_negative)
        run_case("rules.startup", "正例：启动目录新增快捷方式", case_match_startup_file_new_link)
        run_case("rules.schtask", "正例：可疑计划任务", case_match_scheduled_task_positive)
        run_case("rules.schtask", "反例：正常计划任务", case_match_scheduled_task_negative)
        run_case("rules.service", "正例：可疑服务路径", case_match_service_positive)
        run_case("rules.service", "反例：正常系统服务", case_match_service_negative)
        run_case("rules.fileguard", "正例：hosts/诱饵文件完整性", case_match_fileguard_positive)
        run_case("rules.fileguard", "反例：未知完整性类型", case_match_fileguard_negative)
        run_case("rules.exposure", "正例：RDP 暴露面", case_match_exposure_positive)
        run_case("rules.exposure", "反例：未命中/未知检查", case_match_exposure_negative)
        run_case("rules.eventlog", "正/反例：登录失败暴破阈值", case_match_failed_logon_burst)

        run_case("allowlist", "cmdline_contains 生效", case_allowlist_cmdline_contains)
        run_case("allowlist", "process_names / paths 生效", case_allowlist_process_names_and_paths)
        run_case("allowlist", "remote_ips / suppress_rules 生效", case_allowlist_network_and_suppress)

        run_case("db", "init 建库建表", case_db_init)
        run_case("db", "插入 + 去重合并（seen_count）", case_db_insert_and_dedupe)
        run_case("db", "统计 stats", case_db_stats)
        run_case("db", "24 小时时间线", case_db_timeline)
        run_case("db", "标记状态 mark_status", case_db_mark_status)
        run_case("db", "actions 处置记录", case_db_actions)
        run_case("db", "list_events 过滤/搜索/导出", case_db_list_events)
        run_case("db", "prune 过期清理", case_db_prune)
        run_case("db", "metadata 读写", case_db_metadata)

        run_case("config", "首次加载自动生成 token", case_config_generate_token)
        run_case("config", "保存/重载配置", case_config_save_reload)
        run_case("config", "损坏 configuration 自愈", case_config_recovers_broken_file)

        run_case("core", "SentinelCore 初始化", case_core_init)
        run_case("core", "分析管线入库（白名单/去重/统计）", case_core_ingest_pipeline)
        run_case("webapi", "GET /api/health", case_api_health)
        run_case("webapi", "GET /api/status", case_api_status)
        run_case("webapi", "GET /api/events", case_api_events)
        run_case("webapi", "GET /api/events/{id} 与 404", case_api_event_detail)
        run_case("webapi", "GET /api/timeline", case_api_timeline)
        run_case("webapi", "GET /api/settings", case_api_settings_get)
        run_case("webapi", "GET /api/token 回环限制（403）", case_api_token_loopback_only)
        run_case("webapi", "Host 校验（防 DNS rebinding）", case_api_host_guard)
        run_case("webapi", "请求体 1 MB 上限（413）", case_api_body_limit)
        run_case("respond", "kill_process 关键 PID 防护", case_respond_kill_guard)
        run_case("webapi", "写接口无令牌（403）", case_api_write_requires_token)
        run_case("webapi", "POST /api/actions/ack_event（带令牌）", case_api_ack_event_with_token)
        run_case("webapi", "GET /api/actions/recent", case_api_recent_actions)
        run_case("webapi", "POST /api/allowlist 白名单增删", case_api_allowlist_change)
        run_case("webapi", "POST /api/settings 更新设置", case_api_settings_update)
        run_case("webapi", "GET /api/export 导出", case_api_export)
        run_case("webapi", "GET / 看板页面", case_api_index_page)

        run_case("web", "web/index.html 存在性", case_web_index)
        run_case("web", "web/style.css 存在性", case_web_style)
        run_case("web", "web/app.js 语法（node --check）", case_web_app_js)

        for script_name, needles in INSTALL_SCRIPTS.items():
            run_case("install", f"install/{script_name}", _install_case(script_name, needles))

        for module_name in EXPECTED_SENSOR_MODULES:
            run_case("sensors", f"sensors/{module_name}.py 交付状态", _sensor_module_case(module_name))

        run_case("docs", "README.md 关键章节", case_readme)
        run_case("cli", "python sentinel.py --version", case_cli_version)
    finally:
        _cleanup()

    elapsed = time.perf_counter() - started
    print("-" * 72)
    print(f"总耗时 {elapsed:.1f}s")
    return _summary()


if __name__ == "__main__":
    sys.exit(main())
