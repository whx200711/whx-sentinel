"""WHX 哨兵 · 配置、路径与默认值。

最初是一个 SOC 实验环境的一部分，后重构为独立主机防护代理：
不再依赖网站、FastAPI 之外的第三方库全部来自本机已安装环境。
"""

from __future__ import annotations

import copy
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

APP_ID = "whx-sentinel"
APP_NAME = "WHX Sentinel"
APP_NAME_CN = "WHX 哨兵"
VERSION = "1.0.0"

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("WHX_SENTINEL_DATA") or (BASE_DIR / "data"))
LOG_DIR = DATA_DIR / "logs"
DB_PATH = DATA_DIR / "sentinel.db"
CONFIG_PATH = DATA_DIR / "config.json"
PID_PATH = DATA_DIR / "sentinel.pid"
BASELINE_PATH = DATA_DIR / "baselines.json"
BLOCKLIST_PATH = DATA_DIR / "blocklist.txt"
WEB_DIR = BASE_DIR / "web"

HOST = "127.0.0.1"
DEFAULT_PORT = 8765

OLLAMA_ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}
OLLAMA_ALLOWED_PORT = 11434

DEFAULT_ALLOWLIST: dict[str, list[str]] = {
    # 小写进程名（如 "chrome.exe"），命中后该进程的进程类告警不再产生
    "process_names": [],
    # 命令行里包含任一标记则不告警（哨兵自身探针标记在首次启动时随机生成）
    "cmdline_contains": [],
    # 可执行文件路径前缀
    "paths": [],
    # 远端 IP
    "remote_ips": [],
    # 直接抑制的规则 id
    "suppress_rules": [],
}

DEFAULT_CONFIG: dict[str, Any] = {
    "version": VERSION,
    "host": HOST,
    "port": DEFAULT_PORT,
    "control_token": "",
    "first_run_ts": 0.0,

    # AI 研判（本地 Ollama，可选；默认关闭，用户主动开启）
    "ai_enabled": False,
    "ai_model": "deepseek-r1:8b",
    "ollama_url": "http://127.0.0.1:11434",
    "ai_cooldown_s": 600,

    # 本机探针随机标记（首次启动生成，用于过滤哨兵自己的 PowerShell 子进程）
    "internal_marker": "",

    # 通知与处置
    "toast_enabled": True,
    "toast_min_severity": "HIGH",
    "auto_quick_scan_on_malware": False,
    "auto_block_high_remote": False,

    # 数据保留
    "retention_days": 30,
    "max_events": 20000,

    # 传感器
    "canary_enabled": True,
    "process_interval_s": 2.0,
    "network_interval_s": 4.0,
    "autorun_interval_s": 300.0,
    "eventlog_interval_s": 30.0,
    "defender_interval_s": 60.0,
    "fileguard_interval_s": 60.0,
    "exposure_interval_s": 1800.0,

    "allowlist": DEFAULT_ALLOWLIST,
}


def validate_ollama_url(value: Any) -> str:
    """只接受指向本机回环 Ollama 的 http(s) 地址，拒绝 userinfo / 外部域名 / 非常用端口。"""

    text = str(value or "").strip().rstrip("/")
    if not text:
        raise ValueError("ollama_url 不能为空")
    parsed = urlsplit(text)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("ollama_url 只允许 http/https")
    if parsed.username or parsed.password:
        raise ValueError("ollama_url 不允许包含用户名/密码")
    try:
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError as exc:
        raise ValueError("ollama_url 端口无效") from exc
    if host not in OLLAMA_ALLOWED_HOSTS:
        raise ValueError("ollama_url 只允许本机回环地址")
    if port not in {None, OLLAMA_ALLOWED_PORT}:
        raise ValueError("ollama_url 只允许 11434 端口")
    return text


def configure(data_dir: str | Path | None = None) -> None:
    """Allow the CLI/tests to point the agent at another data directory."""

    global DATA_DIR, LOG_DIR, DB_PATH, CONFIG_PATH, PID_PATH, BASELINE_PATH, BLOCKLIST_PATH
    if data_dir is None:
        return
    DATA_DIR = Path(data_dir).expanduser().resolve()
    LOG_DIR = DATA_DIR / "logs"
    DB_PATH = DATA_DIR / "sentinel.db"
    CONFIG_PATH = DATA_DIR / "config.json"
    PID_PATH = DATA_DIR / "sentinel.pid"
    BASELINE_PATH = DATA_DIR / "baselines.json"
    BLOCKLIST_PATH = DATA_DIR / "blocklist.txt"


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if key == "allowlist" and isinstance(value, dict):
            merged = dict(DEFAULT_ALLOWLIST)
            merged.update({k: v for k, v in value.items() if isinstance(v, list)})
            result["allowlist"] = merged
        else:
            result[key] = value
    return result


def load_config() -> dict[str, Any]:
    """Load config.json, filling defaults and generating the control token."""

    ensure_dirs()
    raw: dict[str, Any] = {}
    if CONFIG_PATH.is_file():
        try:
            raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw = {}
    cfg = _merge(DEFAULT_CONFIG, raw if isinstance(raw, dict) else {})

    changed = False
    if not cfg.get("control_token"):
        cfg["control_token"] = secrets.token_urlsafe(24)
        changed = True
    if not cfg.get("first_run_ts"):
        cfg["first_run_ts"] = time.time()
        changed = True
    if cfg.get("version") != VERSION:
        cfg["version"] = VERSION
        changed = True
    if not cfg.get("internal_marker"):
        # 每个安装随机生成，避免开源代码后 "WHX_SENTINEL_INTERNAL" 变成公开免检口令
        cfg["internal_marker"] = "WHX_SENTINEL_" + secrets.token_hex(8).upper()
        changed = True
    allowlist = cfg.get("allowlist")
    if isinstance(allowlist, dict):
        markers = allowlist.get("cmdline_contains")
        if not isinstance(markers, list):
            markers = []
        marker = str(cfg["internal_marker"])
        if marker and marker not in markers:
            markers.append(marker)
            changed = True
        allowlist["cmdline_contains"] = markers
    try:
        cfg["ollama_url"] = validate_ollama_url(cfg.get("ollama_url"))
    except ValueError:
        cfg["ollama_url"] = DEFAULT_CONFIG["ollama_url"]
        changed = True
    if changed or not CONFIG_PATH.is_file():
        save_config(cfg)
    return cfg


def save_config(cfg: dict[str, Any]) -> None:
    ensure_dirs()
    tmp = CONFIG_PATH.with_suffix(".json.tmp")
    payload = json.dumps(cfg, ensure_ascii=False, indent=2)
    tmp.write_text(payload, encoding="utf-8")
    try:
        os.replace(tmp, CONFIG_PATH)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def load_blocklist() -> list[str]:
    """Optional local IP / CIDR blocklist, one entry per line."""

    if not BLOCKLIST_PATH.is_file():
        return []
    entries: list[str] = []
    try:
        for line in BLOCKLIST_PATH.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                entries.append(line)
    except OSError:
        return []
    return entries
