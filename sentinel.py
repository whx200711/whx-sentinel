#!/usr/bin/env python3
"""WHX 哨兵 · 命令行入口。

最初是一个 SOC 演示环境的一部分，后重构为独立 Windows 主机防护代理：
单进程运行，看板在 127.0.0.1:8765，数据只保存在本地 data/ 目录。

常用：
    python sentinel.py                 # 前台运行（调试，控制台可看日志）
    pythonw sentinel.py --daemon      # 后台运行（自启动用）
    python sentinel.py --open          # 启动并打开看板
    python sentinel.py --once          # 只采集一轮，打印结果（调试传感器）
    python sentinel.py --status        # 查看运行状态
    python sentinel.py --stop          # 停止运行中的哨兵
    python sentinel.py --smoke-test    # 冒烟测试
    python sentinel.py --install-autostart / --uninstall-autostart
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any

VERSION_FALLBACK = "1.0.0"


def _say(text: str) -> None:
    try:
        print(text, flush=True)
    except Exception:  # noqa: BLE001 - pythonw 下没有控制台
        pass


def _configure_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream is not None:
                stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sentinel.py",
        description="WHX 哨兵 — 本地 Windows 主机防护代理（127.0.0.1 only）",
    )
    parser.add_argument("--data-dir", help="数据目录（默认 <程序目录>/data）")
    parser.add_argument("--port", type=int, help="看板端口（默认 8765）")
    parser.add_argument("--open", action="store_true", help="启动后自动打开看板")
    parser.add_argument("--daemon", action="store_true", help="后台模式（供 pythonw / 自启动使用）")
    parser.add_argument("--once", action="store_true", help="只采集一轮并打印结果，不启动服务")
    parser.add_argument("--status", action="store_true", help="查询正在运行的哨兵状态")
    parser.add_argument("--stop", action="store_true", help="停止正在运行的哨兵")
    parser.add_argument("--smoke-test", action="store_true", help="运行冒烟测试")
    parser.add_argument("--install-autostart", action="store_true", help="注册当前用户登录自启动")
    parser.add_argument("--uninstall-autostart", action="store_true", help="移除登录自启动")
    parser.add_argument("--version", action="store_true", help="显示版本")
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# HTTP helpers（只用本机回环）
# ---------------------------------------------------------------------------
def _url(port: int, path: str = "") -> str:
    return f"http://127.0.0.1:{int(port)}{path}"


def _health(port: int) -> dict[str, Any] | None:
    try:
        import httpx

        response = httpx.get(_url(port, "/api/health"), timeout=1.5)
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, dict) and data.get("app") == "whx-sentinel":
                return data
    except Exception:  # noqa: BLE001
        return None
    return None


def _api_token(port: int) -> str | None:
    try:
        import httpx

        response = httpx.get(_url(port, "/api/token"), timeout=3)
        if response.status_code == 200:
            return str(response.json().get("token") or "")
    except Exception:  # noqa: BLE001
        pass
    return None


# ---------------------------------------------------------------------------
# PID 文件
# ---------------------------------------------------------------------------
def _write_pid(port: int) -> None:
    import config

    config.ensure_dirs()
    payload = {
        "pid": os.getpid(),
        "port": int(port),
        "started": time.time(),
        "version": config.VERSION,
    }
    config.PID_PATH.write_text(json.dumps(payload), encoding="utf-8")


def _read_pid() -> dict[str, Any] | None:
    import config

    try:
        return json.loads(config.PID_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _remove_pid() -> None:
    import config

    data = _read_pid()
    if data and int(data.get("pid") or 0) == os.getpid():
        try:
            config.PID_PATH.unlink()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# 各命令
# ---------------------------------------------------------------------------
def _run_smoke_test() -> int:
    import config

    test_file = Path(config.BASE_DIR) / "tests" / "smoke_test.py"
    if not test_file.is_file():
        _say(f"冒烟测试文件不存在：{test_file}")
        return 2
    import subprocess

    return subprocess.call([sys.executable, str(test_file)], cwd=str(config.BASE_DIR))


def _run_once(args: argparse.Namespace) -> int:
    from core import SentinelCore
    from rules import filter_findings

    core = SentinelCore(data_dir=args.data_dir, port=args.port)
    try:
        core.db.init()
        total = 0
        for sensor in core.sensors:
            _say(f"\n=== {sensor.id} · {sensor.name} ===")
            try:
                findings = sensor.collect() or []
            except Exception as exc:  # noqa: BLE001
                _say(f"  采集失败：{exc}")
                continue
            findings = filter_findings(findings, core.cfg)
            _say(f"  capability: {sensor.capability} | findings: {len(findings)}")
            for finding in findings:
                total += 1
                _say(f"  [{finding.severity}] {finding.rule_id}  {finding.title}")
                if finding.detail:
                    _say(f"      {finding.detail[:240]}")
        _say(f"\n共 {total} 条告警（本次仅打印，未写入数据库）")
        return 0
    finally:
        try:
            core.db.close()
        except Exception:  # noqa: BLE001
            pass


def _run_status() -> int:
    import config

    cfg = config.load_config()
    port = int(cfg.get("port") or config.DEFAULT_PORT)
    info = _health(port)
    if not info:
        _say("哨兵未运行（或端口不可达）。启动：install/start_sentinel.bat")
        return 1
    try:
        import httpx

        status = httpx.get(_url(port, "/api/status"), timeout=5).json()
    except Exception as exc:  # noqa: BLE001
        _say(f"读取状态失败：{exc}")
        return 1
    sensors = status.get("sensors") or []
    ok = sum(1 for s in sensors if s.get("status") == "ok")
    stats = status.get("stats") or {}
    defender = status.get("defender") or {}
    elevated = "管理员" if status.get("elevated") else "标准用户"
    _say(f"WHX 哨兵 v{status.get('version')} 运行中：{_url(port)}/  （{elevated}模式）")
    _say(f"运行时长：{int(status.get('uptime_s', 0)) // 60} 分钟 | 传感器 ok {ok}/{len(sensors)}")
    _say(
        f"24h 事件：高危 {stats.get('high_24h', 0)} / 中危 {stats.get('medium_24h', 0)} / "
        f"低危 {stats.get('low_24h', 0)} / 提示 {stats.get('info_24h', 0)} | 未处理 {stats.get('open_events', 0)}"
    )
    if defender.get("available"):
        _say(
            "Defender：实时保护={}，病毒库年龄={}天，防火墙={}".format(
                "开" if defender.get("realtime") else "关",
                defender.get("signature_age_days"),
                "已启用" if (defender.get("firewall") or {}).get("enabled") else "有配置关闭",
            )
        )
    ai_status = status.get("ai") or {}
    _say(
        f"本地 AI 研判：{'开启' if ai_status.get('enabled') else '关闭'}"
        f"（{ai_status.get('model')}，{'可用' if ai_status.get('available') else '未就绪'}）"
    )
    for sensor in sensors:
        if sensor.get("status") != "ok":
            _say(f"  ⚠ 传感器 {sensor.get('id')} 状态 {sensor.get('status')}：{sensor.get('error')}")
    return 0


def _run_stop() -> int:
    import config

    cfg = config.load_config()
    port = int(cfg.get("port") or config.DEFAULT_PORT)
    token = _api_token(port)
    if token:
        try:
            import httpx

            httpx.post(
                _url(port, "/api/admin/shutdown"),
                headers={"X-Sentinel-Token": token},
                timeout=5,
            )
            _say("已请求哨兵优雅退出…")
            for _ in range(20):
                time.sleep(0.4)
                if not _health(port):
                    _say("哨兵已停止。")
                    return 0
        except Exception:  # noqa: BLE001
            pass
    pid_data = _read_pid()
    pid = int((pid_data or {}).get("pid") or 0)
    if not pid:
        _say("没有找到运行中的哨兵进程。")
        return 0
    try:
        import psutil

        process = psutil.Process(pid)
        if "sentinel.py" not in " ".join(process.cmdline()):
            _say(f"PID {pid} 不是哨兵进程，已放弃终止。")
            return 1
        process.terminate()
        try:
            process.wait(timeout=5)
        except psutil.TimeoutExpired:
            process.kill()
        _say(f"已终止哨兵进程 {pid}。")
        _remove_pid()
        return 0
    except Exception as exc:  # noqa: BLE001
        _say(f"停止失败：{exc}（可任务管理器结束 pythonw.exe）")
        return 1


def _serve(args: argparse.Namespace) -> int:
    import config

    cfg = config.load_config()
    port = int(args.port or cfg.get("port") or config.DEFAULT_PORT)
    existing = _health(port)
    if existing:
        _say(f"哨兵已经在运行：{_url(port)}/（版本 {existing.get('version')}）")
        if args.open:
            webbrowser.open(_url(port))
        return 0
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.4)
        if sock.connect_ex(("127.0.0.1", port)) == 0:
            _say(f"端口 {port} 已被其它程序占用，无法启动。")
            return 1

    from core import SentinelCore
    from webapi import create_app

    core = SentinelCore(data_dir=args.data_dir, port=args.port)
    app = create_app(core)
    _write_pid(port)

    if args.open:
        def _open_later() -> None:
            deadline = time.time() + 40
            while time.time() < deadline:
                if _health(port):
                    try:
                        webbrowser.open(_url(port))
                    except Exception:  # noqa: BLE001
                        pass
                    return
                time.sleep(0.5)

        threading.Thread(target=_open_later, name="open-dashboard", daemon=True).start()

    try:
        import uvicorn

        server_config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
            log_config=None,
            access_log=False,
            lifespan="on",
        )
        server = uvicorn.Server(server_config)
        core.uvicorn_server = server
        _say(f"WHX 哨兵启动中：{_url(port)}/（标准模式；管理员权限可开启更多能力）")
        server.run()
    except KeyboardInterrupt:
        pass
    finally:
        _remove_pid()
        try:
            core.stop()
        except Exception:  # noqa: BLE001
            pass
    return 0


def _autostart_command(args: argparse.Namespace) -> int:
    from core import SentinelCore

    core = SentinelCore(data_dir=args.data_dir, port=args.port)
    result = (
        core.install_autostart() if args.install_autostart else core.uninstall_autostart()
    )
    _say(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 1


def main(argv: list[str] | None = None) -> int:
    _configure_console()
    args = _parse_args(argv)
    if args.data_dir:
        os.environ["WHX_SENTINEL_DATA"] = str(Path(args.data_dir).expanduser())

    # config 必须在设置 WHX_SENTINEL_DATA 之后再导入
    import config

    if args.version:
        _say(f"WHX 哨兵 v{config.VERSION}（独立主机防护代理）")
        return 0
    if args.smoke_test:
        return _run_smoke_test()
    if args.status:
        return _run_status()
    if args.stop:
        return _run_stop()
    if args.install_autostart or args.uninstall_autostart:
        return _autostart_command(args)
    if args.once:
        return _run_once(args)
    return _serve(args)


if __name__ == "__main__":
    sys.exit(main())
