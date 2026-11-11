"""WHX 哨兵 · 传感器基类与运行上下文。

传感器 = 独立线程，周期性采集一类系统信息，产出 Finding 列表。
规则判断放在 rules.py，传感器只负责采集与调用匹配器，保持可测试。
"""

from __future__ import annotations

import json
import logging
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Callable

from events import Finding

logger = logging.getLogger("whx.sentinel.sensors")


class BaselineStore:
    """持久化的基线（自启动项、监听端口、文件哈希...）。线程安全。"""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._data: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        try:
            if self.path.is_file():
                self._data = json.loads(self.path.read_text(encoding="utf-8"))
                if not isinstance(self._data, dict):
                    self._data = {}
        except (OSError, json.JSONDecodeError):
            self._data = {}

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._data.get(key, default)

    def set(self, key: str, value: Any, save: bool = True) -> None:
        with self._lock:
            self._data[key] = value
        if save:
            self.save()

    def update(self, values: dict[str, Any], save: bool = True) -> None:
        with self._lock:
            self._data.update(values)
        if save:
            self.save()

    def save(self) -> None:
        with self._lock:
            snapshot = json.dumps(self._data, ensure_ascii=False, indent=2, default=str)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".json.tmp")
            tmp.write_text(snapshot, encoding="utf-8")
            tmp.replace(self.path)
        except OSError:
            logger.exception("保存基线失败：%s", self.path)


class SensorContext:
    """所有传感器共享的上下文（由 core.SentinelCore 构造）。"""

    def __init__(
        self,
        cfg: dict[str, Any],
        db: Any,
        data_dir: Path,
        emit: Callable[[list[Finding]], None],
        baselines: BaselineStore,
    ):
        self.cfg = cfg
        self.db = db
        self.data_dir = Path(data_dir)
        self.emit = emit
        self.baselines = baselines
        self.shared: dict[str, Any] = {}
        self.started_at = time.time()
        self.is_admin = False
        try:
            import winutil

            self.is_admin = winutil.is_admin()
        except Exception:  # noqa: BLE001 - non-Windows/test context
            pass

    # 便捷探针（sensors 里统一走 winutil，避免每个传感器重复处理编码）
    def probe_json(self, script: str, timeout: float = 25.0) -> Any:
        import winutil

        return winutil.run_ps_json(script, timeout=timeout)

    def probe_text(self, script: str, timeout: float = 25.0) -> str:
        import winutil

        return winutil.run_ps_text(script, timeout=timeout)


class Sensor:
    """传感器基类：子类只需实现 collect()。"""

    id: str = "base"
    name: str = "基础传感器"
    description: str = ""
    interval_key: str = ""
    default_interval: float = 60.0
    requires_admin: bool = False
    initial_delay: float = 1.0
    capability: str = "starting"  # ok / degraded / needs_admin / unavailable / starting

    def __init__(self, ctx: SensorContext):
        self.ctx = ctx
        self.interval = float(
            ctx.cfg.get(self.interval_key, self.default_interval) if self.interval_key else self.default_interval
        )
        self.status = "starting"
        self.last_run = 0.0
        self.last_ms = 0.0
        self.last_error = ""
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_error_log = 0.0

    # ------------------------------------------------------------------ 采集
    def collect(self) -> list[Finding]:  # pragma: no cover - 子类必须实现
        raise NotImplementedError

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._run_loop, name=f"sensor-{self.id}", daemon=True
        )
        self._thread.start()

    def _run_loop(self) -> None:
        if self._stop.wait(max(0.0, self.initial_delay)):
            return
        while not self._stop.is_set():
            started = time.perf_counter()
            try:
                findings = self.collect() or []
                if findings:
                    self.ctx.emit(findings)
                self.status = "ok"
                self.last_error = ""
            except Exception as exc:  # noqa: BLE001 - 传感器必须自愈
                self.status = "error"
                self.last_error = str(exc)[:300]
                now = time.time()
                if now - self._last_error_log > 60:
                    self._last_error_log = now
                    logger.warning("传感器 %s 采集失败：%s", self.id, self.last_error)
                    logger.debug("%s", traceback.format_exc())
            finally:
                elapsed = time.perf_counter() - started
                self.last_run = time.time()
                self.last_ms = round(elapsed * 1000, 1)
            if self._stop.wait(max(0.5, self.interval - elapsed)):
                break

    def stop(self) -> None:
        self._stop.set()

    # ------------------------------------------------------------------ 状态
    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "interval_s": self.interval,
            "requires_admin": self.requires_admin,
            "status": "stopped" if self._stop.is_set() else self.status,
            "capability": self.capability,
            "last_run": self.last_run,
            "last_ms": self.last_ms,
            "error": self.last_error,
        }
