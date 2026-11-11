"""WHX 哨兵 · 事件分析管线（入库 / 通知 / AI 研判 / 自动处置）。

传感器线程调用 ingest()，管道保证：
- 白名单过滤；
- 同一 dedupe_key 在窗口内合并，不会刷屏；
- 高危事件进入 Toast 通知队列（节流）；
- 可选把 HIGH 事件交给本地 Ollama 做中文研判；
- 自动处置默认关闭，开启时也只通过 respond 模块的受限动作。
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Any

import ai
import respond
from events import SEVERITY_RANK, Finding
from rules import filter_findings

logger = logging.getLogger("whx.sentinel.analyst")


class Analyst:
    def __init__(self, core: Any):
        self.core = core
        self.cfg = core.cfg
        self.db = core.db
        self._toast_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=300)
        self._ai_queue: queue.Queue[int] = queue.Queue(maxsize=100)
        self._auto_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=100)
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.last_toast: dict[str, Any] = {"ts": 0.0, "ok": None, "detail": ""}
        self.last_ai: dict[str, Any] = {"ts": 0.0, "engine": "", "event_id": None}
        self.ai_available = False
        self._last_ai_probe = 0.0
        self._ingested = 0

    # ------------------------------------------------------------------ 生命周期
    def start(self) -> None:
        targets = (
            ("toast", self._toast_loop),
            ("ai", self._ai_loop),
            ("auto", self._auto_loop),
        )
        for name, target in targets:
            thread = threading.Thread(target=target, name=f"analyst-{name}", daemon=True)
            thread.start()
            self._threads.append(thread)
        logger.info("分析管线已启动（AI=%s, Toast=%s）", self.cfg.get("ai_enabled"), self.cfg.get("toast_enabled"))

    def stop(self) -> None:
        self._stop.set()

    # ------------------------------------------------------------------ 入口
    def ingest(self, findings: list[Finding]) -> None:
        """Called from sensor threads for every batch of findings."""

        if not findings:
            return
        try:
            allowed = filter_findings(findings, self.cfg)
        except Exception:  # noqa: BLE001 - 白名单异常不影响主流程
            logger.exception("白名单过滤失败，按全部放行处理")
            allowed = findings
        for finding in allowed:
            try:
                event_id, is_new = self.db.insert_finding(finding)
            except Exception:  # noqa: BLE001
                logger.exception("事件入库失败")
                continue
            self._ingested += 1
            if not is_new or not event_id:
                continue
            logger.info(
                "[%s] %s | %s | %s",
                finding.severity,
                finding.title,
                finding.sensor,
                (finding.detail or "")[:200],
            )
            event = {
                "id": event_id,
                "severity": finding.severity,
                "title": finding.title,
                "detail": finding.detail,
                "sensor": finding.sensor,
                "rule_id": finding.rule_id,
                "metadata": finding.metadata or {},
            }
            threshold = str(self.cfg.get("toast_min_severity") or "HIGH").upper()
            if self.cfg.get("toast_enabled") and SEVERITY_RANK.get(finding.severity, 0) >= SEVERITY_RANK.get(threshold, 3):
                self._offer(self._toast_queue, event)
            if (
                self.cfg.get("ai_enabled")
                and finding.ai_eligible
                and finding.severity == "HIGH"
            ):
                self._offer(self._ai_queue, event_id)
            if finding.severity == "HIGH" and (
                self.cfg.get("auto_quick_scan_on_malware") or self.cfg.get("auto_block_high_remote")
            ):
                self._offer(self._auto_queue, event)

    @staticmethod
    def _offer(target: queue.Queue, item: Any) -> None:
        try:
            target.put_nowait(item)
        except queue.Full:
            pass

    # ------------------------------------------------------------------ 通知
    def _toast_loop(self) -> None:
        last_sent = 0.0
        while not self._stop.is_set():
            try:
                first = self._toast_queue.get(timeout=1.0)
            except queue.Empty:
                continue
            batch = [first]
            deadline = time.time() + 2.0
            while time.time() < deadline and len(batch) < 6:
                try:
                    batch.append(self._toast_queue.get_nowait())
                except queue.Empty:
                    time.sleep(0.15)
            wait = max(0.0, float(self.cfg.get("toast_min_interval_s") or 15.0) - (time.time() - last_sent))
            if wait and self._stop.wait(wait):
                return
            if len(batch) == 1:
                item = batch[0]
                title = f"⚠ {item['title']}"
                message = str(item.get("detail") or "")[:200]
            else:
                latest = batch[-1]
                title = f"⚠ 检测到 {len(batch)} 条高风险事件"
                message = f"最新：{latest['title']} — {str(latest.get('detail') or '')[:160]}"
            ok, detail = respond.send_toast(title, message)
            last_sent = time.time()
            self.last_toast = {"ts": last_sent, "ok": ok, "detail": detail}
            if not ok:
                logger.info("Toast 通知未成功：%s", detail)

    # ------------------------------------------------------------------ AI
    def _ai_loop(self) -> None:
        while not self._stop.is_set():
            now = time.time()
            if now - self._last_ai_probe > 60:
                self._last_ai_probe = now
                self.ai_available = ai.ollama_available(self.cfg)
            if not self.cfg.get("ai_enabled"):
                time.sleep(2)
                continue
            try:
                event_id = self._ai_queue.get(timeout=2.0)
            except queue.Empty:
                continue
            event = self.db.get_event(int(event_id))
            if not event or event.get("ai_note"):
                continue
            result = ai.analyze(event, self.cfg)
            self.ai_available = ai.ollama_available(self.cfg) if result is None else True
            if not result:
                continue
            note = ai.note_text(result)
            try:
                self.db.set_ai_note(int(event_id), note, str(result.get("engine") or "ollama"))
                self.db.record_action(int(event_id), "ai_analyze", str(result.get("engine") or ""), note, True)
            except Exception:  # noqa: BLE001
                logger.exception("写入 AI 研判失败")
                continue
            self.last_ai = {
                "ts": time.time(),
                "engine": result.get("engine"),
                "event_id": int(event_id),
            }
            logger.info("AI 研判事件 #%s：%s", event_id, note[:200])

    # ------------------------------------------------------------------ 自动处置
    def _auto_loop(self) -> None:
        while not self._stop.is_set():
            try:
                event = self._auto_queue.get(timeout=2.0)
            except queue.Empty:
                continue
            try:
                respond.auto_react(self.core, event)
            except Exception:  # noqa: BLE001
                logger.exception("自动处置线程异常")

    # ------------------------------------------------------------------ 状态
    def status(self) -> dict[str, Any]:
        return {
            "enabled": bool(self.cfg.get("ai_enabled")),
            "model": self.cfg.get("ai_model"),
            "available": bool(self.ai_available),
            "queue": self._ai_queue.qsize(),
            "toast_queue": self._toast_queue.qsize(),
            "last_ai": dict(self.last_ai),
            "last_toast": dict(self.last_toast),
            "ingested": self._ingested,
        }
