"""WHX 哨兵 · 事件模型与严重度工具。"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEVERITY_LABELS = {
    "HIGH": "高危",
    "MEDIUM": "中危",
    "LOW": "低危",
    "INFO": "提示",
}

STATUSES = ("new", "ack", "ignored")
STATUS_LABELS = {"new": "未处理", "ack": "已确认", "ignored": "已忽略"}


@dataclass
class Finding:
    """一条待入库的观测/告警，由传感器构造。"""

    sensor: str
    rule_id: str
    severity: str
    title: str
    detail: str = ""
    subject: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    dedupe_key: str = ""
    ts: float = field(default_factory=time.time)
    ai_eligible: bool = False
    dedupe_window_s: float = 600.0

    def key(self) -> str:
        if self.dedupe_key:
            return self.dedupe_key
        raw = f"{self.sensor}|{self.rule_id}|{self.subject}|{self.title}"
        return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:24]


def normalize_severity(value: Any, default: str = "INFO") -> str:
    text = str(value or "").strip().upper()
    return text if text in SEVERITY_RANK else default


def at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_RANK.get(normalize_severity(severity), 0) >= SEVERITY_RANK.get(
        normalize_severity(threshold), 0
    )


def time_text(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts if ts else time.time()))


def day_text(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(ts if ts else time.time()))
