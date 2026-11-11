"""WHX 哨兵 · 本地事件数据库（SQLite，WAL）。

所有数据只保存在本机 data/sentinel.db；多个传感器线程共享一个 Database 实例，
写操作通过进程内锁串行化，读操作各自开连接（WAL 允许并发读）。
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from events import Finding

logger = logging.getLogger("whx.sentinel.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    time TEXT NOT NULL,
    day TEXT NOT NULL,
    sensor TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT,
    subject TEXT,
    metadata TEXT,
    dedupe_key TEXT NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'new',
    ai_note TEXT,
    ai_engine TEXT,
    first_ts REAL NOT NULL,
    last_ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_sensor ON events(sensor, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_dedupe ON events(dedupe_key, last_ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_status ON events(status, ts DESC);

CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    time TEXT NOT NULL,
    event_id INTEGER,
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT,
    ok INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_actions_ts ON actions(ts DESC);

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    payload = item.get("metadata")
    if isinstance(payload, str) and payload:
        try:
            item["metadata"] = json.loads(payload)
        except json.JSONDecodeError:
            item["metadata"] = {"raw": payload}
    elif payload is None:
        item["metadata"] = {}
    return item


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._initialized = False

    # ------------------------------------------------------------------ 基础
    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=8000")
        connection.execute("PRAGMA synchronous=NORMAL")
        return connection

    def init(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            connection = self._connect()
            try:
                connection.executescript(SCHEMA)
                connection.commit()
            finally:
                connection.close()
            self._initialized = True
            logger.info("事件库已就绪：%s", self.path)

    def close(self) -> None:
        self._initialized = False

    # ------------------------------------------------------------------ 写入
    def insert_finding(self, finding: Finding) -> tuple[int, bool]:
        """Insert a finding, collapsing repeats inside its dedupe window.

        Returns (event_id, is_new). is_new=False means an existing event's
        counter/time was refreshed instead of creating a new row.
        """

        ts = float(finding.ts or time.time())
        key = finding.key()
        window = float(finding.dedupe_window_s or 600.0)
        cutoff = ts - window
        time_text = time.strftime("%H:%M:%S", time.localtime(ts))
        day_text = time.strftime("%Y-%m-%d", time.localtime(ts))
        metadata = json.dumps(finding.metadata or {}, ensure_ascii=False, default=str)
        if len(metadata) > 8000:
            metadata = metadata[:8000]

        with self._lock:
            connection = self._connect()
            try:
                with connection:
                    row = connection.execute(
                        "SELECT id FROM events WHERE dedupe_key=? AND last_ts>=? "
                        "ORDER BY id DESC LIMIT 1",
                        (key, cutoff),
                    ).fetchone()
                    if row:
                        connection.execute(
                            "UPDATE events SET seen_count=seen_count+1, last_ts=?, time=?, day=?, "
                            "detail=CASE WHEN length(?)>length(detail) THEN ? ELSE detail END "
                            "WHERE id=?",
                            (ts, time_text, day_text, finding.detail or "", finding.detail or "", row["id"]),
                        )
                        return int(row["id"]), False
                    cursor = connection.execute(
                        "INSERT INTO events (ts, time, day, sensor, rule_id, severity, title, detail, "
                        "subject, metadata, dedupe_key, seen_count, status, first_ts, last_ts) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'new', ?, ?)",
                        (
                            ts,
                            time_text,
                            day_text,
                            finding.sensor,
                            finding.rule_id,
                            finding.severity,
                            finding.title,
                            finding.detail or "",
                            finding.subject or "",
                            metadata,
                            key,
                            ts,
                            ts,
                        ),
                    )
                    return int(cursor.lastrowid), True
            except sqlite3.Error:
                logger.exception("写入事件失败")
                return 0, False
            finally:
                connection.close()

    def mark_status(self, event_id: int, status: str) -> bool:
        if status not in {"new", "ack", "ignored"}:
            return False
        with self._lock:
            connection = self._connect()
            try:
                with connection:
                    cursor = connection.execute(
                        "UPDATE events SET status=? WHERE id=?", (status, int(event_id))
                    )
                return cursor.rowcount > 0
            finally:
                connection.close()

    def set_ai_note(self, event_id: int, note: str, engine: str) -> None:
        with self._lock:
            connection = self._connect()
            try:
                with connection:
                    connection.execute(
                        "UPDATE events SET ai_note=?, ai_engine=? WHERE id=?",
                        (str(note)[:4000], str(engine)[:40], int(event_id)),
                    )
            finally:
                connection.close()

    def record_action(
        self,
        event_id: int | None,
        action: str,
        target: str = "",
        detail: str = "",
        ok: bool = True,
    ) -> int:
        ts = time.time()
        with self._lock:
            connection = self._connect()
            try:
                with connection:
                    cursor = connection.execute(
                        "INSERT INTO actions (ts, time, event_id, action, target, detail, ok) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            ts,
                            time.strftime("%H:%M:%S", time.localtime(ts)),
                            int(event_id) if event_id else None,
                            str(action)[:60],
                            str(target)[:300],
                            str(detail)[:1000],
                            1 if ok else 0,
                        ),
                    )
                    return int(cursor.lastrowid)
            finally:
                connection.close()

    # ------------------------------------------------------------------ 读取
    def list_events(
        self,
        limit: int = 50,
        offset: int = 0,
        severity: str | None = None,
        sensor: str | None = None,
        status: str | None = None,
        query: str | None = None,
        hours: float | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        clauses: list[str] = []
        params: list[Any] = []
        if severity:
            clauses.append("severity=?")
            params.append(severity.upper())
        if sensor:
            clauses.append("sensor=?")
            params.append(sensor)
        if status:
            clauses.append("status=?")
            params.append(status)
        if hours:
            clauses.append("ts>=?")
            params.append(time.time() - float(hours) * 3600)
        if query:
            clauses.append("(title LIKE ? OR detail LIKE ? OR subject LIKE ? OR rule_id LIKE ?)")
            pattern = f"%{query}%"
            params.extend([pattern, pattern, pattern, pattern])
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        limit = max(1, min(int(limit), 500))
        offset = max(0, int(offset))

        connection = self._connect()
        try:
            total = connection.execute(
                f"SELECT COUNT(*) AS n FROM events{where}", params
            ).fetchone()["n"]
            rows = connection.execute(
                f"SELECT * FROM events{where} ORDER BY last_ts DESC, id DESC LIMIT ? OFFSET ?",
                (*params, limit, offset),
            ).fetchall()
            return [_row_to_dict(row) for row in rows], int(total)
        finally:
            connection.close()

    def get_event(self, event_id: int) -> dict[str, Any] | None:
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM events WHERE id=?", (int(event_id),)).fetchone()
            return _row_to_dict(row) if row else None
        finally:
            connection.close()

    def recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        rows, _ = self.list_events(limit=limit)
        return rows

    def recent_actions(self, limit: int = 20) -> list[dict[str, Any]]:
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT * FROM actions ORDER BY id DESC LIMIT ?", (max(1, min(int(limit), 100)),)
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            connection.close()

    def stats(self, hours: float = 24.0) -> dict[str, Any]:
        since = time.time() - hours * 3600
        connection = self._connect()
        try:
            by_severity = {row["severity"]: int(row["n"]) for row in connection.execute(
                "SELECT severity, COUNT(*) AS n FROM events WHERE ts>=? GROUP BY severity", (since,)
            ).fetchall()}
            by_sensor = [
                {"sensor": row["sensor"], "n": int(row["n"])}
                for row in connection.execute(
                    "SELECT sensor, COUNT(*) AS n FROM events WHERE ts>=? GROUP BY sensor "
                    "ORDER BY n DESC LIMIT 12",
                    (since,),
                ).fetchall()
            ]
            total = connection.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]
            open_count = connection.execute(
                "SELECT COUNT(*) AS n FROM events WHERE status='new'"
            ).fetchone()["n"]
            ai_done = connection.execute(
                "SELECT COUNT(*) AS n FROM events WHERE ai_note IS NOT NULL AND ai_note!=''"
            ).fetchone()["n"]
            return {
                "events_24h": sum(by_severity.values()),
                "high_24h": by_severity.get("HIGH", 0),
                "medium_24h": by_severity.get("MEDIUM", 0),
                "low_24h": by_severity.get("LOW", 0),
                "info_24h": by_severity.get("INFO", 0),
                "by_severity": by_severity,
                "by_sensor": by_sensor,
                "total_events": int(total),
                "open_events": int(open_count),
                "ai_done": int(ai_done),
            }
        finally:
            connection.close()

    def timeline(self, hours: int = 24) -> list[dict[str, Any]]:
        """Bucket events per hour for the dashboard chart (oldest → newest)."""

        hours = max(1, min(int(hours), 72))
        now = time.time()
        start = now - hours * 3600
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT ts, severity FROM events WHERE ts>=?", (start,)
            ).fetchall()
        finally:
            connection.close()

        bucket_seconds = 3600
        buckets: list[dict[str, Any]] = []
        current = start
        index = 0
        while index < hours:
            label = time.strftime("%H:00", time.localtime(current))
            buckets.append({"label": label, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "total": 0})
            current += bucket_seconds
            index += 1
        last_start = start + (hours - 1) * bucket_seconds
        for row in rows:
            ts = float(row["ts"])
            index = int((ts - start) // bucket_seconds)
            index = max(0, min(hours - 1, index))
            severity = str(row["severity"] or "INFO")
            if severity not in {"HIGH", "MEDIUM", "LOW", "INFO"}:
                severity = "INFO"
            buckets[index][severity] += 1
            buckets[index]["total"] += 1
        # 保证最后一个桶对应最近一小时（标签用当前小时更直观）
        if buckets:
            buckets[-1]["label"] = time.strftime("%H:00", time.localtime(max(last_start, now - 60)))
        return buckets

    def export(self, limit: int = 1000) -> list[dict[str, Any]]:
        rows, _ = self.list_events(limit=min(int(limit), 5000), hours=None)
        return rows

    def count(self) -> int:
        connection = self._connect()
        try:
            return int(connection.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"])
        finally:
            connection.close()

    def size_mb(self) -> float:
        try:
            total = self.path.stat().st_size
            for suffix in ("-wal", "-shm"):
                extra = Path(str(self.path) + suffix)
                if extra.is_file():
                    total += extra.stat().st_size
            return round(total / (1024 * 1024), 2)
        except OSError:
            return 0.0

    # ------------------------------------------------------------------ 维护
    def prune(self, retention_days: int = 30, max_events: int = 20000) -> int:
        cutoff = time.time() - max(1, int(retention_days)) * 86400
        removed = 0
        with self._lock:
            connection = self._connect()
            try:
                with connection:
                    cursor = connection.execute("DELETE FROM events WHERE ts<?", (cutoff,))
                    removed += cursor.rowcount
                    cursor = connection.execute(
                        "DELETE FROM events WHERE id NOT IN "
                        "(SELECT id FROM events ORDER BY id DESC LIMIT ?)",
                        (max(1000, int(max_events)),),
                    )
                    removed += cursor.rowcount
                    connection.execute("DELETE FROM actions WHERE ts<?", (cutoff,))
                    connection.execute(
                        "DELETE FROM actions WHERE id NOT IN "
                        "(SELECT id FROM actions ORDER BY id DESC LIMIT 5000)"
                    )
            finally:
                connection.close()
        if removed:
            logger.info("事件库清理：删除 %s 条过期记录", removed)
        return removed

    def set_meta(self, key: str, value: Any) -> None:
        with self._lock:
            connection = self._connect()
            try:
                with connection:
                    connection.execute(
                        "INSERT INTO metadata (key, value) VALUES (?, ?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (key, json.dumps(value, ensure_ascii=False, default=str)),
                    )
            finally:
                connection.close()

    def get_meta(self, key: str, default: Any = None) -> Any:
        connection = self._connect()
        try:
            row = connection.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
            if not row:
                return default
            try:
                return json.loads(row["value"])
            except (TypeError, json.JSONDecodeError):
                return default
        finally:
            connection.close()
