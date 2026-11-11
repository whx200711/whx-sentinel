"""WHX 哨兵 · 本地 Web API 与看板托管（127.0.0.1 only）。

只读接口（状态/事件/时间线）不要求令牌；所有会改变系统或配置的接口都要求
X-Sentinel-Token（令牌只回显给本机请求，看板从 /api/token 获取）。
"""

from __future__ import annotations

import json
import logging
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

import ai
import config
import respond
from events import SEVERITIES

logger = logging.getLogger("whx.sentinel.webapi")

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'"
    ),
}

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
_MAX_BODY_BYTES = 1_048_576  # 1 MB


def _hostname(host_header: str) -> str:
    """从 Host 头里取主机名（去端口 / IPv6 方括号），非法值返回空串。"""

    value = str(host_header or "").strip().lower()
    try:
        return (urlsplit("//" + value).hostname or "").lower()
    except ValueError:
        return ""


def create_app(core: Any) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        core.start()
        try:
            yield
        finally:
            core.stop()

    app = FastAPI(
        title="WHX Sentinel",
        version=config.VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    def require_token(
        x_sentinel_token: str | None = Header(default=None, alias="X-Sentinel-Token"),
    ) -> None:
        expected = str(core.cfg.get("control_token") or "")
        if not expected or not x_sentinel_token or not secrets.compare_digest(
            x_sentinel_token, expected
        ):
            raise HTTPException(status_code=403, detail="missing or invalid X-Sentinel-Token")

    @app.middleware("http")
    async def _guard(request: Request, call_next):
        # H-1：所有接口都校验 Host，防止 DNS rebinding 页面直读本机数据
        if _hostname(request.headers.get("host", "")) not in _LOOPBACK_HOSTS:
            return JSONResponse(
                status_code=403,
                content={"detail": "只接受 127.0.0.1 / localhost / [::1] 访问"},
            )
        response = await call_next(request)
        for key, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def _check_body_size(request: Request) -> None:
        length = request.headers.get("content-length")
        if not length:
            return
        try:
            size = int(length)
        except ValueError:
            raise HTTPException(status_code=400, detail="Content-Length 非法")
        if size > _MAX_BODY_BYTES:
            raise HTTPException(status_code=413, detail="请求体超过 1 MB 上限")

    async def _read_json(request: Request) -> Any:
        _check_body_size(request)
        try:
            return await request.json()
        except (json.JSONDecodeError, ValueError):
            return None

    # ------------------------------------------------------------------ 静态
    web_dir = Path(config.WEB_DIR)
    if web_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(web_dir)), name="static")

    @app.get("/")
    def index() -> Any:
        page = web_dir / "index.html"
        if not page.is_file():
            return JSONResponse(
                status_code=503,
                content={
                    "error": "看板文件缺失",
                    "hint": "请确认 web/index.html 存在，或访问 /api/status 查看接口",
                },
            )
        return FileResponse(page, media_type="text/html; charset=utf-8")

    @app.get("/favicon.svg")
    def favicon() -> Any:
        icon = web_dir / "favicon.svg"
        if icon.is_file():
            return FileResponse(icon, media_type="image/svg+xml")
        raise HTTPException(status_code=404, detail="no favicon")

    # ------------------------------------------------------------------ 只读 API
    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {
            "app": config.APP_ID,
            "status": "ok",
            "version": config.VERSION,
            "uptime_s": round(time.time() - core.started_at),
        }

    @app.get("/api/token")
    def token(request: Request) -> dict[str, str]:
        client = (request.client.host if request.client else "") or ""
        if client not in _LOOPBACK_HOSTS or _hostname(request.headers.get("host", "")) not in _LOOPBACK_HOSTS:
            raise HTTPException(status_code=403, detail="token is only exposed to loopback clients")
        return {"token": str(core.cfg.get("control_token") or "")}

    @app.get("/api/status")
    def status() -> dict[str, Any]:
        return core.status()

    @app.get("/api/events")
    def list_events(
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
        severity: str | None = Query(None),
        sensor: str | None = Query(None),
        status: str | None = Query(None),
        q: str | None = Query(None),
        hours: float | None = Query(None, ge=0, le=24 * 90),
    ) -> dict[str, Any]:
        if severity and severity.upper() not in SEVERITIES:
            raise HTTPException(status_code=422, detail="unknown severity")
        events, total = core.db.list_events(
            limit=limit,
            offset=offset,
            severity=severity.upper() if severity else None,
            sensor=sensor or None,
            status=status or None,
            query=q or None,
            hours=hours,
        )
        return {"events": events, "total": total, "limit": limit, "offset": offset}

    @app.get("/api/events/{event_id}")
    def get_event(event_id: int) -> dict[str, Any]:
        event = core.db.get_event(event_id)
        if not event:
            raise HTTPException(status_code=404, detail="事件不存在")
        return event

    @app.get("/api/timeline")
    def timeline(hours: int = Query(24, ge=1, le=72)) -> dict[str, Any]:
        return {"buckets": core.db.timeline(hours), "hours": hours}

    @app.get("/api/actions/recent")
    def recent_actions(limit: int = Query(20, ge=1, le=100)) -> dict[str, Any]:
        return {"actions": core.db.recent_actions(limit)}

    @app.get("/api/settings")
    def get_settings() -> dict[str, Any]:
        return {"settings": core.public_settings()}

    @app.get("/api/allowlist")
    def get_allowlist() -> dict[str, Any]:
        return {"allowlist": core.cfg.get("allowlist") or {}}

    @app.get("/api/export")
    def export_events(limit: int = Query(1000, ge=1, le=5000)) -> JSONResponse:
        events = core.db.export(limit)
        payload = json.dumps(events, ensure_ascii=False, default=str)
        return JSONResponse(
            content=json.loads(payload),
            headers={
                "Content-Disposition": 'attachment; filename="whx-sentinel-events.json"'
            },
        )

    @app.get("/api/ai/test")
    def ai_test() -> dict[str, Any]:
        return {
            "enabled": bool(core.cfg.get("ai_enabled")),
            "model": core.cfg.get("ai_model"),
            "available": ai.ollama_available(core.cfg),
        }

    # ------------------------------------------------------------------ 写 API（需要令牌）
    @app.post("/api/settings", dependencies=[Depends(require_token)])
    async def update_settings(request: Request) -> dict[str, Any]:
        payload = await _read_json(request)
        if not isinstance(payload, dict):
            raise HTTPException(status_code=422, detail="请求体必须是 JSON 对象")
        try:
            result = core.update_settings(payload)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        return {"ok": True, **result}

    @app.post("/api/allowlist", dependencies=[Depends(require_token)])
    async def change_allowlist(request: Request) -> dict[str, Any]:
        payload = await _read_json(request)
        if not isinstance(payload, dict):
            raise HTTPException(status_code=422, detail="请求体必须是 JSON 对象")
        return core.allowlist_change(payload)

    @app.post("/api/actions/{action}", dependencies=[Depends(require_token)])
    async def run_action(action: str, request: Request) -> dict[str, Any]:
        payload = await _read_json(request)
        if not isinstance(payload, dict):
            payload = {}
        logger.info("看板动作：%s %s", action, {k: v for k, v in payload.items() if k != "token"})
        # M-2：AI 研判等同步动作可能阻塞到 150 秒，放线程池避免卡死事件循环
        return await run_in_threadpool(respond.execute, core, action, payload)

    @app.post("/api/admin/shutdown", dependencies=[Depends(require_token)])
    def shutdown() -> dict[str, Any]:
        core.request_shutdown()
        return {"ok": True, "message": "哨兵正在退出…"}

    return app
