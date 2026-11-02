"""HTTP API and the one-page UI."""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from change2fa.export_text import error_text, verified_text
from change2fa.hub import Hub
from change2fa.runner import RunError, Runner
from change2fa.store import Store

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"


def create_app(db_path: Path) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        store = Store(db_path)
        await store.open()
        await store.mark_interrupted()
        app.state.store = store
        app.state.hub = Hub()
        app.state.runner = Runner(store, app.state.hub)
        yield
        runner: Runner = app.state.runner
        runner.stop_event.set()
        if runner.task is not None and not runner.task.done():
            runner.task.cancel()
        await store.close()

    app = FastAPI(title="Change 2FA", lifespan=lifespan)
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/")
    async def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/api/health")
    async def health():
        return {"ok": True}

    @app.get("/api/state")
    async def state(request: Request):
        return await request.app.state.runner.state()

    @app.put("/api/draft")
    async def draft(request: Request):
        body = await request.json()
        return await request.app.state.runner.save_draft(body)

    @app.post("/api/run")
    async def run(request: Request):
        body = await request.json()
        try:
            return await request.app.state.runner.start(body)
        except RunError as exc:
            raise HTTPException(exc.status, exc.message) from exc

    @app.post("/api/stop")
    async def stop(request: Request):
        return await request.app.state.runner.stop()

    @app.post("/api/clear")
    async def clear(request: Request):
        body = await request.json()
        try:
            return await request.app.state.runner.clear(str(body.get("filter") or ""))
        except RunError as exc:
            raise HTTPException(exc.status, exc.message) from exc

    @app.get("/api/export")
    async def export(request: Request, kind: str = "verified"):
        jobs = await request.app.state.store.list_jobs()
        if kind == "errors":
            return PlainTextResponse(error_text(jobs))
        if kind == "verified":
            return PlainTextResponse(verified_text(jobs))
        raise HTTPException(400, "invalid kind")

    @app.get("/api/jobs/{idx}/logs")
    async def job_logs(idx: int, request: Request):
        return {"items": await request.app.state.store.logs(idx)}

    @app.get("/api/events")
    async def events(request: Request):
        hub: Hub = request.app.state.hub
        queue = hub.subscribe()

        async def gen():
            try:
                yield "event: hello\ndata: {}\n\n"
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        item = await asyncio.wait_for(queue.get(), timeout=15)
                    except TimeoutError:
                        yield ": ping\n\n"
                        continue
                    payload = json.dumps(item["data"], ensure_ascii=False)
                    yield f"event: {item['event']}\ndata: {payload}\n\n"
            finally:
                hub.unsubscribe(queue)

        return StreamingResponse(
            gen(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    return app
