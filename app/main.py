"""A small, inert operations portal for the controlled HTTP experiment.

The UI is server-rendered from app/templates/ (single sign-in page plus denial and
not-found pages). Disclosures the experiment relies on remain literal response-body
text, and page chrome stays out of the disclosure scan: no navigation links and a
relative form action.
"""

import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import CONDITIONS, LAB_ID, ROOT, load_decoys
from app.disclosure import scan_refs
from app.intent import classify_intent
from app.logging import EventWriter

STATIC_DIR = ROOT / "app" / "static"
UNLOGGED_PREFIXES = ("/static/", "/favicon.ico")


def create_app(condition: str, log_path: Path, decoys=None) -> FastAPI:
    if condition not in CONDITIONS:
        raise ValueError("condition must be baseline or enhanced")
    decoys = load_decoys() if decoys is None else decoys
    by_path = {item.path: item for item in decoys}
    writer = EventWriter(log_path)
    sequences = defaultdict(int)
    disclosed = defaultdict(set)
    templates = Jinja2Templates(directory=str(ROOT / "app" / "templates"))
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.middleware("http")
    async def capture(request: Request, call_next):
        if request.url.path.startswith(UNLOGGED_PREFIXES):
            return await call_next(request)
        server_session = request.cookies.get("hd_sid")
        minted = server_session is None
        if minted:
            server_session = uuid.uuid4().hex
        session = request.headers.get("X-Lab-Session", "manual")
        playbook = request.headers.get("X-Lab-Playbook", "manual")
        session = session if LAB_ID.fullmatch(session) else "manual"
        playbook = playbook if LAB_ID.fullmatch(playbook) else "manual"
        sequences[server_session] += 1
        sequence = sequences[server_session]
        before = sorted(disclosed[server_session])
        response = await call_next(request)
        # BaseHTTPMiddleware hands back a streaming wrapper; drain it so the
        # disclosure scan sees the real body, then rebuild a plain response.
        body = b"".join([chunk async for chunk in response.body_iterator])
        here = sorted(scan_refs(body.decode("utf-8", "replace")))
        disclosed[server_session].update(here)
        artefact = getattr(request.state, "artefact", None)
        category = artefact.category if artefact else None
        writer.write({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": session,
            "server_session": server_session,
            "playbook_id": playbook,
            "condition": condition,
            "sequence": sequence,
            "method": request.method,
            "path": request.url.path[:2048],
            "query_keys": sorted({key[:80] for key in request.query_params.keys()}),
            "status_code": response.status_code,
            "artefact_id": artefact.id if artefact else None,
            "artefact_category": category,
            "intent_labels": classify_intent(request.method, request.url.path, category),
            "follow_through": request.headers.get("X-Lab-Follow") == "1",
            "disclosed_before": before,
            "disclosed_here": here,
        })
        headers = {
            k: v for k, v in response.headers.items() if k.lower() != "content-length"
        }
        rebuilt = Response(
            content=body,
            status_code=response.status_code,
            headers=headers,
            media_type=response.media_type,
        )
        if minted:
            rebuilt.set_cookie("hd_sid", server_session, httponly=True, samesite="strict")
        rebuilt.headers["Cache-Control"] = "no-store"
        rebuilt.headers["X-Content-Type-Options"] = "nosniff"
        rebuilt.headers["Server"] = "dispatch-gateway"  # deliberate service masquerade
        return rebuilt

    @app.get("/")
    async def index(request: Request):
        # Relative form action: keeps the literal "/login" out of the home body so
        # navigation chrome never enters the disclosure scan.
        return templates.TemplateResponse(
            request=request, name="login.html", context={"action": "login", "message": None}
        )

    @app.get("/login")
    async def login_page(request: Request):
        return templates.TemplateResponse(
            request=request, name="login.html", context={"action": "", "message": None}
        )

    @app.post("/login")
    async def login_attempt(request: Request):
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > 16_384:
                return PlainTextResponse("Request too large", status_code=413)
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "action": "",
                "message": "Authentication failed. Check your credentials and try again.",
            },
            status_code=401,
        )

    @app.get("/admin")
    async def admin(request: Request):
        debug_refs = (
            ["/files/.env", "/files/runbooks/credential-rotation.txt", "/api/users"]
            if condition == "enhanced"
            else []
        )
        return templates.TemplateResponse(
            request=request,
            name="denied.html",
            context={"request_id": uuid.uuid4().hex[:12], "links": debug_refs},
            status_code=403,
        )

    @app.get("/favicon.ico")
    async def favicon():
        return FileResponse(str(STATIC_DIR / "logo.png"), media_type="image/png")

    @app.get("/robots.txt")
    async def robots():
        text = "User-agent: *\nDisallow: /admin\n"
        if condition == "enhanced":
            text += "Disallow: /files/.env\nDisallow: /files/.git/config\n"
        return PlainTextResponse(text)

    @app.get("/api/status")
    async def status():
        result = {"service": "dispatch", "ok": True}
        if condition == "enhanced":
            result.update(environment="staging", config_hint="/files/.env")
        return result

    @app.get("/api/users")
    async def users():
        if condition == "baseline":
            return {"users": []}
        return {
            "users": [
                {"id": 1001, "email": "a.rivera@homerdrive.invalid"},
                {"id": 1002, "email": "m.chen@homerdrive.invalid"},
            ],
            "backup_hint": "/files/backups/customers.sql",
        }

    @app.get("/files/{path:path}")
    async def file_view(path: str, request: Request):
        if path.startswith("/") or ".." in path.split("/"):
            return templates.TemplateResponse(
                request=request, name="notfound.html",
                context={"path": request.url.path}, status_code=404,
            )
        artefact = by_path.get(path)
        if artefact is None:
            return templates.TemplateResponse(
                request=request, name="notfound.html",
                context={"path": request.url.path}, status_code=404,
            )
        request.state.artefact = artefact
        return PlainTextResponse(artefact.content(condition), media_type=artefact.media_type)

    @app.exception_handler(404)
    async def not_found(request: Request, exc):
        return templates.TemplateResponse(
            request=request, name="notfound.html",
            context={"path": request.url.path}, status_code=404,
        )

    return app
