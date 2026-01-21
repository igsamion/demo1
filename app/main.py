import json
import logging
import secrets
import time
from typing import Any, AsyncGenerator

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, Signer

from app.config import load_settings
from app.ldap_client import fetch_user, verify_password
from app.security import (
    LockoutManager,
    RateLimiter,
    SessionStore,
    SprayDetector,
    constant_time_compare,
)

load_dotenv()

logger = logging.getLogger("ollama_ad")
logging.basicConfig(level=logging.INFO)

app = FastAPI()
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

settings = load_settings()

session_store = SessionStore(settings.session_secret)
csrf_signer = Signer(settings.csrf_secret)
login_rate_limiter = RateLimiter(settings.rate_limit_login_per_min)
chat_rate_limiter = RateLimiter(settings.rate_limit_chat_per_min)
lockout_manager = LockoutManager(
    settings.lockout_threshold,
    settings.lockout_window_min,
    settings.lockout_duration_min,
)
spray_detector = SprayDetector()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers[
        "Content-Security-Policy"
    ] = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'"
    return response


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    client = request.client
    return client.host if client else "unknown"


def _validate_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if not origin:
        return
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    expected = scheme + "://" + request.headers.get("host", "")
    if origin != expected:
        raise HTTPException(status_code=403, detail="Invalid origin")


def _get_session(request: Request) -> tuple[str, Any] | tuple[None, None]:
    cookie = request.cookies.get("session")
    if not cookie:
        return None, None
    session_id = session_store.unsign(cookie)
    if not session_id:
        return None, None
    session = session_store.get(session_id)
    if not session:
        return None, None

    now = time.time()
    idle_timeout = settings.session_idle_timeout_min * 60
    absolute_timeout = settings.session_absolute_timeout_h * 3600
    if now - session.last_activity > idle_timeout:
        session_store.delete(session_id)
        return None, None
    if now - session.created_at > absolute_timeout:
        session_store.delete(session_id)
        return None, None

    session.last_activity = now
    return session_id, session


def _verify_csrf(request: Request, token: str | None, session_token: str) -> None:
    _validate_origin(request)
    if not token or not constant_time_compare(token, session_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/")
async def index(request: Request):
    session_id, session = _get_session(request)
    if session:
        return RedirectResponse("/chat", status_code=302)
    return RedirectResponse("/login", status_code=302)


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    session_id, session = _get_session(request)
    if session:
        return RedirectResponse("/chat", status_code=302)
    return _login_response(request)


@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(""),
):
    _validate_origin(request)
    csrf_cookie = request.cookies.get("csrf_login")
    if not csrf_cookie or not _verify_login_csrf(csrf_token, csrf_cookie):
        raise HTTPException(status_code=403, detail="Invalid CSRF")
    ip = _get_client_ip(request)
    key = f"{ip}:{username}"
    if lockout_manager.is_locked(key):
        logger.warning("lockout active", extra={"ip": ip, "username": username})
        raise HTTPException(status_code=429, detail="Too many attempts")
    if not login_rate_limiter.allow(key):
        logger.warning("rate limit hit", extra={"ip": ip, "username": username})
        raise HTTPException(status_code=429, detail="Too many attempts")

    if spray_detector.register(ip, username):
        logger.warning("spray detected", extra={"ip": ip})

    user = fetch_user(
        url=settings.ldap_url,
        base_dn=settings.ldap_base_dn,
        bind_dn=settings.ldap_bind_dn,
        bind_password=settings.ldap_bind_password,
        user_filter=settings.ldap_user_filter,
        username=username,
        attrs=settings.ldap_attrs,
        timeout=settings.ldap_timeout_seconds,
        ca_cert=settings.ldap_ca_cert,
    )
    if not user:
        lockout_manager.record_failure(key)
        raise HTTPException(status_code=401, detail="Authentication failed")

    bind_identity = username if (settings.ldap_use_upn and "@" in username) else user.dn
    if not verify_password(
        url=settings.ldap_url,
        user_dn_or_upn=bind_identity,
        password=password,
        timeout=settings.ldap_timeout_seconds,
        ca_cert=settings.ldap_ca_cert,
    ):
        lockout_manager.record_failure(key)
        raise HTTPException(status_code=401, detail="Authentication failed")

    if settings.required_ad_groups:
        groups = {g.lower() for g in user.attributes.get("memberOf", [])}
        required = {g.lower() for g in settings.required_ad_groups}
        if not groups.intersection(required):
            logger.warning(
                "missing required group",
                extra={"ip": ip, "username": username},
            )
            raise HTTPException(status_code=403, detail="Access denied")

    lockout_manager.reset(key)
    session_data = session_store.create(
        {
            "username": username,
            "display_name": _first(user.attributes.get("displayName")),
            "email": _first(user.attributes.get("mail")),
            "object_guid": _first(user.attributes.get("objectGUID")),
            "member_of": user.attributes.get("memberOf", []),
        }
    )
    signed = session_store.sign(session_data.session_id)
    response = RedirectResponse("/chat", status_code=302)
    response.set_cookie(
        "session",
        signed,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="strict",
        max_age=settings.session_absolute_timeout_h * 3600,
    )
    response.delete_cookie("csrf_login")
    return response


def _first(value: Any) -> str | None:
    if isinstance(value, list):
        return value[0] if value else None
    return value


@app.get("/chat", response_class=HTMLResponse)
async def chat(request: Request):
    session_id, session = _get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(
        "chat.html",
        {
            "request": request,
            "user": session.user,
            "csrf_token": session.csrf_token,
            "messages": session.chat_history,
        },
    )


@app.post("/logout")
async def logout(request: Request):
    session_id, session = _get_session(request)
    if not session:
        return RedirectResponse("/login", status_code=302)
    form = await request.form()
    _verify_csrf(request, form.get("csrf_token"), session.csrf_token)
    session_store.delete(session_id)
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie("session")
    return response


@app.post("/clear")
async def clear_chat(request: Request):
    session_id, session = _get_session(request)
    if not session:
        raise HTTPException(status_code=401)
    form = await request.form()
    _verify_csrf(request, form.get("csrf_token"), session.csrf_token)
    session.chat_history = []
    return RedirectResponse("/chat", status_code=302)


@app.post("/api/chat/stream")
async def chat_stream(
    request: Request,
    prompt: str = Form(...),
    csrf_token: str = Form(""),
):
    session_id, session = _get_session(request)
    if not session:
        raise HTTPException(status_code=401)
    _verify_csrf(request, csrf_token, session.csrf_token)

    ip = _get_client_ip(request)
    if not chat_rate_limiter.allow(f"{ip}:{session_id}"):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    prompt = prompt.strip()
    if not prompt:
        raise HTTPException(status_code=400, detail="Prompt required")

    session.chat_history.append({"role": "user", "content": prompt})
    context = session.chat_history[-settings.chat_context_messages :]

    async def event_stream() -> AsyncGenerator[str, None]:
        payload = {
            "model": settings.ollama_model,
            "stream": True,
            "messages": context,
        }
        async with httpx.AsyncClient(timeout=settings.ollama_timeout_seconds) as client:
            async with client.stream(
                "POST",
                f"{settings.ollama_url}/api/chat",
                json=payload,
            ) as resp:
                if resp.status_code != 200:
                    yield _sse_event("error", "Upstream error")
                    return
                content = []
                async for line in resp.aiter_lines():
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    delta = data.get("message", {}).get("content")
                    if delta:
                        content.append(delta)
                        yield _sse_event("message", delta)
                assistant_message = "".join(content)
                if assistant_message:
                    session.chat_history.append(
                        {"role": "assistant", "content": assistant_message}
                    )
                yield _sse_event("done", "")

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache"},
    )


def _sse_event(event: str, data: str) -> str:
    safe = data.replace("\r", "").replace("\n", "\\n")
    return f"event: {event}\ndata: {safe}\n\n"


def _verify_login_csrf(token: str, signed_cookie: str) -> bool:
    try:
        raw = csrf_signer.unsign(signed_cookie.encode()).decode()
    except BadSignature:
        return False
    return constant_time_compare(token, raw)


def _login_response(request: Request) -> Response:
    token = secrets.token_urlsafe(32)
    signed_token = csrf_signer.sign(token.encode()).decode()
    response = templates.TemplateResponse(
        "login.html",
        {"request": request, "csrf_token": token},
    )
    response.set_cookie(
        "csrf_login",
        signed_token,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="strict",
        max_age=300,
    )
    return response


@app.get("/api/session")
async def session_info(request: Request):
    _, session = _get_session(request)
    if not session:
        raise HTTPException(status_code=401)
    return {"user": session.user, "csrf_token": session.csrf_token}


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if request.url.path.startswith("/api/"):
        return Response(
            content=json.dumps({"error": "Request failed"}),
            status_code=exc.status_code,
            media_type="application/json",
        )
    if exc.status_code == 403:
        return templates.TemplateResponse(
            "forbidden.html", {"request": request}, status_code=403
        )
    response = _login_response(request)
    response.status_code = exc.status_code
    response.context["error"] = "Anmeldung fehlgeschlagen."
    return response


@app.get("/forbidden", response_class=HTMLResponse)
async def forbidden(request: Request):
    return templates.TemplateResponse(
        "forbidden.html", {"request": request}, status_code=403
    )


@app.on_event("startup")
async def startup_event():
    logger.info("App starting", extra={"env": settings.app_env})
