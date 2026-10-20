"""Session authentication for browser pages and the API documentation."""

from urllib.parse import quote

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, RedirectResponse, Response

from .auth import get_current_user
from .security import safe_relative_path, session_cookie


PUBLIC_PATHS = frozenset(
    {
        "/login",
        "/register",
        "/accept-invite",
        "/request-access",
        "/favicon.ico",
    }
)
DOCS_PATHS = frozenset(
    {
        "/api/docs",
        "/api/docs/oauth2-redirect",
        "/api/redoc",
        "/openapi.json",
    }
)
PAGE_ROLE_REQUIREMENTS = {
    "/": frozenset({"Threat Hunter", "admin"}),
    "/agent/chat": frozenset({"Threat Hunter", "admin"}),
    "/agent/investigations": frozenset({"Threat Hunter", "admin"}),
    "/agent/playbooks": frozenset({"Incident Responder", "admin"}),
    "/integrations": frozenset({"Incident Responder", "admin"}),
    "/integrations/wazuh": frozenset({"Incident Responder", "admin"}),
    "/analysis/ioc": frozenset({"SOC Analyst Tier 1-2", "admin"}),
    "/analysis/file": frozenset({"SOC Analyst Tier 1-2", "admin"}),
    "/analysis/email": frozenset({"SOC Analyst Tier 1-2", "admin"}),
    "/admin/helpdesk": frozenset({"admin"}),
    "/settings": frozenset({"admin"}),
}

ROLE_DEFAULT_LANDING = {
    "SOC Analyst Tier 1-2": "/analysis/ioc",
    "Incident Responder": "/agent/playbooks",
    "Threat Hunter": "/",
    "Team Lead": "/dashboard",
    "admin": "/",
}


def page_auth_user(request: Request):
    """Return the authenticated user from the session cookie or Bearer header."""
    token = session_cookie(request.cookies)
    if not token:
        authorization = request.headers.get("authorization", "")
        if authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
    if not token:
        return None
    try:
        return get_current_user(token, request=request)
    except Exception:
        return None


def _login_redirect(request: Request) -> RedirectResponse:
    next_path = safe_relative_path(request.url.path)
    return RedirectResponse(
        url=f"/login?next={quote(next_path, safe='')}",
        status_code=303,
    )


class PageAuthMiddleware(BaseHTTPMiddleware):
    """Require sessions on private pages and roles on restricted pages."""

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.scope.get("type") != "http":
            return await call_next(request)

        path = request.url.path
        if path in DOCS_PATHS:
            user = page_auth_user(request)
            if user is None:
                return _login_redirect(request)
            request.state.user = user
            return await call_next(request)

        if (
            path in PUBLIC_PATHS
            or path == "/api"
            or path.startswith("/api/")
            or path == "/static"
            or path.startswith("/static/")
        ):
            return await call_next(request)

        user = page_auth_user(request)
        if user is None:
            return _login_redirect(request)
        request.state.user = user

        required_roles = PAGE_ROLE_REQUIREMENTS.get(path)
        if (
            path == "/agent/chat"
            and user.get("role") == "Incident Responder"
            and not (request.query_params.get("session") or "").strip()
        ):
            return RedirectResponse(url="/agent/playbooks", status_code=303)
        if (
            required_roles is not None
            and user.get("role") not in required_roles
            and not (
                path == "/agent/chat"
                and user.get("role") == "Incident Responder"
                and bool((request.query_params.get("session") or "").strip())
            )
        ):
            return JSONResponse(
                {"detail": "Insufficient permissions"},
                status_code=403,
            )
        return await call_next(request)
