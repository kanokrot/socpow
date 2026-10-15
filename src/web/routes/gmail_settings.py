"""Owner-only Gmail OAuth settings endpoints."""

from __future__ import annotations

import html
import logging
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from ..auth import get_current_user, require_role
from ..gmail_oauth import (
    GmailOAuthConfigurationError,
    GmailOAuthService,
    OAuthStateError,
)
from ..visibility import serialize_gmail_status, serialize_gmail_summary


router = APIRouter()
admin_router = APIRouter()
ACCOUNT_PATH = "/account"
CALLBACK_ERROR_REASONS = frozenset(
    {
        "state_missing",
        "state_invalid",
        "consent_denied",
        "invalid_code",
        "configuration",
        "exchange_failed",
    }
)
logger = logging.getLogger(__name__)


def _service() -> GmailOAuthService:
    return GmailOAuthService()


def _account_redirect(result: str, reason: str | None = None) -> RedirectResponse:
    query = {"gmail": result}
    if reason:
        query["reason"] = reason
    return RedirectResponse(
        f"{ACCOUNT_PATH}?{urlencode(query)}", status_code=status.HTTP_302_FOUND
    )


def _callback_result_page(result: str, reason: str | None = None) -> HTMLResponse:
    if result == "success":
        target = f"{ACCOUNT_PATH}?gmail=success"
    else:
        safe_reason = reason if reason in CALLBACK_ERROR_REASONS else "exchange_failed"
        target = f"{ACCOUNT_PATH}?gmail=error&reason={safe_reason}"

    attribute_target = html.escape(target, quote=True)
    return HTMLResponse(
        content=(
            "<!doctype html><html><head><meta charset=\"utf-8\">"
            f'<meta http-equiv="refresh" content="0;url={attribute_target}">'
            "<title>Gmail connection</title></head><body>"
            f"<noscript><p><a href=\"{attribute_target}\">Continue to account</a></p></noscript>"
            f"<script>window.location.replace('{target}');</script>"
            "</body></html>"
        ),
        status_code=status.HTTP_200_OK,
        headers={"Cache-Control": "no-store"},
    )


@router.get("/connect")
def connect_gmail(current_user: dict = Depends(get_current_user)) -> RedirectResponse:
    try:
        authorization_url, _raw_state = _service().authorization_url(int(current_user["id"]))
    except GmailOAuthConfigurationError:
        logger.warning("Gmail OAuth start failed: configuration")
        return _account_redirect("error", "configuration")
    except Exception as exc:
        logger.warning("Gmail OAuth start failed: %s", type(exc).__name__)
        return _account_redirect("error", "start_failed")
    return RedirectResponse(authorization_url, status_code=status.HTTP_302_FOUND)


@router.get("/callback")
def gmail_callback(
    state: str | None = Query(default=None),
    code: str | None = Query(default=None),
    error: str | None = Query(default=None),
) -> HTMLResponse:
    """Complete OAuth using the single-use state as the callback's user binding."""
    try:
        if not state:
            logger.warning("Gmail OAuth callback failed: state_missing")
            return _callback_result_page("error", "state_missing")
        service = _service()
        user_id = service.resolve_pending_state(state)
        if error or not code:
            service.consume_authorization_state(state, user_id)
            reason = "consent_denied" if error else "invalid_code"
            logger.warning("Gmail OAuth callback failed: %s", reason)
            return _callback_result_page("error", reason)
        service.exchange_code(state, user_id, code)
        return _callback_result_page("success")
    except OAuthStateError:
        logger.warning("Gmail OAuth callback failed: state_invalid")
        return _callback_result_page("error", "state_invalid")
    except GmailOAuthConfigurationError:
        logger.warning("Gmail OAuth callback failed: configuration")
        return _callback_result_page("error", "configuration")
    except Exception as exc:
        logger.warning("Gmail OAuth callback failed: %s", type(exc).__name__)
        return _callback_result_page("error", "exchange_failed")


@router.get("/status")
def gmail_status(current_user: dict = Depends(get_current_user)) -> dict:
    return serialize_gmail_status(
        _service().get_status(int(current_user["id"])), current_user["role"]
    )


@router.delete("")
def disconnect_gmail(current_user: dict = Depends(get_current_user)) -> dict:
    result = _service().disconnect(int(current_user["id"]))
    return {"status": "disconnected", "remote_revoked": result.remote_revoked}


@admin_router.get("/gmail/summary")
def gmail_summary(admin_user: dict = Depends(require_role("admin"))) -> dict:
    return serialize_gmail_summary(_service().aggregate_summary(), admin_user["role"])
