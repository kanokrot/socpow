"""Owner-only Gmail OAuth settings endpoints."""

from __future__ import annotations

import logging
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse

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
) -> RedirectResponse:
    """Complete OAuth using the single-use state as the callback's user binding."""
    try:
        if not state:
            logger.warning("Gmail OAuth callback failed: state_missing")
            return _account_redirect("error", "state_missing")
        service = _service()
        user_id = service.resolve_pending_state(state)
        if error or not code:
            service.consume_authorization_state(state, user_id)
            reason = "consent_denied" if error else "invalid_code"
            logger.warning("Gmail OAuth callback failed: %s", reason)
            return _account_redirect("error", reason)
        service.exchange_code(state, user_id, code)
        return _account_redirect("success")
    except OAuthStateError:
        logger.warning("Gmail OAuth callback failed: state_invalid")
        return _account_redirect("error", "state_invalid")
    except GmailOAuthConfigurationError:
        logger.warning("Gmail OAuth callback failed: configuration")
        return _account_redirect("error", "configuration")
    except Exception as exc:
        logger.warning("Gmail OAuth callback failed: %s", type(exc).__name__)
        return _account_redirect("error", "exchange_failed")


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
