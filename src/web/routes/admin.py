"""Admin-only invitation endpoint for Phase 1.5."""

from __future__ import annotations

import time
import hashlib
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from src.integrations.notifications import EmailChannel

from ..auth import (
    API_KEY_SCOPE,
    INVITE_TOKEN_TTL_SECONDS,
    TEAM_LEAD,
    VALID_ROLES,
    create_invite_token,
    _connect,
    require_role,
)


router = APIRouter()
team_lead_router = APIRouter()

TEAM_MEMBER_INVITABLE_ROLES = frozenset(
    {
        "SOC Analyst Tier 1-2",
        "Incident Responder",
        "Threat Hunter",
    }
)


class InviteUserRequest(BaseModel):
    email: str = Field(min_length=1)
    role: str = Field(min_length=1)


class CreateApiKeyRequest(BaseModel):
    expires_in_days: int = Field(default=90, ge=1, le=365)


def _audit_api_key(request: Request, actor: dict, action: str, key_id: int,
                   key_prefix: str, expires_at: int) -> None:
    store = getattr(request.app.state, "agent_store", None)
    if store is None or not hasattr(store, "add_audit_entry"):
        return
    try:
        store.add_audit_entry(
            session_id=None,
            action=f"api_key_{action}",
            action_type="api_key_management",
            actor=f"user:{actor['id']}",
            actor_role=actor["role"],
            target_user_id=None,
            resource_type="api_key",
            resource_id=str(key_id),
            after_state={
                "key_prefix": key_prefix,
                "key_id": key_id,
                "scope": API_KEY_SCOPE,
                "expires_at": expires_at,
            },
        )
    except Exception:
        # Key material is deliberately excluded from audit errors and metadata.
        return


@router.post("/users/{user_id}/api-keys", status_code=status.HTTP_201_CREATED)
def create_user_api_key(
    user_id: int,
    payload: CreateApiKeyRequest,
    request: Request,
    admin_user: dict = Depends(require_role("admin")),
) -> dict:
    with _connect() as connection:
        owner = connection.execute(
            "SELECT id, role, is_active FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if owner is None:
            raise HTTPException(status_code=404, detail="User not found")
        if owner["role"] not in {"Incident Responder", "admin"}:
            raise HTTPException(
                status_code=400,
                detail="API keys are available only to Incident Responders and admins",
            )
        if not owner["is_active"]:
            raise HTTPException(status_code=400, detail="User is inactive")

        prefix8 = secrets.token_hex(4)
        key_prefix = f"socpow_live_{prefix8}"
        secret = secrets.token_urlsafe(32)
        raw_key = f"{key_prefix}_{secret}"
        expires_at = int(time.time()) + payload.expires_in_days * 86400
        cursor = connection.execute(
            "INSERT INTO api_keys "
            "(user_id, key_prefix, key_hash, scope, expires_at, created_by) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                user_id,
                key_prefix,
                hashlib.sha256(raw_key.encode("utf-8")).hexdigest(),
                API_KEY_SCOPE,
                expires_at,
                int(admin_user["id"]),
            ),
        )
        key_id = int(cursor.lastrowid)
        connection.commit()
    _audit_api_key(request, admin_user, "created", key_id, key_prefix, expires_at)
    return {
        "id": key_id,
        "key": raw_key,
        "prefix": key_prefix,
        "scope": API_KEY_SCOPE,
        "expires_at": expires_at,
    }


@router.get("/users/{user_id}/api-keys")
def list_user_api_keys(
    user_id: int,
    _admin_user: dict = Depends(require_role("admin")),
) -> dict:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT id, key_prefix, scope, expires_at, revoked_at, last_used_at "
            "FROM api_keys WHERE user_id = ? ORDER BY id",
            (user_id,),
        ).fetchall()
    return {
        "api_keys": [
            {
                "id": int(row["id"]),
                "prefix": row["key_prefix"],
                "scope": row["scope"],
                "expires_at": row["expires_at"],
                "revoked_at": row["revoked_at"],
                "last_used_at": row["last_used_at"],
            }
            for row in rows
        ]
    }


@router.delete(
    "/users/{user_id}/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT
)
def revoke_user_api_key(
    user_id: int,
    key_id: int,
    request: Request,
    response: Response,
    admin_user: dict = Depends(require_role("admin")),
) -> Response:
    now = int(time.time())
    with _connect() as connection:
        row = connection.execute(
            "SELECT id, key_prefix, scope, expires_at, revoked_at FROM api_keys "
            "WHERE id = ? AND user_id = ?",
            (key_id, user_id),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="API key not found")
        if row["revoked_at"] is None:
            connection.execute(
                "UPDATE api_keys SET revoked_at = ? WHERE id = ?", (now, key_id)
            )
            connection.commit()
            _audit_api_key(
                request,
                admin_user,
                "revoked",
                int(row["id"]),
                row["key_prefix"],
                int(row["expires_at"]),
            )
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


def _send_invitation(
    payload: InviteUserRequest,
    request: Request,
    inviter: dict,
) -> dict:
    if payload.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail="Unsupported role")

    config = getattr(request.app.state, "config", {}) or {}
    email_cfg = dict(
        (config.get("notifications", {}) or {}).get("email", {}) or {}
    )
    if not email_cfg.get("enabled"):
        raise HTTPException(
            status_code=503,
            detail="Invitation email is not configured",
        )

    normalized_email = payload.email.strip().lower()
    try:
        token = create_invite_token(
            normalized_email, payload.role, inviter["id"]
        )
    except ValueError as exc:
        detail = str(exc)
        code = 400 if detail == "Invalid email" else 409
        raise HTTPException(status_code=code, detail=detail) from exc

    email_cfg["to_addrs"] = [normalized_email]
    invitation_actor = (
        "A Team Lead" if inviter.get("role") == TEAM_LEAD else "An administrator"
    )
    result = EmailChannel(email_cfg).send(
        "[CTI INVITE] Complete your account registration",
        f"{invitation_actor} invited you to the CTI system.\n\n"
        f"Invite token: {token}\n"
        "Accept it with POST /api/auth/accept-invite using the token, "
        "a username, and a password.\n"
        f"This invite expires in {INVITE_TOKEN_TTL_SECONDS // 3600} hours.",
    )
    if not result.get("success"):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Invitation email could not be sent",
        )

    return {
        "email": normalized_email,
        "role": payload.role,
        "expires_at": int(time.time()) + INVITE_TOKEN_TTL_SECONDS,
    }


@router.post("/users/invite", status_code=status.HTTP_202_ACCEPTED)
def invite_user(
    payload: InviteUserRequest,
    request: Request,
    admin_user: dict = Depends(require_role("admin")),
) -> dict:
    return _send_invitation(payload, request, admin_user)


@team_lead_router.post("/users/invite", status_code=status.HTTP_202_ACCEPTED)
def invite_team_member(
    payload: InviteUserRequest,
    request: Request,
    team_lead_user: dict = Depends(require_role(TEAM_LEAD)),
) -> dict:
    if payload.role not in TEAM_MEMBER_INVITABLE_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Team Leads may invite operator roles only",
        )
    return _send_invitation(payload, request, team_lead_user)
