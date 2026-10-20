"""Authentication primitives for Phase 1 Auth core."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext

from .security import (
    UNSAFE_METHODS,
    api_key_rate_limiter,
    csrf_cookie,
    session_cookie,
)


AUTH_DB_ENV = "AUTH_DB_PATH"
JWT_SECRET_ENV = "AUTH_JWT_SECRET"
ACCESS_TOKEN_TTL_SECONDS = 60 * 60
INVITE_TOKEN_TTL_SECONDS = 48 * 60 * 60
TEAM_LEAD = "Team Lead"
API_KEY_SCOPE = "POST /api/playbooks/alert_triage/run"
API_KEY_PREFIX = "socpow_live_"
_API_KEY_PATTERN = re.compile(
    r"^(?P<brand>socpow|cabta)_live_"
    r"(?P<identifier>[A-Za-z0-9]{8})_(?P<secret>[A-Za-z0-9_-]+)$"
)

VALID_ROLES = frozenset(
    {
        "SOC Analyst Tier 1-2",
        "Incident Responder",
        "Threat Hunter",
        "admin",
        TEAM_LEAD,
    }
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/auth/login",
    auto_error=False,
)


def _connect() -> sqlite3.Connection:
    db_path = Path(os.getenv(AUTH_DB_ENV, "src/db/auth.db"))
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row
    return connection


def get_user_ids_by_role(role: str) -> list[int]:
    """Return active user IDs for an application role."""
    if role not in VALID_ROLES:
        raise ValueError("Unsupported role")
    with _connect() as connection:
        rows = connection.execute(
            "SELECT id FROM users WHERE role = ? AND is_active = 1 ORDER BY id",
            (role,),
        ).fetchall()
    return [int(row["id"]) for row in rows]


def get_active_user(user_id: int) -> Optional[Dict[str, Any]]:
    """Return an active user's identity and role by database ID."""
    with _connect() as connection:
        row = connection.execute(
            "SELECT id, email, username, role, is_active "
            "FROM users WHERE id = ? AND is_active = 1",
            (user_id,),
        ).fetchone()
    return dict(row) if row is not None else None


def _jwt_secret() -> bytes:
    secret = os.getenv(JWT_SECRET_ENV)
    if not secret:
        raise RuntimeError(f"{JWT_SECRET_ENV} must be configured")
    return secret.encode("utf-8")


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _encode_jwt(payload: Dict[str, Any]) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    encoded_header = _b64encode(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = _b64encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = hmac.new(_jwt_secret(), signing_input, hashlib.sha256).digest()
    return f"{encoded_header}.{encoded_payload}.{_b64encode(signature)}"


def _decode_jwt(token: str) -> Dict[str, Any]:
    try:
        encoded_header, encoded_payload, encoded_signature = token.split(".")
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        expected_signature = hmac.new(
            _jwt_secret(), signing_input, hashlib.sha256
        ).digest()
        if not hmac.compare_digest(_b64decode(encoded_signature), expected_signature):
            raise ValueError("invalid signature")
        header = json.loads(_b64decode(encoded_header))
        payload = json.loads(_b64decode(encoded_payload))
        if header.get("alg") != "HS256" or int(payload["exp"]) <= int(time.time()):
            raise ValueError("expired or invalid token")
        return payload
    except (KeyError, ValueError, TypeError, json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError("invalid access token") from exc


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_context.verify(password, password_hash)
    except (ValueError, TypeError):
        return False


def authenticate_user(email: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticate by email or username without changing the public API."""
    identifier = email.strip()
    with _connect() as connection:
        row = connection.execute(
            "SELECT id, email, username, password_hash, role, is_active "
            "FROM users WHERE lower(email) = lower(?) "
            "OR lower(username) = lower(?)",
            (identifier, identifier),
        ).fetchone()

    if row is None or not row["is_active"]:
        return None
    if not verify_password(password, row["password_hash"]):
        return None
    return dict(row)


def create_access_token(user: Dict[str, Any]) -> str:
    now = int(time.time())
    expires_at = now + ACCESS_TOKEN_TTL_SECONDS
    jti = secrets.token_urlsafe(16)
    payload = {
        "sub": str(user["id"]),
        "role": user["role"],
        "iat": now,
        "exp": expires_at,
        "jti": jti,
    }
    token = _encode_jwt(payload)

    with _connect() as connection:
        connection.execute(
            "INSERT INTO auth_sessions "
            "(jti, user_id, expires_at) VALUES (?, ?, ?)",
            (jti, int(user["id"]), expires_at),
        )
        connection.commit()
    return token


def _session_is_active(connection: sqlite3.Connection, jti: str) -> bool:
    row = connection.execute(
        "SELECT expires_at, revoked_at FROM auth_sessions WHERE jti = ?",
        (jti,),
    ).fetchone()
    return bool(
        row
        and row["revoked_at"] is None
        and int(row["expires_at"]) > int(time.time())
    )


def get_access_token(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
) -> Optional[str]:
    """Return a bearer token first, falling back to the browser session cookie."""
    return token or session_cookie(request.cookies)


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _api_key_rate_identifier(value: str) -> str:
    match = _API_KEY_PATTERN.match(value)
    return match.group("identifier") if match else "invalid"


def _authenticate_api_key(key: str, request: Request) -> Dict[str, Any]:
    identifier = _api_key_rate_identifier(key)
    client_ip = _client_ip(request)
    if api_key_rate_limiter.is_limited(identifier, client_ip):
        retry_after = api_key_rate_limiter.retry_after(identifier, client_ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed API key attempts",
            headers={"Retry-After": str(retry_after)},
        )

    match = _API_KEY_PATTERN.fullmatch(key)
    row = None
    if match:
        key_prefix = f"{match.group('brand')}_live_{match.group('identifier')}"
        with _connect() as connection:
            row = connection.execute(
                "SELECT api_keys.id AS key_id, api_keys.user_id, "
                "api_keys.key_hash, api_keys.scope, api_keys.expires_at, "
                "api_keys.revoked_at, users.id, users.email, users.username, "
                "users.role, users.is_active FROM api_keys "
                "JOIN users ON users.id = api_keys.user_id "
                "WHERE api_keys.key_prefix = ?",
                (key_prefix,),
            ).fetchone()

    valid = bool(
        row
        and hmac.compare_digest(
            hashlib.sha256(key.encode("utf-8")).hexdigest(), row["key_hash"]
        )
        and row["revoked_at"] is None
        and int(row["expires_at"]) > int(time.time())
        and row["is_active"]
    )
    if not valid:
        api_key_rate_limiter.record_failure(identifier, client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if row["scope"] != API_KEY_SCOPE or (
        request.method.upper(), request.url.path
    ) != ("POST", "/api/playbooks/alert_triage/run"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="API key scope does not allow this request")

    with _connect() as connection:
        connection.execute(
            "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
            (int(time.time()), int(row["key_id"])),
        )
        connection.commit()
    request.state.api_key_id = int(row["key_id"])
    request.state.api_key_scope = str(row["scope"])
    return {
        "id": int(row["id"]),
        "email": row["email"],
        "username": row["username"],
        "role": row["role"],
        "is_active": row["is_active"],
    }


def _require_cookie_csrf(request: Request) -> None:
    if request.method.upper() not in UNSAFE_METHODS:
        return

    cookie_token = csrf_cookie(request.cookies)
    header_token = request.headers.get("X-CSRF-Token")
    if (
        not cookie_token
        or not header_token
        or not hmac.compare_digest(cookie_token, header_token)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF validation failed",
        )


def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    request: Request = None,
) -> Dict[str, Any]:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    bearer_is_key = bool(token and _API_KEY_PATTERN.fullmatch(token))
    header_api_key = request.headers.get("X-API-Key") if request else None
    if header_api_key is not None or bearer_is_key:
        if request is None:
            raise credentials_error
        if header_api_key is not None and token is not None and not hmac.compare_digest(
            header_api_key, token
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Conflicting authentication credentials",
            )
        api_key = header_api_key if header_api_key is not None else token
        if session_cookie(request.cookies):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Conflicting authentication credentials",
            )
        return _authenticate_api_key(api_key, request)

    cookie_token = session_cookie(request.cookies) if request else None
    using_session_cookie = not token and bool(cookie_token)
    token = token or cookie_token
    if using_session_cookie and request is not None:
        _require_cookie_csrf(request)
    if not token:
        raise credentials_error

    try:
        payload = _decode_jwt(token)
        user_id = int(payload["sub"])
        jti = str(payload["jti"])
    except (ValueError, KeyError, TypeError):
        raise credentials_error

    with _connect() as connection:
        if not _session_is_active(connection, jti):
            raise credentials_error
        row = connection.execute(
            "SELECT id, email, username, role, is_active FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()

    if row is None or not row["is_active"]:
        raise credentials_error
    return dict(row)


def _normalize_roles(roles: str | Sequence[str]) -> frozenset[str]:
    allowed_roles = frozenset((roles,) if isinstance(roles, str) else roles)
    if not allowed_roles or not allowed_roles.issubset(VALID_ROLES):
        raise ValueError("Unsupported role")
    return allowed_roles


def authorize_role(
    current_user: Dict[str, Any], roles: str | Sequence[str]
) -> None:
    if current_user.get("role") not in _normalize_roles(roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )


def require_role(roles: str | Sequence[str]):
    allowed_roles = _normalize_roles(roles)

    def dependency(current_user: Dict[str, Any] = Depends(get_current_user)):
        authorize_role(current_user, allowed_roles)
        return current_user

    return dependency


def create_invite_token(
    email: str,
    role: str,
    invited_by: int,
    ttl_seconds: int = INVITE_TOKEN_TTL_SECONDS,
) -> str:
    normalized_email = email.strip().lower()
    if role not in VALID_ROLES:
        raise ValueError(f"Unsupported role: {role}")
    if not normalized_email or "@" not in normalized_email:
        raise ValueError("Invalid email")

    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + ttl_seconds
    placeholder_hash = hash_password(secrets.token_urlsafe(32))

    with _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute(
            "SELECT id FROM users WHERE lower(email) = lower(?)",
            (normalized_email,),
        ).fetchone()
        if existing is not None:
            raise ValueError("Email is already registered or invited")

        connection.execute(
            "INSERT INTO users "
            "(email, password_hash, role, is_active) VALUES (?, ?, ?, 0)",
            (normalized_email, placeholder_hash, role),
        )
        connection.execute(
            "INSERT INTO invite_tokens "
            "(token, email, role, invited_by, expires_at) VALUES (?, ?, ?, ?, ?)",
            (token, normalized_email, role, int(invited_by), expires_at),
        )
        connection.commit()
    return token


def consume_invite_token(token: str, username: str, password: str) -> Dict[str, Any]:
    token = token.strip()
    username = username.strip()
    if not token:
        raise ValueError("Invalid invite token")
    if not username:
        raise ValueError("Username is required")

    password_hash = hash_password(password)
    now = int(time.time())

    with _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        invite = connection.execute(
            "SELECT token, email, role, expires_at, used_at "
            "FROM invite_tokens WHERE token = ?",
            (token,),
        ).fetchone()
        if invite is None:
            raise ValueError("Invalid invite token")
        if invite["used_at"] is not None:
            raise ValueError("Invite token already used")
        if int(invite["expires_at"]) <= now:
            raise ValueError("Invite token expired")

        user = connection.execute(
            "SELECT id, email, username, is_active FROM users "
            "WHERE lower(email) = lower(?)",
            (invite["email"],),
        ).fetchone()
        if user is None or user["is_active"]:
            raise ValueError("Invite has already been accepted")

        duplicate_username = connection.execute(
            "SELECT id FROM users WHERE lower(username) = lower(?) AND id != ?",
            (username, user["id"]),
        ).fetchone()
        if duplicate_username is not None:
            raise ValueError("Username is already taken")

        connection.execute(
            "UPDATE users SET username = ?, password_hash = ?, "
            "role = ?, is_active = 1 WHERE id = ?",
            (username, password_hash, invite["role"], user["id"]),
        )
        connection.execute(
            "UPDATE invite_tokens SET used_at = ? WHERE token = ?",
            (now, token),
        )
        activated = connection.execute(
            "SELECT id, email, username, role, is_active FROM users WHERE id = ?",
            (user["id"],),
        ).fetchone()
        connection.commit()
    return dict(activated)


def revoke_token(token: str) -> None:
    if token.startswith(API_KEY_PREFIX):
        raise ValueError("API keys cannot be revoked as access tokens")
    payload = _decode_jwt(token)
    with _connect() as connection:
        connection.execute(
            "UPDATE auth_sessions SET revoked_at = ? WHERE jti = ?",
            (int(time.time()), str(payload["jti"])),
        )
        connection.commit()


def public_user(user: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": user["id"],
        "email": user["email"],
        "username": user.get("username"),
        "role": user["role"],
    }
