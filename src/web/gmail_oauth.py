"""Gmail OAuth credential lifecycle service for Phase 4."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import requests
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import credentials as google_credentials
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow

from .token_crypto import TokenCipher


logger = logging.getLogger(__name__)
GMAIL_CLIENT_ID_ENV = "GMAIL_OAUTH_CLIENT_ID"
GMAIL_CLIENT_SECRET_ENV = "GMAIL_OAUTH_CLIENT_SECRET"
GMAIL_REDIRECT_URI = "http://localhost:3003/api/settings/gmail/callback"
GMAIL_REVOKE_URI = "https://oauth2.googleapis.com/revoke"
STATE_TTL_SECONDS = 20 * 60
ALLOWED_SCOPES = frozenset(
    {
        "https://www.googleapis.com/auth/gmail.send",
        "openid",
        "email",
        "profile",
    }
)
REQUESTED_SCOPES = frozenset(
    {
        "https://www.googleapis.com/auth/gmail.send",
        "openid",
        "email",
        "profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
    }
)


def _normalize_scopes(scopes: Iterable[str]) -> set[str]:
    aliases = {
        "https://www.googleapis.com/auth/userinfo.email": "email",
        "https://www.googleapis.com/auth/userinfo.profile": "profile",
    }
    return {aliases.get(str(scope), str(scope)) for scope in scopes}


class OAuthStateError(ValueError):
    pass


class GmailOAuthConfigurationError(RuntimeError):
    pass


class TokenRefreshError(RuntimeError):
    pass


@dataclass(frozen=True)
class OAuthState:
    raw_state: str
    state_hash: str
    user_id: int
    redirect_uri: str
    expires_at: int


@dataclass(frozen=True)
class DisconnectResult:
    remote_revoked: bool


def _migration_module():
    """Load numeric migration 007 without requiring a non-importable module name."""
    import importlib.util

    path = Path(__file__).resolve().parents[1] / "db" / "migrations" / "007_add_gmail_oauth.py"
    spec = importlib.util.spec_from_file_location("gmail_oauth_migration", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load Gmail OAuth migration")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GmailOAuthService:
    def __init__(self, db_path: str | os.PathLike[str] | None = None):
        self.db_path = Path(db_path or os.getenv("AUTH_DB_PATH", "src/db/auth.db"))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.requested_scopes = tuple(sorted(REQUESTED_SCOPES))
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.db_path))
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _ensure_schema(self) -> None:
        with self._connect() as connection:
            _migration_module().upgrade(connection)

    @staticmethod
    def _hash_state(raw_state: str) -> str:
        return hashlib.sha256(raw_state.encode("utf-8")).hexdigest()

    @staticmethod
    def _required_env(name: str) -> str:
        value = os.getenv(name)
        if not value:
            raise GmailOAuthConfigurationError(f"{name} must be configured")
        return value

    def _client_config(self) -> dict[str, Any]:
        return {
            "web": {
                "client_id": self._required_env(GMAIL_CLIENT_ID_ENV),
                "client_secret": self._required_env(GMAIL_CLIENT_SECRET_ENV),
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [GMAIL_REDIRECT_URI],
            }
        }

    def _new_flow(self, state: str | None = None) -> Flow:
        flow = Flow.from_client_config(
            self._client_config(), scopes=list(self.requested_scopes), state=state
        )
        flow.redirect_uri = GMAIL_REDIRECT_URI
        return flow

    def create_authorization_state(
        self, user_id: int, ttl_seconds: int = STATE_TTL_SECONDS
    ) -> OAuthState:
        raw_state = secrets.token_urlsafe(32)
        state_hash = self._hash_state(raw_state)
        expires_at = int(time.time()) + int(ttl_seconds)
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO gmail_oauth_states "
                "(state_hash, user_id, redirect_uri, expires_at) VALUES (?, ?, ?, ?)",
                (state_hash, int(user_id), GMAIL_REDIRECT_URI, expires_at),
            )
            connection.commit()
        return OAuthState(raw_state, state_hash, int(user_id), GMAIL_REDIRECT_URI, expires_at)

    def authorization_url(self, user_id: int) -> tuple[str, str]:
        state = self.create_authorization_state(user_id)
        flow = self._new_flow(state.raw_state)
        authorization_url, returned_state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
            state=state.raw_state,
        )
        # Google libraries normally return the supplied state; never trust a different value.
        if returned_state and returned_state != state.raw_state:
            raise RuntimeError("OAuth library returned an unexpected state")
        return authorization_url, state.raw_state

    @staticmethod
    def _identity_from_credentials(credentials: Any, client_id: str) -> tuple[str, str]:
        raw_claims = getattr(credentials, "id_token", None)
        if isinstance(raw_claims, dict):
            claims = raw_claims
        elif raw_claims:
            claims = id_token.verify_oauth2_token(
                raw_claims, GoogleRequest(), client_id
            )
        else:
            raise ValueError("Google did not return an OpenID identity token")
        subject = str(claims.get("sub", "")).strip()
        email = str(claims.get("email", "")).strip().lower()
        if not subject or not email or claims.get("email_verified") is False:
            raise ValueError("Google identity token is missing a verified email")
        return subject, email

    def exchange_code(self, raw_state: str, user_id: int, code: str) -> dict[str, Any]:
        state = self.consume_authorization_state(raw_state, user_id)
        if state.redirect_uri != GMAIL_REDIRECT_URI:
            raise OAuthStateError("OAuth redirect URI mismatch")
        flow = self._new_flow(raw_state)
        flow.fetch_token(code=code)
        credentials = flow.credentials
        subject, email = self._identity_from_credentials(
            credentials, self._required_env(GMAIL_CLIENT_ID_ENV)
        )
        scopes = _normalize_scopes(getattr(credentials, "scopes", None) or ())
        if not scopes:
            token_response = getattr(flow, "_token_response", {}) or {}
            raw_scopes = token_response.get("scope", "")
            scopes = _normalize_scopes(raw_scopes.split()) if raw_scopes else set(self.requested_scopes)
        self.save_token(user_id, subject, email, credentials.refresh_token, scopes)
        return self.get_status(user_id)

    def _state_row(self, raw_state: str, user_id: int | None = None) -> sqlite3.Row | None:
        state_hash = self._hash_state(raw_state)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT state_hash, user_id, redirect_uri, expires_at, used_at "
                "FROM gmail_oauth_states WHERE state_hash = ?",
                (state_hash,),
            ).fetchone()
        if row is not None and user_id is not None and int(row["user_id"]) != int(user_id):
            raise OAuthStateError("OAuth state user mismatch")
        return row

    def get_state_redirect_uri(self, raw_state: str, user_id: int) -> str:
        row = self._state_row(raw_state, user_id)
        if row is None:
            raise OAuthStateError("OAuth state not found")
        return str(row["redirect_uri"])

    def resolve_pending_state(self, raw_state: str) -> int:
        row = self._state_row(raw_state)
        if row is None:
            raise OAuthStateError("OAuth state not found")
        if row["used_at"] is not None:
            raise OAuthStateError("OAuth state already used")
        if int(row["expires_at"]) <= int(time.time()):
            raise OAuthStateError("OAuth state expired")
        return int(row["user_id"])

    def consume_authorization_state(self, raw_state: str, user_id: int) -> OAuthState:
        if not raw_state:
            raise OAuthStateError("OAuth state is required")
        state_hash = self._hash_state(raw_state)
        now = int(time.time())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT state_hash, user_id, redirect_uri, expires_at, used_at "
                "FROM gmail_oauth_states WHERE state_hash = ?",
                (state_hash,),
            ).fetchone()
            if row is None:
                raise OAuthStateError("OAuth state not found")
            if int(row["user_id"]) != int(user_id):
                raise OAuthStateError("OAuth state user mismatch")
            if row["used_at"] is not None:
                raise OAuthStateError("OAuth state already used")
            if int(row["expires_at"]) <= now:
                raise OAuthStateError("OAuth state expired")
            connection.execute(
                "UPDATE gmail_oauth_states SET used_at = ? WHERE state_hash = ?",
                (now, state_hash),
            )
            connection.commit()
        return OAuthState(raw_state, state_hash, int(row["user_id"]), str(row["redirect_uri"]), int(row["expires_at"]))

    def _cipher(self) -> TokenCipher:
        return TokenCipher.from_environment()

    def save_token(
        self,
        user_id: int,
        google_subject: str,
        google_email: str,
        refresh_token: str,
        granted_scopes: Iterable[str],
    ) -> None:
        scopes = sorted(_normalize_scopes(granted_scopes))
        if not ALLOWED_SCOPES.issuperset(scopes) or "https://www.googleapis.com/auth/gmail.send" not in scopes:
            raise ValueError("Google granted scopes are outside the Phase 4 allowlist")
        cipher = self._cipher()
        ciphertext = cipher.encrypt(refresh_token)
        now = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT google_subject FROM user_gmail_tokens WHERE user_id = ?",
                (int(user_id),),
            ).fetchone()
            if existing is not None and existing["google_subject"] != google_subject:
                raise ValueError("A different Gmail account is already linked")
            connection.execute(
                "INSERT INTO user_gmail_tokens "
                "(user_id, google_subject, google_email, refresh_token_ciphertext, "
                "token_key_version, granted_scopes, created_at, updated_at, revoked_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL) "
                "ON CONFLICT(user_id) DO UPDATE SET google_subject=excluded.google_subject, "
                "google_email=excluded.google_email, refresh_token_ciphertext=excluded.refresh_token_ciphertext, "
                "token_key_version=excluded.token_key_version, granted_scopes=excluded.granted_scopes, "
                "updated_at=excluded.updated_at, revoked_at=NULL",
                (int(user_id), google_subject, google_email, ciphertext, cipher.key_version, json.dumps(scopes), now, now),
            )
            connection.execute(
                "INSERT INTO gmail_oauth_audit (user_id, event, google_subject, google_email) VALUES (?, 'connect', ?, ?)",
                (int(user_id), google_subject, google_email),
            )
            connection.commit()

    def get_record(self, user_id: int) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM user_gmail_tokens WHERE user_id = ?", (int(user_id),)
            ).fetchone()
        return dict(row) if row is not None else None

    def get_status(self, user_id: int) -> dict[str, Any]:
        row = self.get_record(user_id)
        if row is None:
            return {
                "linked": False,
                "google_email": None,
                "granted_scopes": [],
                "linked_at": None,
                "last_refresh_at": None,
                "revoked": False,
            }
        try:
            scopes = json.loads(row["granted_scopes"])
        except (TypeError, json.JSONDecodeError):
            scopes = []
        return {
            "linked": True,
            "google_email": row["google_email"],
            "granted_scopes": [scope for scope in scopes if scope in ALLOWED_SCOPES],
            "linked_at": row["created_at"],
            "last_refresh_at": row["last_refresh_at"],
            "revoked": row["revoked_at"] is not None,
        }

    def _decrypt_record(self, row: dict[str, Any]) -> str:
        return self._cipher().decrypt(str(row["refresh_token_ciphertext"]))

    def refresh_access_token(self, user_id: int):
        row = self.get_record(user_id)
        if row is None or row["revoked_at"] is not None:
            raise TokenRefreshError("Gmail token is not active")
        try:
            refresh_token = self._decrypt_record(row)
        except Exception as exc:
            self._mark_revoked(user_id, row)
            raise TokenRefreshError("Gmail token could not be decrypted; token marked revoked") from exc
        credentials = google_credentials.Credentials(
            token=None,
            refresh_token=refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=self._required_env(GMAIL_CLIENT_ID_ENV),
            client_secret=self._required_env(GMAIL_CLIENT_SECRET_ENV),
            scopes=json.loads(row["granted_scopes"]),
        )
        error: Exception | None = None
        for _attempt in range(2):
            try:
                credentials.refresh(GoogleRequest())
                now = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
                with self._connect() as connection:
                    connection.execute(
                        "UPDATE user_gmail_tokens SET updated_at = ?, last_refresh_at = ? WHERE user_id = ?",
                        (now, now, int(user_id)),
                    )
                    connection.commit()
                return credentials
            except Exception as exc:  # Google can raise several transport/auth exceptions.
                error = exc
        self._mark_revoked(user_id, row)
        raise TokenRefreshError("Gmail token refresh failed; token marked revoked") from error

    def _mark_revoked(self, user_id: int, row: dict[str, Any]) -> None:
        now = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        with self._connect() as connection:
            connection.execute(
                "UPDATE user_gmail_tokens SET revoked_at = ?, updated_at = ? WHERE user_id = ?",
                (now, now, int(user_id)),
            )
            connection.execute(
                "INSERT INTO gmail_oauth_audit (user_id, event, google_subject, google_email) VALUES (?, 'refresh_failed', ?, ?)",
                (int(user_id), row.get("google_subject"), row.get("google_email")),
            )
            connection.commit()

    def _revoke_remote(self, refresh_token: str) -> bool:
        try:
            response = requests.post(GMAIL_REVOKE_URI, params={"token": refresh_token}, timeout=10)
            return 200 <= response.status_code < 300
        except requests.RequestException:
            return False

    def disconnect(self, user_id: int) -> DisconnectResult:
        row = self.get_record(user_id)
        if row is None:
            return DisconnectResult(remote_revoked=False)
        try:
            remote_revoked = self._revoke_remote(self._decrypt_record(row))
        except Exception:
            remote_revoked = False
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO gmail_oauth_audit (user_id, event, google_subject, google_email) VALUES (?, 'disconnect', ?, ?)",
                (int(user_id), row["google_subject"], row["google_email"]),
            )
            connection.execute("DELETE FROM user_gmail_tokens WHERE user_id = ?", (int(user_id),))
            connection.commit()
        return DisconnectResult(remote_revoked=remote_revoked)

    def aggregate_summary(self) -> dict[str, Any]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT u.role, COUNT(CASE WHEN t.revoked_at IS NULL THEN t.id END) AS linked_count "
                "FROM users u LEFT JOIN user_gmail_tokens t ON t.user_id = u.id "
                "GROUP BY u.role ORDER BY u.role"
            ).fetchall()
        by_role = {str(row["role"]): int(row["linked_count"]) for row in rows}
        return {"linked_users": sum(by_role.values()), "by_role": by_role}


# Keep the public module import surface independent of numeric Python module names.
