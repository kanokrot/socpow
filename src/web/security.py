"""Small, process-local security controls for the web authentication layer."""

from __future__ import annotations

import os
import time
from collections import deque
from threading import Lock
from typing import Callable
from urllib.parse import urlsplit


LOGIN_RATE_LIMIT_MAX_ATTEMPTS = int(
    os.getenv("AUTH_LOGIN_MAX_ATTEMPTS", "5")
)
LOGIN_RATE_LIMIT_WINDOW_SECONDS = int(
    os.getenv("AUTH_LOGIN_WINDOW_SECONDS", str(15 * 60))
)
API_KEY_RATE_LIMIT_MAX_ATTEMPTS = int(
    os.getenv("AUTH_API_KEY_MAX_ATTEMPTS", "10")
)
API_KEY_RATE_LIMIT_WINDOW_SECONDS = int(
    os.getenv("AUTH_API_KEY_WINDOW_SECONDS", str(15 * 60))
)


class LoginRateLimiter:
    """Limit failed logins for a normalized identifier and client IP.

    State is intentionally process-local for the current single-process
    deployment.  A shared store such as Redis is required before running
    multiple workers or expecting limits to survive process restarts.
    """

    def __init__(
        self,
        max_attempts: int = LOGIN_RATE_LIMIT_MAX_ATTEMPTS,
        window_seconds: int = LOGIN_RATE_LIMIT_WINDOW_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        if window_seconds < 1:
            raise ValueError("window_seconds must be positive")
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._clock = clock
        self._attempts: dict[tuple[str, str], deque[float]] = {}
        self._lock = Lock()

    @staticmethod
    def _key(identifier: str, client_ip: str) -> tuple[str, str]:
        return identifier.strip().casefold(), client_ip.strip()

    def _prune(self, key: tuple[str, str], now: float) -> deque[float]:
        attempts = self._attempts.setdefault(key, deque())
        cutoff = now - self.window_seconds
        while attempts and attempts[0] <= cutoff:
            attempts.popleft()
        return attempts

    def is_limited(self, identifier: str, client_ip: str) -> bool:
        """Return whether another attempt is currently blocked."""
        now = self._clock()
        key = self._key(identifier, client_ip)
        with self._lock:
            attempts = self._prune(key, now)
            if not attempts:
                self._attempts.pop(key, None)
                return False
            return len(attempts) >= self.max_attempts

    def record_failure(self, identifier: str, client_ip: str) -> None:
        """Record one failed login attempt."""
        now = self._clock()
        key = self._key(identifier, client_ip)
        with self._lock:
            self._prune(key, now).append(now)

    def clear(self, identifier: str, client_ip: str) -> None:
        """Forget failures after a successful login."""
        with self._lock:
            self._attempts.pop(self._key(identifier, client_ip), None)

    def retry_after(self, identifier: str, client_ip: str) -> int:
        """Return a conservative Retry-After value in seconds."""
        now = self._clock()
        key = self._key(identifier, client_ip)
        with self._lock:
            attempts = self._prune(key, now)
            if not attempts:
                self._attempts.pop(key, None)
                return 0
            return max(1, int(attempts[0] + self.window_seconds - now + 0.999))


login_rate_limiter = LoginRateLimiter()
api_key_rate_limiter = LoginRateLimiter(
    max_attempts=API_KEY_RATE_LIMIT_MAX_ATTEMPTS,
    window_seconds=API_KEY_RATE_LIMIT_WINDOW_SECONDS,
)


SESSION_COOKIE_NAME = "socpow_session"
CSRF_COOKIE_NAME = "socpow_csrf"
COOKIE_SAMESITE = "strict"
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _cookie_by_explicit_alias(cookies, name: str) -> str | None:
    """Read the current cookie name, allowing only its explicitly named alias."""
    legacy_names = {
        SESSION_COOKIE_NAME: ("cabta_session",),
        CSRF_COOKIE_NAME: ("cabta_csrf",),
    }.get(name, ())
    for cookie_name in (name, *legacy_names):
        value = cookies.get(cookie_name)
        if value:
            return value
    return None


def session_cookie(cookies) -> str | None:
    return _cookie_by_explicit_alias(cookies, SESSION_COOKIE_NAME)


def csrf_cookie(cookies) -> str | None:
    return _cookie_by_explicit_alias(cookies, CSRF_COOKIE_NAME)


def cookie_secure() -> bool:
    """Return whether auth cookies should include the Secure attribute."""
    return os.getenv("AUTH_COOKIE_SECURE", "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def safe_relative_path(value: str | None, default: str = "/") -> str:
    """Accept only same-origin relative paths for post-login redirects."""
    if not isinstance(value, str):
        return default
    candidate = value.strip()
    if (
        not candidate.startswith("/")
        or candidate.startswith("//")
        or "\\" in candidate
        or any(ord(char) <= 0x1F or ord(char) == 0x7F for char in candidate)
    ):
        return default
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return default
    if parsed.scheme or parsed.netloc:
        return default
    return candidate
