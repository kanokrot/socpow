"""Manual end-to-end smoke test for the browser authentication flow.

By default this script starts a real uvicorn instance with isolated temporary
databases and HOME/USERPROFILE paths.  It uses a persistent httpx.Client so
the requests exercise cookie behavior like a browser.  An already-running
instance can be used with --base-url, but then --invite-token, --email, and
--auth-db are required so the created user can be verified and cleaned up.

The admin invite endpoint requires a configured SMTP server and does not return
the generated token.  In self-start mode the script therefore provisions the
invite with the same production create_invite_token helper against its
throwaway auth database; the HTTP accept-invite, login, cookie, CSRF, page,
logout, and WebSocket portions remain real network requests.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import os
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

import httpx


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SESSION_COOKIE = "socpow_session"
CSRF_COOKIE = "socpow_csrf"


class SmokeFailure(RuntimeError):
    pass


def _load_migration(filename: str):
    path = ROOT / "src" / "db" / "migrations" / filename
    spec = importlib.util.spec_from_file_location(
        f"auth_smoke_{path.stem}", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load migration {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _cookie_value(client: httpx.Client, name: str) -> str:
    for cookie in client.cookies.jar:
        if cookie.name == name:
            return cookie.value
    raise SmokeFailure(f"Persistent client has no {name} cookie")


def _set_cookie_morsels(response: httpx.Response) -> dict[str, Any]:
    cookies: dict[str, Any] = {}
    for header in response.headers.get_list("set-cookie"):
        parsed = SimpleCookie()
        parsed.load(header)
        for name, morsel in parsed.items():
            cookies[name] = morsel
    return cookies


def _assert_no_token_body(response: httpx.Response) -> None:
    body = response.text.lower()
    if "access_token" in body or "token_type" in body:
        raise SmokeFailure("response body exposed an access token field")


def _expected_secure(value: str | None) -> bool:
    return str(value or "0").strip().lower() in {
        "1", "true", "yes", "on"
    }


def _assert_auth_cookies(
    response: httpx.Response, *, expected_secure: bool
) -> None:
    cookies = _set_cookie_morsels(response)
    for name in (SESSION_COOKIE, CSRF_COOKIE):
        if name not in cookies:
            raise SmokeFailure(f"login did not set {name}")

    session = cookies[SESSION_COOKIE]
    csrf = cookies[CSRF_COOKIE]
    if not bool(session["httponly"]):
        raise SmokeFailure("socpow_session is not HttpOnly")
    if bool(csrf["httponly"]):
        raise SmokeFailure("socpow_csrf must remain readable by browser JavaScript")
    if session["samesite"].lower() != "strict":
        raise SmokeFailure("socpow_session is not SameSite=Strict")
    if csrf["samesite"].lower() != "strict":
        raise SmokeFailure("socpow_csrf is not SameSite=Strict")
    for name, morsel in ((SESSION_COOKIE, session), (CSRF_COOKIE, csrf)):
        if bool(morsel["secure"]) != expected_secure:
            raise SmokeFailure(
                f"{name} Secure flag does not match expected AUTH_COOKIE_SECURE"
            )


def _assert_cleared_cookies(response: httpx.Response) -> None:
    cookies = _set_cookie_morsels(response)
    for name in (SESSION_COOKIE, CSRF_COOKIE):
        if name not in cookies or cookies[name]["max-age"] != "0":
            raise SmokeFailure(f"logout did not clear {name} with Max-Age=0")


def _seed_isolated_auth_db(
    db_path: Path,
    *,
    email: str,
    username: str,
    password: str,
) -> str:
    _load_migration("001_create_users.py").migrate(str(db_path))
    _load_migration("002_add_username_and_admin_role.py").migrate(str(db_path))
    _load_migration("004_add_team_lead_role.py").migrate(str(db_path))

    from src.web.auth import create_invite_token, hash_password

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO users (email, username, password_hash, role, is_active) "
            "VALUES (?, ?, ?, ?, 1)",
            (
                "auth-smoke-admin@example.test",
                "auth-smoke-admin",
                hash_password("AuthSmokeAdmin!2026"),
                "admin",
            ),
        )
        connection.commit()
        admin_id = int(
            connection.execute(
                "SELECT id FROM users WHERE username = ?",
                ("auth-smoke-admin",),
            ).fetchone()[0]
        )

    return create_invite_token(email, "SOC Analyst Tier 1-2", admin_id)


class RunningServer:
    def __init__(self, env: dict[str, str], port: int, temp_root: Path):
        self.env = env
        self.port = port
        self.temp_root = temp_root
        self.process: subprocess.Popen[str] | None = None
        self.log_handle = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        log_path = self.temp_root / "uvicorn.log"
        self.log_handle = log_path.open("w", encoding="utf-8")
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "src.web.app:create_app",
                "--factory",
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
            ],
            cwd=ROOT,
            env=self.env,
            stdout=self.log_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise SmokeFailure(
                    "server exited during startup; log:\n"
                    + log_path.read_text(encoding="utf-8", errors="replace")
                )
            try:
                response = httpx.get(
                    f"{self.base_url}/api/docs",
                    timeout=1.0,
                    follow_redirects=False,
                )
                if response.status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.25)
        raise SmokeFailure(
            "server did not become ready; log:\n"
            + log_path.read_text(encoding="utf-8", errors="replace")
        )

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.log_handle is not None:
            self.log_handle.close()


def _cleanup_created_user(db_path: Path, email: str) -> None:
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            "SELECT id FROM users WHERE lower(email) = lower(?)",
            (email,),
        ).fetchone()
        if row is None:
            return
        user_id = int(row[0])
        connection.execute("DELETE FROM auth_sessions WHERE user_id = ?", (user_id,))
        connection.execute("DELETE FROM invite_tokens WHERE email = ?", (email,))
        connection.execute("DELETE FROM users WHERE id = ?", (user_id,))
        connection.commit()


async def _check_cookie_websocket(base_url: str, cookie_value: str) -> None:
    import inspect
    import websockets

    parsed = urlsplit(base_url)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    ws_url = f"{scheme}://{parsed.netloc}/ws/analysis/auth-smoke-no-message"
    headers_kw = (
        "additional_headers"
        if "additional_headers" in inspect.signature(websockets.connect).parameters
        else "extra_headers"
    )
    async with websockets.connect(
        ws_url,
        **{headers_kw: {"Cookie": f"{SESSION_COOKIE}={cookie_value}"}},
        open_timeout=10,
        close_timeout=5,
        ping_interval=None,
    ) as socket:
        del socket


def _step(number: int, description: str, callback: Callable[[], None]) -> None:
    try:
        callback()
    except Exception as exc:
        print(f"FAIL {number}: {description} -- {exc}", flush=True)
        raise SmokeFailure(f"step {number} failed: {description}") from exc
    print(f"PASS {number}: {description}", flush=True)


def run(args: argparse.Namespace) -> int:
    temp_root: Path | None = None
    server: RunningServer | None = None
    created_user_email = args.email
    auth_db: Path | None = Path(args.auth_db).resolve() if args.auth_db else None
    invite_token = args.invite_token
    target_email = args.email
    target_username = args.username or f"smoke_{secrets.token_hex(5)}"
    target_password = args.password or f"Smoke!{secrets.token_urlsafe(12)}"

    if args.base_url:
        if not invite_token or not target_email or not auth_db:
            raise SmokeFailure(
                "--base-url requires --invite-token, --email, and --auth-db "
                "so the created user can be cleaned up safely"
            )
        base_url = args.base_url.rstrip("/")
        expected_secure = _expected_secure(
            args.expect_secure if args.expect_secure is not None else os.getenv("AUTH_COOKIE_SECURE")
        )
    else:
        temp_root = Path(tempfile.mkdtemp(prefix="socpow-auth-smoke-"))
        home = temp_root / "home"
        db_path = temp_root / "auth.db"
        config_path = temp_root / "config.yaml"
        config_path.write_text(
            "analysis:\n  enable_rag: false\n"
            "notifications:\n  enabled: false\n",
            encoding="utf-8",
        )
        runtime_env = os.environ.copy()
        runtime_env.update(
            {
                "AUTH_DB_PATH": str(db_path),
                "AUTH_JWT_SECRET": secrets.token_urlsafe(32),
                "AUTH_COOKIE_SECURE": "0",
                "AUTH_LOGIN_MAX_ATTEMPTS": "5",
                "AUTH_LOGIN_WINDOW_SECONDS": "900",
                "BTA_CONFIG": str(config_path),
                "TICKETING_DB_PATH": str(temp_root / "tickets.db"),
                "HOME": str(home),
                "USERPROFILE": str(home),
                "PYTHONUNBUFFERED": "1",
            }
        )
        home.mkdir(parents=True, exist_ok=True)
        target_email = f"auth-smoke-{secrets.token_hex(6)}@example.test"
        target_username = f"auth_smoke_{secrets.token_hex(5)}"
        target_password = f"Smoke!{secrets.token_urlsafe(12)}"
        os.environ.update(runtime_env)
        invite_token = _seed_isolated_auth_db(
            db_path,
            email=target_email,
            username=target_username,
            password=target_password,
        )
        auth_db = db_path
        expected_secure = False
        port = args.port or _free_port()
        server = RunningServer(runtime_env, port, temp_root)
        server.start()
        base_url = server.base_url
        print("SETUP: started isolated real server at", base_url, flush=True)

    created_user_email = target_email

    client = httpx.Client(
        base_url=base_url,
        timeout=15.0,
        follow_redirects=False,
    )
    ws_client = httpx.Client(
        base_url=base_url,
        timeout=15.0,
        follow_redirects=False,
    )
    try:
        _step(
            1,
            "unauthenticated GET / redirects to /login?next=%2F",
            lambda: _check_root_redirect(client),
        )
        _step(
            2,
            "GET /login returns the login form",
            lambda: _check_login_page(client),
        )
        rate_identifier = f"auth-smoke-rate-{secrets.token_hex(5)}"
        _step(
            3,
            "six wrong logins produce 401s then 429 with Retry-After and no token",
            lambda: _check_rate_limit(client, rate_identifier),
        )
        _step(
            4,
            "accept-invite activates the fresh throwaway user",
            lambda: _check_accept_invite(
                client, invite_token, target_username, target_password
            ),
        )
        _step(
            5,
            "correct login is cookie-only with strict session/CSRF cookies",
            lambda: _check_login(
                client, target_username, target_password, expected_secure
            ),
        )
        _step(
            6,
            "authenticated GET /, /dashboard, and /settings return 200",
            lambda: _check_authenticated_pages(client),
        )
        _step(
            7,
            "state-changing request requires CSRF and succeeds with the cookie token",
            lambda: _check_csrf_logout_pair(client),
        )

        # Step 7 intentionally logs the main client out. Re-authenticate it for
        # the final logout check; the separate WS client retains its pre-logout
        # cookie so the cookie-upgrade path can be tested independently.
        response = client.post(
            "/api/auth/login",
            json={"username": target_username, "password": target_password},
        )
        if response.status_code != 200:
            raise SmokeFailure("re-authentication after CSRF check failed")
        ws_login = ws_client.post(
            "/api/auth/login",
            json={"username": target_username, "password": target_password},
        )
        if ws_login.status_code != 200:
            raise SmokeFailure("WebSocket client login failed")
        ws_cookie = _cookie_value(ws_client, SESSION_COOKIE)

        _step(
            8,
            "logout with CSRF clears both cookies with Max-Age=0",
            lambda: _check_logout(client),
        )
        _step(
            9,
            "GET /dashboard after logout redirects to /login",
            lambda: _check_logged_out_dashboard(client),
        )
        _step(
            10,
            "cookie-authenticated WebSocket upgrade succeeds without auth message",
            lambda: asyncio.run(_check_cookie_websocket(base_url, ws_cookie)),
        )
        print(
            "NOTE: browser-only behavior such as theme clicks, visual/CSS rendering, "
            "and browser tracking-prevention UI still requires a real browser.",
            flush=True,
        )
        return 0
    finally:
        client.close()
        ws_client.close()
        if auth_db is not None and created_user_email:
            try:
                _cleanup_created_user(auth_db, created_user_email)
            except Exception as exc:
                print(f"CLEANUP WARNING: {exc}", file=sys.stderr, flush=True)
        if server is not None:
            server.stop()
        if temp_root is not None:
            shutil.rmtree(temp_root, ignore_errors=True)


def _check_root_redirect(client: httpx.Client) -> None:
    response = client.get("/")
    if response.status_code != 303 or response.headers.get("location") != "/login?next=%2F":
        raise SmokeFailure(
            f"expected 303 /login?next=%2F, got {response.status_code} "
            f"{response.headers.get('location')}"
        )


def _check_login_page(client: httpx.Client) -> None:
    response = client.get("/login")
    if response.status_code != 200 or 'data-auth-form="login"' not in response.text:
        raise SmokeFailure("login page or login form missing")


def _check_rate_limit(client: httpx.Client, identifier: str) -> None:
    statuses = []
    for _ in range(6):
        response = client.post(
            "/api/auth/login",
            json={"username": identifier, "password": "wrong-password"},
        )
        _assert_no_token_body(response)
        statuses.append(response.status_code)
        if response.status_code not in {401, 429}:
            raise SmokeFailure(f"unexpected failed-login status {response.status_code}")
        if response.status_code == 401 and response.json().get("detail") != "Invalid email or password":
            raise SmokeFailure("wrong-login response did not use the generic message")
    if statuses[:5] != [401] * 5 or statuses[5] != 429:
        raise SmokeFailure(f"unexpected rate-limit sequence: {statuses}")
    if not response.headers.get("Retry-After"):
        raise SmokeFailure("429 response did not include Retry-After")


def _check_accept_invite(
    client: httpx.Client, token: str, username: str, password: str
) -> None:
    response = client.post(
        "/api/auth/accept-invite",
        json={"token": token, "username": username, "password": password},
    )
    if response.status_code != 200:
        raise SmokeFailure(f"accept-invite returned {response.status_code}: {response.text}")
    if response.json().get("user", {}).get("username") != username:
        raise SmokeFailure("accept-invite returned the wrong user")


def _check_login(
    client: httpx.Client, username: str, password: str, expected_secure: bool
) -> None:
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )
    if response.status_code != 200:
        raise SmokeFailure(f"correct login returned {response.status_code}: {response.text}")
    _assert_no_token_body(response)
    if response.json().get("authenticated") is not True:
        raise SmokeFailure("login response did not confirm authentication")
    _assert_auth_cookies(response, expected_secure=expected_secure)


def _check_authenticated_pages(client: httpx.Client) -> None:
    for path in ("/", "/dashboard", "/settings"):
        response = client.get(path)
        if response.status_code != 200:
            raise SmokeFailure(f"{path} returned {response.status_code}")


def _check_csrf_logout_pair(client: httpx.Client) -> None:
    missing = client.post("/api/auth/logout")
    if missing.status_code != 403 or "CSRF validation failed" not in missing.text:
        raise SmokeFailure(
            f"missing-CSRF logout expected 403, got {missing.status_code}: {missing.text}"
        )
    csrf = _cookie_value(client, CSRF_COOKIE)
    accepted = client.post(
        "/api/auth/logout",
        headers={"X-CSRF-Token": csrf},
    )
    if accepted.status_code != 204:
        raise SmokeFailure(f"CSRF-protected logout returned {accepted.status_code}")


def _check_logout(client: httpx.Client) -> None:
    csrf = _cookie_value(client, CSRF_COOKIE)
    response = client.post(
        "/api/auth/logout",
        headers={"X-CSRF-Token": csrf},
    )
    if response.status_code != 204:
        raise SmokeFailure(f"logout returned {response.status_code}: {response.text}")
    _assert_cleared_cookies(response)


def _check_logged_out_dashboard(client: httpx.Client) -> None:
    response = client.get("/dashboard")
    if response.status_code != 303 or not response.headers.get("location", "").startswith("/login?next="):
        raise SmokeFailure(
            f"post-logout dashboard expected login redirect, got "
            f"{response.status_code} {response.headers.get('location')}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", help="Use an already-running instance")
    parser.add_argument("--port", type=int, default=0, help="Port for the self-started server")
    parser.add_argument("--invite-token", help="Invite token for --base-url mode")
    parser.add_argument("--email", help="Invited email for --base-url mode")
    parser.add_argument("--username", help="Username to activate or use")
    parser.add_argument("--password", help="Password to activate or use")
    parser.add_argument("--auth-db", help="Local auth DB for safe cleanup in --base-url mode")
    parser.add_argument(
        "--expect-secure",
        choices=("0", "1"),
        help="Expected Secure cookie flag; defaults to AUTH_COOKIE_SECURE",
    )
    args = parser.parse_args()
    try:
        return run(args)
    except SmokeFailure as exc:
        print(f"SMOKE TEST FAILED: {exc}", file=sys.stderr, flush=True)
        return 1
    except Exception as exc:
        print(f"SMOKE TEST FAILED UNEXPECTEDLY: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
