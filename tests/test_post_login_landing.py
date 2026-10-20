from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import src.web.app as app_module
from src.web.auth import VALID_ROLES
from src.web.page_auth import PAGE_ROLE_REQUIREMENTS, ROLE_DEFAULT_LANDING
from src.web.routes import auth as auth_routes
from src.web.security import LoginRateLimiter


UNKNOWN_ROLE = "Unknown role"
LOGIN_ROLES = (*sorted(VALID_ROLES), UNKNOWN_ROLE)


def _auth_app() -> FastAPI:
    app = FastAPI()
    app.include_router(auth_routes.router, prefix="/api/auth")
    return app


def _page_app() -> FastAPI:
    app = FastAPI()
    app_module._register_page_routes(app)
    return app


@pytest.mark.parametrize("role", LOGIN_ROLES)
def test_login_response_has_role_default_redirect(monkeypatch, role: str) -> None:
    monkeypatch.setattr(
        auth_routes,
        "login_rate_limiter",
        LoginRateLimiter(max_attempts=10, window_seconds=60),
    )
    monkeypatch.setattr(
        auth_routes,
        "authenticate_user",
        lambda identifier, password: {
            "id": 1,
            "email": "alice@example.test",
            "username": "alice",
            "role": role,
            "is_active": 1,
        },
    )
    monkeypatch.setattr(auth_routes, "create_access_token", lambda user: "token")

    with TestClient(_auth_app()) as client:
        response = client.post(
            "/api/auth/login",
            json={"username": "alice", "password": "correct"},
        )

    assert response.status_code == 200
    assert response.json()["default_redirect"] == ROLE_DEFAULT_LANDING.get(
        role, "/dashboard"
    )


def test_every_role_default_landing_satisfies_page_role_requirements() -> None:
    for role, path in ROLE_DEFAULT_LANDING.items():
        required_roles = PAGE_ROLE_REQUIREMENTS.get(path)
        assert required_roles is None or role in required_roles


@pytest.mark.parametrize("role", sorted(VALID_ROLES))
def test_authenticated_login_page_redirects_to_role_landing(
    monkeypatch, role: str
) -> None:
    monkeypatch.setattr(
        app_module, "_page_auth_user", lambda request: {"role": role}
    )

    with TestClient(_page_app()) as client:
        response = client.get("/login", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == ROLE_DEFAULT_LANDING[role]


def test_authenticated_login_page_preserves_explicit_next(monkeypatch) -> None:
    monkeypatch.setattr(
        app_module, "_page_auth_user", lambda request: {"role": "Team Lead"}
    )

    with TestClient(_page_app()) as client:
        response = client.get(
            "/login?next=/analysis/file",
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/analysis/file"


def test_unauthenticated_login_page_renders_default_next() -> None:
    with TestClient(_page_app()) as client:
        response = client.get("/login", follow_redirects=False)

    assert response.status_code == 200
    assert 'data-next="/"' in response.text


def test_login_javascript_uses_default_redirect_only_for_root_next() -> None:
    auth_js = Path(__file__).parents[1] / "static" / "js" / "auth.js"
    harness = r"""
const fs = require('fs');
const vm = require('vm');
const redirects = [];
let submit;
let nextPath = '/';
const form = {
    addEventListener: (name, callback) => { submit = callback; },
    getAttribute: () => nextPath,
    querySelector: () => ({disabled: false}),
};
const errorElement = {textContent: '', classList: {add() {}, remove() {}}};
const document = {
    cookie: '', body: {},
    addEventListener: (name, callback) => callback(),
    querySelector: (selector) => selector.includes('login') ? form : null,
    getElementById: (id) => id === 'login-identifier' || id === 'login-password'
        ? {value: 'alice'} : id === 'login-error' ? errorElement : null,
    createElement: () => ({classList: {}, setAttribute() {}, appendChild() {}}),
};
const window = {
    location: {origin: 'http://socpow.test', pathname: '/login', search: '', assign: (url) => redirects.push(url)},
    fetch: () => Promise.resolve({status: 200, ok: true, json: () => Promise.resolve({default_redirect: '/dashboard'})}),
    setTimeout: () => 0,
};
class Headers { constructor(values) { this.values = values || {}; } set(name, value) { this.values[name] = value; } }
const context = {window, document, URL, Headers, Request: class Request {}, fetch: (...args) => window.fetch(...args), setTimeout: () => 0};
vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), context);
const submitForm = () => submit({preventDefault() {}});
const tick = () => new Promise((resolve) => setImmediate(resolve));
(async () => {
    await submitForm(); await tick();
    nextPath = '/agent/playbooks';
    await submitForm(); await tick();
    if (JSON.stringify(redirects) !== JSON.stringify(['/dashboard', '/agent/playbooks'])) throw new Error(JSON.stringify(redirects));
})().catch((error) => { console.error(error); process.exitCode = 1; });
"""

    result = subprocess.run(
        ["node", "-e", harness, str(auth_js)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, json.dumps(
        {"stdout": result.stdout, "stderr": result.stderr}
    )
