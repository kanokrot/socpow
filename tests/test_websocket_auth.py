from __future__ import annotations

import pytest

from src.web import websocket as websocket_routes


class FakeWebSocket:
    def __init__(self, cookies=None, message=None):
        self.cookies = cookies or {}
        self.message = message
        self.accepted = False
        self.closed = None
        self.received = False

    async def accept(self):
        self.accepted = True

    async def receive_json(self):
        self.received = True
        return self.message

    async def close(self, code=None):
        self.closed = code


@pytest.mark.asyncio
async def test_websocket_authenticates_from_session_cookie_before_first_message(monkeypatch):
    calls = []
    monkeypatch.setattr(
        websocket_routes,
        "get_current_user",
        lambda token: calls.append(token) or {
            "id": 1,
            "username": "alice",
            "role": "admin",
        },
    )
    websocket = FakeWebSocket(cookies={"socpow_session": "cookie-token"})

    user = await websocket_routes._authenticate_websocket(websocket, ["admin"])

    assert user["username"] == "alice"
    assert calls == ["cookie-token"]
    assert websocket.accepted is True
    assert websocket.received is False
    assert websocket.closed is None


@pytest.mark.asyncio
async def test_websocket_keeps_first_message_token_fallback(monkeypatch):
    calls = []
    monkeypatch.setattr(
        websocket_routes,
        "get_current_user",
        lambda token: calls.append(token) or {
            "id": 1,
            "username": "alice",
            "role": "admin",
        },
    )
    websocket = FakeWebSocket(
        message={"type": "auth", "token": "legacy-token"},
    )

    user = await websocket_routes._authenticate_websocket(websocket, ["admin"])

    assert user["username"] == "alice"
    assert calls == ["legacy-token"]
    assert websocket.accepted is True
    assert websocket.received is True
